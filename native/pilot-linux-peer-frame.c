#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "pilot-linux-peer-frame.h"
#include <errno.h>
#include <linux/capability.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static bool unprivileged(void){
 uid_t u,e,s;
 gid_t g,f,t;
 struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
 struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3]={0};
 if(getresuid(&u,&e,&s)<0||getresgid(&g,&f,&t)<0||!u||u!=e||u!=s||g!=f||g!=t||syscall(SYS_capget,&h,caps)<0)return false;
 for(size_t i=0;i<sizeof caps/sizeof caps[0];i++)if(caps[i].effective||caps[i].permitted||caps[i].inheritable)return false;
 return true;
}
static int deny(int err){errno=err;return -1;}
static bool socket_value(int fd,int option,int expected){
 int x=0;
 socklen_t n=sizeof x;
 return getsockopt(fd,SOL_SOCKET,option,&x,&n)==0&&n==sizeof x&&x==expected;
}
static bool endpoint(int fd){
 return unprivileged()&&socket_value(fd,SO_DOMAIN,AF_UNIX)&&socket_value(fd,SO_TYPE,SOCK_SEQPACKET)&&socket_value(fd,SO_PASSCRED,1)
#ifdef SO_PASSPIDFD
  &&socket_value(fd,SO_PASSPIDFD,0)
#endif
 ;
}
int akc_pilot_peer_pair(int pair[2]){
 if(!pair||!unprivileged())return deny(EPERM);
 pair[0]=pair[1]=-1;
 if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)<0)return -1;
 const int yes=1;
 for(size_t i=0;i<2;i++)if(setsockopt(pair[i],SOL_SOCKET,SO_PASSCRED,&yes,sizeof yes)<0){
  const int error=errno;
  (void)close(pair[0]);(void)close(pair[1]);pair[0]=pair[1]=-1;
  return deny(error);
 }
 return 0;
}
int akc_pilot_peer_send(int fd,const unsigned char *bytes,size_t len){
 if(!bytes||!len||len>AKC_PILOT_PEER_MAX_FRAME||!endpoint(fd))return deny(EINVAL);
 const ssize_t n=send(fd,bytes,len,MSG_DONTWAIT|MSG_NOSIGNAL);
 if(n<0)return -1;
 if((size_t)n!=len)return deny(EIO);
 return shutdown(fd,SHUT_WR);
}

static ssize_t packet(int fd,unsigned char *data,size_t size,struct akc_pilot_peer expected,bool eof){
 struct pollfd p={.fd=fd,.events=POLLIN};
 const int ready=poll(&p,1,1500);
 if(ready<0)return -1;
 if(!ready)return deny(ETIMEDOUT);
 if(!(p.revents&(POLLIN|POLLHUP))||(p.revents&(POLLERR|POLLNVAL)))return deny(EPROTO);
 _Alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(sizeof(int)*4)];
 struct iovec v={.iov_base=data,.iov_len=size};
 struct msghdr m={.msg_iov=&v,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof control};
 const ssize_t n=recvmsg(fd,&m,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
 if(n<0)return -1;
 bool corrupt=(m.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0,have=false;
 struct ucred credential={0};
 for(struct cmsghdr *c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c)){
  const size_t off=(size_t)((unsigned char *)c-control);
  if(off>m.msg_controllen||c->cmsg_len<CMSG_LEN(0)||c->cmsg_len>m.msg_controllen-off){corrupt=true;break;}
  if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_CREDENTIALS&&!have&&c->cmsg_len==CMSG_LEN(sizeof credential)){
   memcpy(&credential,CMSG_DATA(c),sizeof credential);
   have=true;
   continue;
  }
  corrupt=true;
  if(c->cmsg_level==SOL_SOCKET&&(c->cmsg_type==SCM_RIGHTS
#ifdef SCM_PIDFD
   ||c->cmsg_type==SCM_PIDFD
#endif
  )){
   /* Kernel closes excess undelivered rights; close every delivered FD. */
   const size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
   for(size_t i=0;i<count;i++){
    int received;
    memcpy(&received,CMSG_DATA(c)+i*sizeof received,sizeof received);
    (void)close(received);
   }
  }
 }
 if(corrupt)return deny(EPROTO);
 if(eof)return n==0&&!have&&m.msg_controllen==0?0:deny(EPROTO);
 if(n<=0||!have||credential.pid!=expected.pid||credential.uid!=expected.uid||credential.gid!=expected.gid)return deny(EPERM);
 return n;
}
ssize_t akc_pilot_peer_recv(int fd,struct akc_pilot_peer expected,unsigned char *out,size_t capacity){
 if(!out||!capacity||capacity>AKC_PILOT_PEER_MAX_FRAME||expected.pid<=0||expected.uid!=getuid()||
    expected.gid!=getgid()||!endpoint(fd))return deny(EINVAL);
 unsigned char data[AKC_PILOT_PEER_MAX_FRAME],extra;
 const ssize_t n=packet(fd,data,capacity,expected,false);
 if(n<0||packet(fd,&extra,1,expected,true)<0)return -1;
 memcpy(out,data,(size_t)n);
 return n;
}
