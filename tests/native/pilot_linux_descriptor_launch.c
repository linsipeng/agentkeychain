#define _GNU_SOURCE 1
#include "../../native/pilot-linux-descriptor-launch.h"
#include "../../native/pilot-linux-peer-frame.h"
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do{if(!(x)){fprintf(stderr,"line %d: %s (errno %d)\n",__LINE__,#x,errno);exit(1);}}while(0)

static int nybble(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static void reap(pid_t child,int expected){
 for(int i=0;i<500;i++){
  int status;
  const pid_t n=waitpid(child,&status,WNOHANG);
  if(n==child){CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==expected);return;}
  CHECK(n==0||(n<0&&errno==EINTR));
  const struct timespec pause={.tv_nsec=10000000};
  (void)nanosleep(&pause,NULL);
 }
 (void)kill(child,SIGKILL);
 (void)waitpid(child,NULL,0);
 CHECK(false);
}

static void probe(int fd,const unsigned char digest[32],int expected_errno){
 int pair[2];
 CHECK(akc_pilot_peer_pair(pair)==0&&pair[0]>=3&&pair[1]>=3&&pair[0]!=87&&pair[1]!=87);
 pid_t child=fork();
 CHECK(child>=0);
 if(child==0){
  CHECK(close(pair[0])==0&&dup2(pair[1],STDIN_FILENO)==STDIN_FILENO&&close(pair[1])==0&&dup2(fd,87)==87);
  const int accepted=akc_pilot_linux_exec_verified_fd(fd,digest);
  const int result=errno;
  _exit(accepted==-1&&expected_errno&&result==expected_errno?0:90);
 }
 CHECK(close(pair[1])==0);
 if(!expected_errno){
  CHECK(akc_pilot_peer_send(pair[0],(const unsigned char *)"Q",1)==0);
  const struct akc_pilot_peer peer={child,getuid(),getgid()};
  unsigned char frame=0;
  CHECK(akc_pilot_peer_recv(pair[0],peer,&frame,1)==1&&frame=='A');
 }
 CHECK(close(pair[0])==0);
 reap(child,expected_errno?0:42);
}

static void rejected_packet(int inherited,int mode){
 int pair[2];
 CHECK(akc_pilot_peer_pair(pair)==0);
 pid_t child=fork();
 CHECK(child>=0);
 if(child==0){
  CHECK(close(pair[0])==0);
  if(mode==2){
   _Alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(sizeof(int))]={0};
   char marker='B';
   struct iovec v={.iov_base=&marker,.iov_len=1};
   struct msghdr m={.msg_iov=&v,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof control};
   struct cmsghdr *c=CMSG_FIRSTHDR(&m);
   CHECK(c!=NULL);
   c->cmsg_len=CMSG_LEN(sizeof(int));c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;
   memcpy(CMSG_DATA(c),&inherited,sizeof inherited);
   CHECK(sendmsg(pair[1],&m,MSG_NOSIGNAL)==1&&shutdown(pair[1],SHUT_WR)==0);
  }else if(mode==1){
   CHECK(send(pair[1],"B",1,MSG_NOSIGNAL)==1&&send(pair[1],"C",1,MSG_NOSIGNAL)==1&&shutdown(pair[1],SHUT_WR)==0);
  }else{
   CHECK(akc_pilot_peer_send(pair[1],(const unsigned char *)"B",1)==0);
  }
  CHECK(close(pair[1])==0);
  _exit(0);
 }
 CHECK(close(pair[1])==0);
 const struct akc_pilot_peer peer={mode==0?getpid():child,getuid(),getgid()};
 unsigned char frame=0;
 CHECK(akc_pilot_peer_recv(pair[0],peer,&frame,1)<0&&frame==0);
 CHECK(close(pair[0])==0);
 reap(child,0);
}

int main(int argc,char **argv){
 CHECK(argc==3&&strlen(argv[2])==64&&getuid()!=0);
 unsigned char digest[32];
 for(size_t i=0;i<sizeof digest;i++){
  const int hi=nybble(argv[2][2*i]),lo=nybble(argv[2][2*i+1]);
  CHECK(hi>=0&&lo>=0);
  digest[i]=(unsigned char)((hi<<4)|lo);
 }
 const int dir=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 struct stat st;
 CHECK(dir>=0&&fstat(dir,&st)==0&&st.st_uid==geteuid()&&(st.st_mode&07777)==0700);
 const int fd=openat(dir,"reader",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
 CHECK(fd>=3&&fd!=87&&setenv("AKC_DESCRIPTOR_FIXTURE_ENV","must-not-cross-exec",1)==0);
 for(int mode=0;mode<3;mode++)rejected_packet(fd,mode);
 unsigned char wrong[32];
 memcpy(wrong,digest,sizeof wrong);
 wrong[0]^=1;
 probe(fd,wrong,EKEYREJECTED);
 CHECK(symlinkat("reader",dir,"linked-reader")==0);
 CHECK(openat(dir,"linked-reader",O_RDONLY|O_CLOEXEC|O_NOFOLLOW)==-1&&errno==ELOOP);
 CHECK(unlinkat(dir,"linked-reader",0)==0);
 CHECK(fchmod(fd,0550)==0);
 probe(fd,digest,EPERM);
 CHECK(fchmod(fd,0500)==0);
 probe(fd,digest,0);
 CHECK(close(fd)==0&&close(dir)==0);
 puts("PASS pinned Linux sealed child and mutually authenticated Unix packet; wrong peer, extra frame and FD transfer denied (fixture)");
 return 0;
}
