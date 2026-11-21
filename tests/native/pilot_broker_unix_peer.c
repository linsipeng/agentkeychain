/* Test-only kernel peer identity check. No real broker service, keys, TCP,
 * OS config, or pathname supplied by a caller. */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(bool condition, const char *what, int line) {
    if(!condition){fprintf(stderr,"line %d: %s (errno %d)\n",line,what,errno);exit(1);}
}
#define CHECK(x) check((x),#x,__LINE__)

struct peer {pid_t pid;uid_t uid;gid_t gid;};
static bool peer(int fd,struct peer *identity) {
#if defined(__linux__)
    struct ucred creds;socklen_t length=sizeof creds;
    if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&creds,&length)!=0||length!=sizeof creds||creds.pid<=0)return false;
    *identity=(struct peer){creds.pid,creds.uid,creds.gid};return true;
#elif defined(__APPLE__)
    pid_t pid=0;uid_t uid;gid_t gid;socklen_t length=sizeof pid;
    if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&length)!=0||length!=sizeof pid||pid<=0||
       getpeereid(fd,&uid,&gid)!=0)return false;
    *identity=(struct peer){pid,uid,gid};return true;
#else
    (void)fd;(void)identity;return false;
#endif
}
static bool exact_peer(int fd,pid_t pid,uid_t uid,gid_t gid) {
    struct peer p;
    return peer(fd,&p)&&p.pid==pid&&p.uid==uid&&p.gid==gid;
}
static void cloexec(int fd) {CHECK(fcntl(fd,F_SETFD,FD_CLOEXEC)==0);}
static void closed(int fd) {CHECK(close(fd)==0);}
static bool readable(int fd) {
    struct pollfd p={.fd=fd,.events=POLLIN};
    return poll(&p,1,4000)==1&&(p.revents&(POLLIN|POLLHUP));
}
static void finish(pid_t child) {
    for(int i=0;i<400;i++){
        int status;
        const pid_t result=waitpid(child,&status,WNOHANG);
        if(result==child){CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);return;}
        CHECK(result==0||(result<0&&errno==EINTR));
        const struct timespec duration={0,10000000};nanosleep(&duration,NULL);
    }
    kill(child,SIGKILL);
    int status;while(waitpid(child,&status,0)<0&&errno==EINTR){}
    CHECK(false);
}
static int accept_ready(int listener) {
    CHECK(readable(listener));
    const int fd=accept(listener,NULL,NULL);
    CHECK(fd>=0);cloexec(fd);return fd;
}
static void connect_child(const struct sockaddr_un *address,int start,pid_t expected,uid_t uid,gid_t gid,bool authorized) {
    if(start>=0){
        char permit;
        CHECK(readable(start)&&read(start,&permit,1)==1&&permit=='C');closed(start);
    }
    /* Created here after fork; accepted peer credentials must identify
     * this process, not the creator of pre-created socketpair endpoints. */
    const int client=socket(AF_UNIX,SOCK_STREAM,0);
    CHECK(client>=0);cloexec(client);
    CHECK(connect(client,(const struct sockaddr *)address,sizeof *address)==0);
    CHECK(exact_peer(client,expected,uid,gid));
    CHECK(!exact_peer(client,getpid(),uid,gid)); /* reverse PID cannot be ourselves */
    if(authorized){
        CHECK(write(client,"Q",1)==1);
        char answer;
        CHECK(readable(client)&&read(client,&answer,1)==1&&answer=='A');
    }else{
        /* Nothing is written: do not rely on parsing an unexpected frame
         * to reject a same-account client. Verify its connection closes. */
        char answer;
        CHECK(readable(client)&&read(client,&answer,1)==0);
    }
    closed(client);
}
int main(void) {
    CHECK(getuid()!=0&&getuid()==geteuid()&&getgid()==getegid());
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
    umask(077);
    const int listener=socket(AF_UNIX,SOCK_STREAM,0);
    if(listener<0&&(errno==EPERM||errno==EACCES||errno==EAFNOSUPPORT)){
        fputs("UNVERIFIED: AF_UNIX socket unavailable in this runner\n",stderr);return 77;
    }
    CHECK(listener>=0);cloexec(listener);
    char directory[]="/tmp/akc-peer-XXXXXX";CHECK(mkdtemp(directory)!=NULL);
    struct stat st;CHECK(lstat(directory,&st)==0&&S_ISDIR(st.st_mode)&&
        st.st_uid==geteuid()&&(st.st_mode&07777)==0700);
    struct sockaddr_un address={0};address.sun_family=AF_UNIX;
#ifdef __APPLE__
    address.sun_len=sizeof address;
#endif
    const int path_len=snprintf(address.sun_path,sizeof address.sun_path,"%s/broker",directory);
    CHECK(path_len>0&&(size_t)path_len<sizeof address.sun_path);
    const mode_t previous_mask=umask(0177);
    const int bound=bind(listener,(const struct sockaddr *)&address,sizeof address);
    const int bind_error=errno;
    umask(previous_mask);
    errno=bind_error;
    if(bound<0&&(errno==EPERM||errno==EACCES)){
        closed(listener);CHECK(rmdir(directory)==0);
        fputs("UNVERIFIED: AF_UNIX bind unavailable in this runner\n",stderr);return 77;
    }
    CHECK(bound==0);
    CHECK(lstat(address.sun_path,&st)==0&&S_ISSOCK(st.st_mode)&&(st.st_mode&07777)==0600&&st.st_uid==geteuid());
    CHECK(listen(listener,2)==0);
    const pid_t expected_server=getpid();const uid_t uid=geteuid();const gid_t gid=getegid();
    int barrier[2];CHECK(pipe(barrier)==0);cloexec(barrier[0]);cloexec(barrier[1]);
    const pid_t expected_client=fork();
    CHECK(expected_client>=0);
    if(expected_client==0){
        closed(listener);closed(barrier[1]);
        connect_child(&address,barrier[0],expected_server,uid,gid,true);
        _exit(0);
    }
    closed(barrier[0]);
    const pid_t other=fork();CHECK(other>=0);
    if(other==0){
        closed(listener);closed(barrier[1]);
        connect_child(&address,-1,expected_server,uid,gid,false);
        _exit(0);
    }
    const int rejected=accept_ready(listener);
    struct peer stranger;
    CHECK(peer(rejected,&stranger)&&stranger.uid==uid&&stranger.gid==gid&&stranger.pid==other);
    CHECK(!exact_peer(rejected,expected_client,uid,gid));
    /* No application read or write before this wrong-PID closure. */
    closed(rejected);finish(other);
    CHECK(write(barrier[1],"C",1)==1);closed(barrier[1]);
    const int accepted=accept_ready(listener);
    CHECK(exact_peer(accepted,expected_client,uid,gid));
    CHECK(!exact_peer(accepted,expected_server,uid,gid));
    char query;
    CHECK(readable(accepted)&&read(accepted,&query,1)==1&&query=='Q');
    CHECK(write(accepted,"A",1)==1);
    closed(accepted);finish(expected_client);
    closed(listener);CHECK(unlink(address.sun_path)==0&&rmdir(directory)==0);
    puts("PASS native AF_UNIX: exact mutual kernel PID/UID/GID; same-account wrong PID denied before data");
    return 0;
}
