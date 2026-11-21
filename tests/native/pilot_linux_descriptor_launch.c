#define _GNU_SOURCE 1
#include "../../native/pilot-linux-descriptor-launch.h"
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
static void probe(int fd,const unsigned char digest[32],int expected_errno){
 pid_t child=fork();
 CHECK(child>=0);
 if(child==0){
  CHECK(dup2(fd,87)==87);
  const int accepted=akc_pilot_linux_exec_verified_fd(fd,digest);
  const int result=errno;
  _exit(accepted==-1&&expected_errno&&result==expected_errno?0:90);
 }
 for(int i=0;i<500;i++){
  int status;
  const pid_t n=waitpid(child,&status,WNOHANG);
  if(n==child){CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==(expected_errno?0:42));return;}
  CHECK(n==0||(n<0&&errno==EINTR));
  const struct timespec pause={.tv_nsec=10000000};
  (void)nanosleep(&pause,NULL);
 }
 (void)kill(child,SIGKILL);
 (void)waitpid(child,NULL,0);
 CHECK(false);
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
 puts("PASS pinned Linux image sealed descriptor execution and signed digest/mode/link fences (fixture)");
 return 0;
}
