#include "../../native/pilot-linux-peer-frame.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(int argc,char **argv,char **envp){
 errno=0;
 if(argc!=1||strcmp(argv[0],"agentkeychain-pilot-native-reader")||!envp||envp[0]||
    fcntl(87,F_GETFD)>=0||errno!=EBADF||getppid()<=1)return 43;
 const struct akc_pilot_peer parent={getppid(),getuid(),getgid()};
 unsigned char challenge=0;
 if(akc_pilot_peer_recv(STDIN_FILENO,parent,&challenge,1)!=1||challenge!='Q')return 44;
 if(akc_pilot_peer_send(STDIN_FILENO,(const unsigned char *)"A",1)<0)return 45;
 return 42;
}
