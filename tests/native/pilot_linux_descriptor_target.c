#include <errno.h>
#include <fcntl.h>
#include <string.h>

int main(int argc,char **argv,char **envp){
 errno=0;
 return argc==1&&!strcmp(argv[0],"agentkeychain-pilot-native-reader")&&envp&&!envp[0]&&
  fcntl(87,F_GETFD)<0&&errno==EBADF?42:43;
}
