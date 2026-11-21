#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "pilot-linux-descriptor-launch.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/close_range.h>
#include <linux/memfd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define IMAGE_MAX ((off_t)(32*1024*1024))
#define BLOCK_SIZE 16384

static ssize_t read_at(int fd,void *out,size_t size,off_t offset){
 ssize_t n;
 do{n=pread(fd,out,size,offset);}while(n<0&&errno==EINTR);
 return n;
}
static bool write_all(int fd,const unsigned char *bytes,size_t size){
 while(size){
  ssize_t n;
  do{n=write(fd,bytes,size);}while(n<0&&errno==EINTR);
  if(n<=0){if(n==0)errno=EIO;return false;}
  bytes+=n;
  size-=(size_t)n;
 }
 return true;
}
static bool same_info(const struct stat *a,const struct stat *b){
 return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&
  a->st_mode==b->st_mode&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&
  a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
  a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
int akc_pilot_linux_exec_verified_fd(int image_fd,const unsigned char expected_sha256[32]){
 struct stat before,after,sealed;
 if(!expected_sha256||image_fd<3||geteuid()==0||getuid()!=geteuid()||getgid()!=getegid()){errno=EPERM;return -1;}
 for(int fd=0;fd<3;fd++)if(fcntl(fd,F_GETFD)<0)return -1;
 const int flags=fcntl(image_fd,F_GETFL);
 if(flags<0||fstat(image_fd,&before)<0)return -1;
 if((flags&O_PATH)||(flags&O_ACCMODE)!=O_RDONLY||!S_ISREG(before.st_mode)||before.st_uid!=geteuid()||before.st_nlink!=1||
    ((before.st_mode&07777)!=0500&&(before.st_mode&07777)!=0700)||
    before.st_size<(off_t)sizeof(Elf64_Ehdr)||before.st_size>IMAGE_MAX){errno=EPERM;return -1;}

 /* No executable-policy override. An NX default or kernel denial fails closed. */
 const int local=(int)syscall(SYS_memfd_create,"agentkeychain-pilot-native-image",MFD_ALLOW_SEALING|MFD_CLOEXEC);
 if(local<0)return -1;
 if(local<3){(void)close(local);errno=EPERM;return -1;}
 EVP_MD_CTX *ctx=NULL;
 unsigned char block[BLOCK_SIZE],actual[32];
 unsigned length=0;
 for(off_t off=0;off<before.st_size;){
  const off_t left=before.st_size-off;
  const ssize_t n=read_at(image_fd,block,left>(off_t)sizeof block?sizeof block:(size_t)left,off);
  if(n<=0){if(n==0)errno=EIO;goto fail;}
  if(!write_all(local,block,(size_t)n))goto fail;
  off+=n;
 }
 if(fstat(image_fd,&after)<0||fstat(local,&sealed)<0)goto fail;
 if(!same_info(&before,&after)||sealed.st_size!=before.st_size||!(sealed.st_mode&S_IXUSR)){errno=EPERM;goto fail;}
 if(fchmod(local,0500)<0)goto fail;
 const int require=F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
 if(fcntl(local,F_ADD_SEALS,require)<0)goto fail;
 const int seals=fcntl(local,F_GET_SEALS);
 if(seals<0)goto fail;
 if((seals&require)!=require){errno=EPERM;goto fail;}

 Elf64_Ehdr h;
 const ssize_t headers=read_at(local,&h,sizeof h,0);
 if(headers<0)goto fail;
 if(headers!=(ssize_t)sizeof h||CRYPTO_memcmp(h.e_ident,ELFMAG,SELFMAG)||h.e_ident[EI_CLASS]!=ELFCLASS64||
    h.e_ident[EI_DATA]!=ELFDATA2LSB||h.e_ident[EI_VERSION]!=EV_CURRENT||h.e_version!=EV_CURRENT||
    (h.e_type!=ET_EXEC&&h.e_type!=ET_DYN)){errno=ENOEXEC;goto fail;}
#if defined(__x86_64__)
 if(h.e_machine!=EM_X86_64){errno=ENOEXEC;goto fail;}
#elif defined(__aarch64__)
 if(h.e_machine!=EM_AARCH64){errno=ENOEXEC;goto fail;}
#else
 errno=ENOTSUP;goto fail;
#endif
 ctx=EVP_MD_CTX_new();
 if(!ctx||EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)!=1){errno=EIO;goto fail;}
 for(off_t off=0;off<before.st_size;){
  const off_t left=before.st_size-off;
  const ssize_t n=read_at(local,block,left>(off_t)sizeof block?sizeof block:(size_t)left,off);
  if(n<=0){if(n==0)errno=EIO;goto fail;}
  if(EVP_DigestUpdate(ctx,block,(size_t)n)!=1){errno=EIO;goto fail;}
  off+=n;
 }
 if(EVP_DigestFinal_ex(ctx,actual,&length)!=1||length!=sizeof actual){errno=EIO;goto fail;}
 if(CRYPTO_memcmp(actual,expected_sha256,sizeof actual)){errno=EKEYREJECTED;goto fail;}
 if(syscall(SYS_close_range,3U,UINT_MAX,CLOSE_RANGE_CLOEXEC)<0)goto fail;
 char image_name[]="agentkeychain-pilot-native-reader";
 char *const argv[]={image_name,NULL};
 char *const envp[]={NULL};
 (void)syscall(SYS_execveat,local,"",argv,envp,AT_EMPTY_PATH);
fail:{
 const int failure=errno;
 EVP_MD_CTX_free(ctx);
 (void)close(local);
 errno=failure;
 return -1;
 }
}
