/* Cross-language fixture only: this test does not establish a kernel peer or a genuine store. */
#include "../../native/pilot-linux-inspect-wire.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static enum akc_inspect_status fixture_read(void *input){
 int *count=input;
 (*count)++;
 return AKC_INSPECT_SNAPSHOT_PRESENT;
}
int main(int argc,char **argv){
 if(argc!=4||strlen(argv[1])!=64||strlen(argv[2])!=64)return 20;
 char *end=NULL;
 errno=0;
 const long long until=strtoll(argv[3],&end,10);
 if(errno||!end||*end||until<=0)return 20;
 unsigned char seed[32],request[AKC_INSPECT_WIRE_MAX+1],reply[AKC_INSPECT_WIRE_MAX]={0};
 const size_t seed_read=fread(seed,1,sizeof seed,stdin);
 EVP_PKEY *key=seed_read==sizeof seed?EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,seed,sizeof seed):NULL;
 OPENSSL_cleanse(seed,sizeof seed);
 if(!key)return 20;
 const size_t request_read=fread(request,1,sizeof request,stdin);
 struct akc_inspect_scope scope={.not_after=(int64_t)until};
 memcpy(scope.installation_digest,argv[1],64);
 memcpy(scope.profile_digest,argv[2],64);
 size_t public_length=sizeof scope.reader_public;
 if(ferror(stdin)||!feof(stdin)||!request_read||request_read>AKC_INSPECT_WIRE_MAX||
    EVP_PKEY_get_raw_public_key(key,scope.reader_public,&public_length)!=1||public_length!=sizeof scope.reader_public){
  EVP_PKEY_free(key);return 20;
 }
 int calls=0;
 const ssize_t n=akc_inspect_respond(&scope,key,fixture_read,&calls,request,request_read,reply,sizeof reply);
 EVP_PKEY_free(key);
 if(n<0){
  for(size_t i=0;i<sizeof reply;i++)if(reply[i])return 21;
  return calls==0?13:21;
 }
 if(calls!=1||fwrite(reply,1,(size_t)n,stdout)!=(size_t)n)return 21;
 return 0;
}
