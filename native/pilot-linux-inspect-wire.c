#define _POSIX_C_SOURCE 200809L
#include "pilot-linux-inspect-wire.h"
#include <errno.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ABI "pilot-broker-inspect-v1"
#define CHALLENGE "AgentKeychain-pilot-native-inspect-challenge-v1"
#define REPLY "AgentKeychain-pilot-native-inspect-reply-v1"
#define MAX_SAFE INT64_C(9007199254740991)
struct cursor {const unsigned char *p,*end;};

static bool take(struct cursor *c,const char *literal){
 const size_t n=strlen(literal);
 if((size_t)(c->end-c->p)<n||memcmp(c->p,literal,n))return false;
 c->p+=n;
 return true;
}
static bool decimal(struct cursor *c,int64_t *value){
 if(c->p==c->end||*c->p<'1'||*c->p>'9')return false;
 int64_t v=0;
 while(c->p!=c->end&&*c->p>='0'&&*c->p<='9'){
  const int d=*c->p-'0';
  if(v>(MAX_SAFE-d)/10)return false;
  v=v*10+d;
  c->p++;
 }
 *value=v;
 return true;
}
static bool hex_digest(const char value[65]){
 return value[64]=='\0'&&strspn(value,"0123456789abcdef")==64;
}
static bool hash_hex(const void *bytes,size_t n,char hex[65]){
 unsigned char hash[32];
 unsigned size=0;
 const char alphabet[]="0123456789abcdef";
 if(EVP_Digest(bytes,n,hash,&size,EVP_sha256(),NULL)!=1||size!=sizeof hash)return false;
 for(size_t i=0;i<sizeof hash;i++){hex[i*2]=alphabet[hash[i]>>4];hex[i*2+1]=alphabet[hash[i]&15];}
 hex[64]='\0';
 return true;
}
static bool live(int64_t start,int64_t end,int64_t hard,int64_t *now){
 const time_t value=time(NULL);
 if(value==(time_t)-1)return false;
 *now=(int64_t)value;
 return start<=*now&&*now<end&&end<=hard&&end-start<=5;
}
static ssize_t denied(void){errno=EPROTO;return -1;}
ssize_t akc_inspect_respond(const struct akc_inspect_scope *scope,EVP_PKEY *reader,
 akc_inspect_read read_status,void *held_store,const unsigned char *request,size_t length,
 unsigned char *reply,size_t capacity){
 if(!scope||!reader||!read_status||!request||!reply||!length||length>AKC_INSPECT_WIRE_MAX||
    capacity>AKC_INSPECT_WIRE_MAX||!capacity||!hex_digest(scope->installation_digest)||!hex_digest(scope->profile_digest)||
    EVP_PKEY_base_id(reader)!=EVP_PKEY_ED25519)return denied();
 struct cursor c={request,request+length};
 if(!take(&c,"{\"version\":1,\"domain\":\"" CHALLENGE "\",\"abi\":\"" ABI "\",\"installationDigest\":\"")||
    !take(&c,scope->installation_digest)||!take(&c,"\",\"nonce\":\"")||(size_t)(c.end-c.p)<43)return denied();
 char nonce[44];
 for(size_t i=0;i<43;i++){
  const unsigned char n=c.p[i];
  if(n==0||!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",(int)n)||
    (i==42&&!strchr("AEIMQUYcgkosw048",(int)n)))return denied();
  nonce[i]=(char)n;
 }
 nonce[43]='\0';
 c.p+=43;
 int64_t start=0,end=0,now=0;
 if(!take(&c,"\",\"wire\":{\"version\":1,\"op\":\"inspect\",\"profileDigest\":\"")||!take(&c,scope->profile_digest)||
    !take(&c,"\"},\"issuedAt\":")||!decimal(&c,&start)||!take(&c,",\"expiresAt\":")||!decimal(&c,&end)||
    !take(&c,"}")||c.p!=c.end||!live(start,end,scope->not_after,&now))return denied();
 unsigned char pub[32],key64[45];
 size_t key_len=sizeof pub;
 char key_id[65],request_hash[65];
 if(EVP_PKEY_get_raw_public_key(reader,pub,&key_len)!=1||key_len!=sizeof pub||CRYPTO_memcmp(pub,scope->reader_public,sizeof pub)||
    EVP_EncodeBlock(key64,pub,sizeof pub)!=44||!hash_hex(key64,44,key_id)||!hash_hex(request,length,request_hash))return denied();
 const char *status;
 switch(read_status(held_store)){
  case AKC_INSPECT_EMPTY:status="empty";break;
  case AKC_INSPECT_SNAPSHOT_PRESENT:status="snapshot-present";break;
  case AKC_INSPECT_ROLLBACK_JOURNAL_PRESENT:status="rollback-journal-present";break;
  default:return denied();
 }
 if(!live(start,end,scope->not_after,&now))return denied();
 char canonical[1024];
 const int n=snprintf(canonical,sizeof canonical,"{\"version\":1,\"domain\":\"" REPLY "\",\"keyId\":\"%s\",\"abi\":\"" ABI
  "\",\"installationDigest\":\"%s\",\"profileDigest\":\"%s\",\"nonce\":\"%s\",\"requestDigest\":\"%s\",\"observedAt\":%" PRId64 ",\"status\":\"%s\"}",
  key_id,scope->installation_digest,scope->profile_digest,nonce,request_hash,now,status);
 if(n<=0||(size_t)n>=sizeof canonical)return denied();
 unsigned char sig[64],sig64[89];
 size_t sig_len=sizeof sig;
 EVP_MD_CTX *ctx=EVP_MD_CTX_new();
 const bool signed_ok=ctx&&EVP_DigestSignInit(ctx,NULL,NULL,NULL,reader)==1&&
  EVP_DigestSign(ctx,sig,&sig_len,(const unsigned char *)canonical,(size_t)n)==1&&sig_len==sizeof sig;
 EVP_MD_CTX_free(ctx);
 if(!signed_ok||EVP_EncodeBlock(sig64,sig,sizeof sig)!=88)return denied();
 /* Only quotes need escaping: all other characters were fixed or validated. */
 char wire[AKC_INSPECT_WIRE_MAX],*out=wire;
 const char prefix[]="{\"canonical\":\"";
 memcpy(out,prefix,sizeof prefix-1);
 out+=sizeof prefix-1;
 for(int i=0;i<n;i++){
  if((size_t)(out-wire)+2>=sizeof wire)return denied();
  if(canonical[i]=='\"')*out++='\\';
  *out++=canonical[i];
 }
 const size_t left=sizeof wire-(size_t)(out-wire);
 const int tail=snprintf(out,left,"\",\"signature\":\"%s\"}",(const char *)sig64);
 if(tail<0||(size_t)tail>=left)return denied();
 const size_t total=(size_t)(out-wire)+(size_t)tail;
 if(total>capacity||!live(start,end,scope->not_after,&now))return denied();
 memcpy(reply,wire,total);
 return (ssize_t)total;
}
