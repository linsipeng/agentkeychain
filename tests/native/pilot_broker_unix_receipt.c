/* Exclusive fixture: exact canonical bytes, no product dispatch or real keys. */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define AKC_COMBINED_BRIDGE 1
#include "pilot_sqlite_broker_receipt.c"
#undef main
#undef CHECK
#define main peer_fixture
#include "pilot_broker_unix_peer.c"
#undef main
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SIGNATURE_SIZE 64
#define NONCE_BYTES 16
struct envelope {
    unsigned char request[512], response[1024];
    size_t request_len,response_len;
};

static bool exact_io(int fd, void *bytes,size_t size,bool send_data) {
    unsigned char *p=bytes;
    /* Deadline also set on the socket so a partial frame cannot wait forever. */
    while(size){
        const ssize_t n=send_data?write(fd,p,size):read(fd,p,size);
        if(n<=0)return false;
        p+=n;size-=(size_t)n;
    }
    return true;
}
static void io_timeout(int fd) {
    const struct timeval limit={.tv_sec=2};
    CHECK(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof limit)==0);
    CHECK(setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&limit,sizeof limit)==0);
}
static void sign_exact(EVP_PKEY *key,unsigned char *sig,const unsigned char *bytes,size_t len) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();size_t n=SIGNATURE_SIZE;
    CHECK(ctx&&EVP_DigestSignInit(ctx,NULL,NULL,NULL,key)==1&&EVP_DigestSign(ctx,sig,&n,bytes,len)==1&&n==SIGNATURE_SIZE);
    EVP_MD_CTX_free(ctx);
}
static bool verify_exact(const unsigned char public[32],const unsigned char *sig,
                         const unsigned char *bytes,size_t len) {
    EVP_PKEY *key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,public,32);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    const bool ok=key&&ctx&&EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1&&
        EVP_DigestVerify(ctx,sig,SIGNATURE_SIZE,bytes,len)==1;
    EVP_MD_CTX_free(ctx);EVP_PKEY_free(key);return ok;
}
static void raw_public(EVP_PKEY *key,unsigned char public[32]) {
    size_t n=32;CHECK(key&&EVP_PKEY_get_raw_public_key(key,public,&n)==1&&n==32);
}
static void hex(const unsigned char *in,size_t n,char *out) {
    const char alphabet[]="0123456789abcdef";
    for(size_t i=0;i<n;i++){out[i*2]=alphabet[in[i]>>4];out[i*2+1]=alphabet[in[i]&15];}out[n*2]=0;
}
#ifdef AKC_NATIVE_INSPECT_ONLY
#define INSPECT_WIRE "{\"version\":1,\"op\":\"inspect\",\"profileDigest\":\"" PROFILE "\"}"
#define SEED_WIRE "{\"version\":1,\"op\":\"seed-pending\",\"profileDigest\":\"" PROFILE "\",\"record\":" SEED_FRAME "}"
#define WIRE_SNAPSHOT "{\"version\":1,\"kind\":\"snapshot\",\"receipt\":" SEED_RECEIPT ",\"record\":" SEED_FRAME "}"

static size_t format_response(struct envelope *e,const char *wire){
    unsigned char digest[32];unsigned n=0;
    CHECK(EVP_Digest(e->request,e->request_len,digest,&n,EVP_sha256(),NULL)==1&&n==sizeof digest);
    char correlation[65];hex(digest,sizeof digest,correlation);
    const int count=snprintf((char *)e->response,sizeof e->response,
        "{\"domain\":\"akc-fixture-native-inspect-response-v1\",\"requestDigest\":\"%s\",\"wire\":%s}",correlation,wire);
    CHECK(count>0&&(size_t)count<sizeof e->response);return (size_t)count;
}
static void inspect_committed_wire(struct run r,char wire[768]){
    sqlite3_vfs v;sqlite3 *db=open_exact(&r,&v,true);
    CHECK(sqlite3_db_readonly(db,"main")==1);
    inspect(db,1);
    sqlite3_stmt *q=NULL;
    CHECK(sqlite3_prepare_v2(db,"SELECT receipt.canonical,snapshot.frame FROM snapshot JOIN receipt "
        "ON snapshot.operation=receipt.operation AND snapshot.generation=receipt.generation WHERE snapshot.id=1",-1,&q,NULL)==SQLITE_OK);
    CHECK(sqlite3_step(q)==SQLITE_ROW&&sqlite3_column_type(q,0)==SQLITE_TEXT&&sqlite3_column_type(q,1)==SQLITE_TEXT);
    const int n=snprintf(wire,768,"{\"version\":1,\"kind\":\"snapshot\",\"receipt\":%s,\"record\":%s}",
        sqlite3_column_text(q,0),sqlite3_column_text(q,1));
    CHECK(n>0&&n<768&&sqlite3_step(q)==SQLITE_DONE&&sqlite3_finalize(q)==SQLITE_OK);
    CHECK(!strcmp(wire,WIRE_SNAPSHOT));
    close_exact(&r,&v,db);CHECK(gate_access(&r.scope,rollback_name)==0);
}
#endif
static struct envelope exact_envelope(const unsigned char *nonce,int attempt) {
    struct envelope e;
    char id[NONCE_BYTES*2+1];hex(nonce,NONCE_BYTES,id);
#ifdef AKC_NATIVE_INSPECT_ONLY
    const int len=snprintf((char *)e.request,sizeof e.request,
        "{\"domain\":\"akc-fixture-native-inspect-request-v1\",\"run\":\"%s\",\"wire\":%s}",id,
        attempt==1?INSPECT_WIRE:SEED_WIRE);
    CHECK(len>0&&(size_t)len<sizeof e.request);e.request_len=(size_t)len;
    e.response_len=format_response(&e,WIRE_SNAPSHOT);return e;
#else
    const int len=snprintf((char *)e.request,sizeof e.request,
        "{\"domain\":\"akc-fixture-handoff-request-v1\",\"run\":\"%s\",\"attempt\":%d,\"operation\":\"%s\",\"frame\":%s}",
        id,attempt,ADVANCE,ADVANCE_FRAME);
    CHECK(len>0&&(size_t)len<sizeof e.request);e.request_len=(size_t)len;
    unsigned char digest[32];unsigned n=0;
    CHECK(EVP_Digest(e.request,e.request_len,digest,&n,EVP_sha256(),NULL)==1&&n==sizeof digest);
    char correlation[65];hex(digest,sizeof digest,correlation);
    const int count=snprintf((char *)e.response,sizeof e.response,
        "{\"domain\":\"akc-fixture-handoff-response-v1\",\"run\":\"%s\",\"requestDigest\":\"%s\",\"receipt\":%s}",
        id,correlation,ADVANCE_RECEIPT);
    CHECK(count>0&&(size_t)count<sizeof e.response);e.response_len=(size_t)count;return e;
#endif
}
static void receive(int fd,const unsigned char *expected,size_t len,const unsigned char public[32]) {
    unsigned char bytes[1024],sig[SIGNATURE_SIZE],extra;
    CHECK(len<=sizeof bytes&&exact_io(fd,bytes,len,false)&&exact_io(fd,sig,sizeof sig,false));
    CHECK(read(fd,&extra,1)==0&&memcmp(bytes,expected,len)==0&&verify_exact(public,sig,bytes,len));
}
static void transmit(int fd,unsigned char *expected,size_t len,EVP_PKEY *key) {
    unsigned char sig[SIGNATURE_SIZE];sign_exact(key,sig,expected,len);
    CHECK(exact_io(fd,expected,len,true)&&exact_io(fd,sig,sizeof sig,true)&&shutdown(fd,SHUT_WR)==0);
}
static bool combined_bridge(struct run r) {
    /* Keep standalone test code compiled without unused functions. */
    (void)kill_at;(void)conflict;
#ifdef AKC_NATIVE_INSPECT_ONLY
    // Local readback is still exercised where the runner lacks AF_UNIX.
    char initial_wire[768];inspect_committed_wire(r,initial_wire);
#endif
    CHECK(getgid()==getegid()&&signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
    const int listen_fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(listen_fd<0&&(errno==EPERM||errno==EACCES||errno==EAFNOSUPPORT)){
        fputs("UNVERIFIED: AF_UNIX unavailable\n",stderr);return false;
    }
    CHECK(listen_fd>=0);cloexec(listen_fd);
    char temp[]="/tmp/akc-bridge-XXXXXX";CHECK(mkdtemp(temp));
    struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;
#ifdef __APPLE__
    addr.sun_len=sizeof addr;
#endif
    const int size=snprintf(addr.sun_path,sizeof addr.sun_path,"%s/bridge",temp);
    CHECK(size>0&&(size_t)size<sizeof addr.sun_path);
    const mode_t previous_mask=umask(0177);
    const int bound=bind(listen_fd,(const struct sockaddr *)&addr,sizeof addr);
    const int bind_error=errno;
    umask(previous_mask);
    errno=bind_error;
    if(bound<0&&(errno==EPERM||errno==EACCES)){
        close_checked(listen_fd);CHECK(rmdir(temp)==0);
        fputs("UNVERIFIED: AF_UNIX bind unavailable\n",stderr);return false;
    }
    struct stat socket_metadata;
    CHECK(bound==0&&lstat(addr.sun_path,&socket_metadata)==0&&S_ISSOCK(socket_metadata.st_mode)&&
          socket_metadata.st_uid==geteuid()&&(socket_metadata.st_mode&07777)==0600&&listen(listen_fd,1)==0);
    EVP_PKEY_CTX *k=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
    EVP_PKEY *server=NULL;
    CHECK(k&&EVP_PKEY_keygen_init(k)==1&&EVP_PKEY_keygen(k,&server)==1);EVP_PKEY_CTX_free(k);
    unsigned char nonce[NONCE_BYTES],server_public[32];
    CHECK(RAND_bytes(nonce,sizeof nonce)==1);raw_public(server,server_public);
    struct envelope probe=exact_envelope(nonce,1);
    unsigned char probe_signature[SIGNATURE_SIZE];
    sign_exact(server,probe_signature,probe.response,probe.response_len);
    CHECK(verify_exact(server_public,probe_signature,probe.response,probe.response_len));
    probe_signature[0]^=1;
    CHECK(!verify_exact(server_public,probe_signature,probe.response,probe.response_len));
    pid_t parent=getpid();uid_t uid=geteuid();gid_t gid=getegid();
    for(int attempt=1;attempt<=2;attempt++){
        /* One narrowly bounded bootstrap pipe carries only child public bytes;
         * the child generates the signing key after fork. */
        int bootstrap[2];CHECK(pipe(bootstrap)==0);
        struct envelope e=exact_envelope(nonce,attempt);
        const pid_t child=fork();CHECK(child>=0);
        unsigned char client_public[32];
        if(child==0){
            EVP_PKEY_free(server);
            close_checked(listen_fd);close_checked(bootstrap[0]);
            close_checked(r.scope.directory);close_checked(r.parent);
            EVP_PKEY_CTX *cx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);EVP_PKEY *client=NULL;
            CHECK(cx&&EVP_PKEY_keygen_init(cx)==1&&EVP_PKEY_keygen(cx,&client)==1);EVP_PKEY_CTX_free(cx);
            raw_public(client,client_public);
            CHECK(exact_io(bootstrap[1],client_public,32,true));close_checked(bootstrap[1]);
            const int client_fd=socket(AF_UNIX,SOCK_STREAM,0);CHECK(client_fd>=0);cloexec(client_fd);
            CHECK(connect(client_fd,(const struct sockaddr *)&addr,sizeof addr)==0&&exact_peer(client_fd,parent,uid,gid));
            io_timeout(client_fd);transmit(client_fd,e.request,e.request_len,client);
#ifdef AKC_NATIVE_INSPECT_ONLY
            if(attempt==2){unsigned char denied_byte;CHECK(read(client_fd,&denied_byte,1)==0);}
            else
#endif
                receive(client_fd,e.response,e.response_len,server_public);
            EVP_PKEY_free(client);close_checked(client_fd);_exit(0);
        }
        close_checked(bootstrap[1]);
        CHECK(readable(bootstrap[0])&&read(bootstrap[0],client_public,32)==32);close_checked(bootstrap[0]);
        const int fd=accept_ready(listen_fd);
        CHECK(exact_peer(fd,child,uid,gid));io_timeout(fd);
        receive(fd,e.request,e.request_len,client_public);
#ifdef AKC_NATIVE_INSPECT_ONLY
        // Both requests are signed by the correct child. The valid write
        // operation still closes with no response and never opens its DB.
        const struct envelope allowed=exact_envelope(nonce,1);
        if(allowed.request_len!=e.request_len||memcmp(allowed.request,e.request,e.request_len)){
            CHECK(attempt==2);close_checked(fd);finish(child);continue;
        }
        CHECK(attempt==1);
        char committed_wire[768];inspect_committed_wire(r,committed_wire);
        e.response_len=format_response(&e,committed_wire);
#else
        sqlite3_vfs v;sqlite3 *db=open_exact(&r,&v,false);inspect(db,attempt);
        CHECK(advance(db,ADVANCE,ADVANCE_FRAME,ADVANCE_RECEIPT)==(attempt==1?written:replayed));
        inspect(db,2);close_exact(&r,&v,db);
        CHECK(gate_access(&r.scope,rollback_name)==0);
#endif
        transmit(fd,e.response,e.response_len,server);
        close_checked(fd);finish(child);
    }
    EVP_PKEY_free(server);close_checked(listen_fd);
    CHECK(unlink(addr.sun_path)==0&&rmdir(temp)==0);return true;
}
int main(void) { return receipt_fixture(); }
