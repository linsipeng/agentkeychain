/* Hosted combined installed-read rehearsal only. No product test key hook. */
#define _GNU_SOURCE 1
#define AKC_ROLLBACK_PRIMITIVES_ONLY 1
#include "pilot_sqlite_rollback_writer.c"
#include "../../native/pilot-linux-peer-frame.h"
#include "../../native/pilot-linux-inspect-wire.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "pilot_linux_installed_inspect_fixture.h"

struct held_reader {struct run r;sqlite3_vfs v;sqlite3 *db;bool registered;unsigned reads;};
static bool bound_dir(int fd,ino_t inode,struct stat *out){
 return fstat(fd,out)==0&&S_ISDIR(out->st_mode)&&(out->st_mode&07777)==0700&&
    out->st_uid==expected_uid&&out->st_dev==expected_device&&out->st_ino==inode;
}
static bool bound_main(const struct run *r){
 struct stat st;
 return fstatat(r->scope.directory,main_name,&st,AT_SYMLINK_NOFOLLOW)==0&&
    allowed_stat(&r->scope,&st)&&st.st_ino==expected_main;
}
static bool exact_text(sqlite3_stmt *s,int column,const char *text){
 if(sqlite3_column_type(s,column)!=SQLITE_TEXT)return false;
 const unsigned char *bytes=sqlite3_column_text(s,column);
 const int n=sqlite3_column_bytes(s,column);
 return bytes&&n>=0&&(size_t)n==strlen(text)&&!memcmp(bytes,text,(size_t)n);
}
static bool scalar_ok(sqlite3 *db,const char *query,int expected){
 sqlite3_stmt *s=NULL;
 const bool same=sqlite3_prepare_v2(db,query,-1,&s,NULL)==SQLITE_OK&&sqlite3_step(s)==SQLITE_ROW&&
    sqlite3_column_type(s,0)==SQLITE_INTEGER&&sqlite3_column_int64(s,0)==expected&&sqlite3_step(s)==SQLITE_DONE;
 return sqlite3_finalize(s)==SQLITE_OK&&same;
}
static bool one_exact_snapshot(sqlite3 *db){
 if(!scalar_ok(db,"SELECT count(*) FROM snapshot",1)||!scalar_ok(db,"SELECT count(*) FROM receipt",1)||
    !scalar_ok(db,"SELECT count(*) FROM pragma_integrity_check WHERE integrity_check='ok'",1))return false;
 sqlite3_stmt *s=NULL;
 const bool same=sqlite3_prepare_v2(db,"SELECT s.operation,s.frame,r.canonical FROM snapshot s JOIN receipt r "
    "ON s.operation=r.operation AND s.generation=r.generation WHERE s.id=1 AND s.generation=1",-1,&s,NULL)==SQLITE_OK&&
    sqlite3_step(s)==SQLITE_ROW&&exact_text(s,0,expected_operation)&&exact_text(s,1,expected_frame)&&
    exact_text(s,2,expected_receipt)&&sqlite3_step(s)==SQLITE_DONE;
 return sqlite3_finalize(s)==SQLITE_OK&&same;
}
static enum akc_inspect_status read_snapshot(void *input){
 struct held_reader *h=input;
 struct run *r=&h->r;
 if(++h->reads!=1||acquire(&r->scope,r->parent,r->lock_inode,&r->lease)!=lease_held||!bound_main(r)||
    gate_access(&r->scope,rollback_name)!=0)return AKC_INSPECT_UNAVAILABLE;
 h->v=(sqlite3_vfs){.iVersion=1,.szOsFile=sizeof(struct file),.mxPathname=128,.zName=vfs_name,.pAppData=r,
    .xOpen=open_file,.xDelete=delete_file,.xAccess=access_file,.xFullPathname=canonical_path,.xRandomness=randomness,
    .xSleep=sleep_for,.xCurrentTime=clock_now};
 if(sqlite3_vfs_register(&h->v,0)!=SQLITE_OK)return AKC_INSPECT_UNAVAILABLE;
 h->registered=true;
 if(sqlite3_open_v2(main_name,&h->db,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOFOLLOW|SQLITE_OPEN_PRIVATECACHE,vfs_name)!=SQLITE_OK||
    sqlite3_db_readonly(h->db,"main")!=1||sqlite3_db_config(h->db,SQLITE_DBCONFIG_TRUSTED_SCHEMA,0,NULL)!=SQLITE_OK||
    !one_exact_snapshot(h->db)||r->fault||!lease_live(r)||!bound_main(r)||gate_access(&r->scope,rollback_name)!=0)return AKC_INSPECT_UNAVAILABLE;
 return AKC_INSPECT_SNAPSHOT_PRESENT;
}
static bool release(struct held_reader *h){
 bool ok=true;
 if(h->db&&sqlite3_close(h->db)!=SQLITE_OK)ok=false;
 if(h->registered&&sqlite3_vfs_unregister(&h->v)!=SQLITE_OK)ok=false;
 if(h->r.lease>=0&&close(h->r.lease)!=0)ok=false;
 return ok;
}
int main(int argc,char **argv,char **envp){
 (void)sql;(void)scalar;(void)close_checked;(void)wait_child;
 struct stat top,dir;
 if(argc!=1||!argv[0]||strcmp(argv[0],"agentkeychain-pilot-native-reader")||!envp||envp[0]||
    !expected_uid||getuid()!=expected_uid||geteuid()!=expected_uid||getppid()<=1||
    sqlite3_libversion_number()!=3054001||strcmp(sqlite3_sourceid(),sqlite_source)||
    !bound_dir(1,expected_parent,&top)||!bound_dir(2,expected_directory,&dir))return 76;
 struct held_reader h={.r={.scope={2,dir.st_dev,dir.st_uid,dir.st_ino},.parent=1,.lease=-1,.fence_fd=-1,
    .lock_inode=expected_lock,.verify_only=true}};
 if(!location_matches(&h.r.scope,h.r.parent))return 76;
 const struct akc_pilot_peer parent={.pid=getppid(),.uid=getuid(),.gid=getgid()};
 unsigned char request[AKC_INSPECT_WIRE_MAX],reply[AKC_INSPECT_WIRE_MAX];
 const ssize_t received=akc_pilot_peer_recv(0,parent,request,sizeof request);
 if(received<0)return 77;
 EVP_PKEY *key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,fixture_seed,sizeof fixture_seed);
 OPENSSL_cleanse(fixture_seed,sizeof fixture_seed);
 if(!key)return 77;
 const ssize_t n=akc_inspect_respond(&binding,key,read_snapshot,&h,request,(size_t)received,reply,sizeof reply);
 EVP_PKEY_free(key);
 const bool known=n>0&&h.reads==1&&lease_live(&h.r)&&bound_main(&h.r)&&gate_access(&h.r.scope,rollback_name)==0;
 /* Preserve the read lease until the one bounded response is sent. */
 const bool sent=known&&akc_pilot_peer_send(0,reply,(size_t)n)==0;
 if(!release(&h))return 80;
 if(sent)return 0;
 return h.reads==0?78:79;
}
