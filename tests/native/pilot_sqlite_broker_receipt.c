/* Durable receipt smoke test with fixed keys-free golden vectors. No protocol
 * parser, arbitrary SQL, native credentials, installed channel or activation. */
#define AKC_ROLLBACK_PRIMITIVES_ONLY 1
#include "pilot_sqlite_rollback_writer.c"

#define PROFILE "1111111111111111111111111111111111111111111111111111111111111111"
#define SEED "0437e784aa6a0e820eac661a91829a727c38c19bed567e6b7a27c36b2703fda8"
#define ADVANCE "0bc11b4b3ede7bd0008a5cb7ab18e51eef45d1039f76edc64fc731675b11cfd6"
#define NONCE "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SEED_FRAME "{\"nonce\":\"" NONCE "\",\"ciphertext\":\"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF\"}"
#define ADVANCE_FRAME "{\"nonce\":\"" NONCE "\",\"ciphertext\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\"}"
#define SEED_RECEIPT "{\"version\":1,\"kind\":\"receipt\",\"profileDigest\":\"" PROFILE "\",\"generation\":1,\"step\":\"pending\"," \
    "\"operationDigest\":\"" SEED "\",\"previousDigest\":null,\"recordDigest\":\"17fd1754d3466313ac81f39f2cc129eecbb3966d5f3b78bc6ec851568d4f9e45\"}"
#define ADVANCE_RECEIPT "{\"version\":1,\"kind\":\"receipt\",\"profileDigest\":\"" PROFILE "\",\"generation\":2,\"step\":\"handoff-recorded\"," \
    "\"operationDigest\":\"" ADVANCE "\",\"previousDigest\":\"" SEED "\",\"recordDigest\":\"8866dbdf959f5176ba9f483e2fddcc23ffd0a1c482755ba5d6f39ba58e2c4599\"}"
static const char conflict[]="1212121212121212121212121212121212121212121212121212121212121212";

enum outcome { written, replayed, denied };

static sqlite3_vfs callbacks(struct run *r) {
    return (sqlite3_vfs){.iVersion=1,.szOsFile=sizeof(struct file),.mxPathname=128,.zName=vfs_name,.pAppData=r,
        .xOpen=open_file,.xDelete=delete_file,.xAccess=access_file,.xFullPathname=canonical_path,.xRandomness=randomness,
        .xSleep=sleep_for,.xCurrentTime=clock_now};
}
static enum outcome advance(sqlite3 *db,const char *operation,const char *frame,const char *answer) {
    sqlite3_stmt *stmt=NULL;
    sql(db,"BEGIN IMMEDIATE");
    CHECK(sqlite3_prepare_v2(db,"SELECT canonical, generation, "
        "(SELECT frame FROM snapshot WHERE snapshot.operation=receipt.operation) FROM receipt WHERE operation=?",-1,&stmt,NULL)==SQLITE_OK);
    CHECK(sqlite3_bind_text(stmt,1,operation,-1,SQLITE_STATIC)==SQLITE_OK);
    int hit=sqlite3_step(stmt);
    if(hit==SQLITE_ROW){
        CHECK(sqlite3_column_type(stmt,0)==SQLITE_TEXT);
        const bool exact=sqlite3_column_int(stmt,1)==2&&!strcmp((const char *)sqlite3_column_text(stmt,0),answer)&&
            sqlite3_column_type(stmt,2)==SQLITE_TEXT&&!strcmp((const char *)sqlite3_column_text(stmt,2),frame);
        CHECK(sqlite3_step(stmt)==SQLITE_DONE&&sqlite3_finalize(stmt)==SQLITE_OK);
        sql(db,"ROLLBACK");return exact?replayed:denied;
    }
    CHECK(hit==SQLITE_DONE&&sqlite3_finalize(stmt)==SQLITE_OK);
    CHECK(sqlite3_prepare_v2(db,"UPDATE snapshot SET generation=2, operation=?, frame=? "
        "WHERE id=1 AND generation=1 AND operation='" SEED "'",-1,&stmt,NULL)==SQLITE_OK);
    CHECK(sqlite3_bind_text(stmt,1,operation,-1,SQLITE_STATIC)==SQLITE_OK);
    CHECK(sqlite3_bind_text(stmt,2,frame,-1,SQLITE_STATIC)==SQLITE_OK);
    CHECK(sqlite3_step(stmt)==SQLITE_DONE&&sqlite3_finalize(stmt)==SQLITE_OK);
    if(sqlite3_changes(db)!=1){sql(db,"ROLLBACK");return denied;}
    CHECK(sqlite3_prepare_v2(db,"INSERT INTO receipt VALUES(2,?,?)",-1,&stmt,NULL)==SQLITE_OK);
    CHECK(sqlite3_bind_text(stmt,1,operation,-1,SQLITE_STATIC)==SQLITE_OK);
    CHECK(sqlite3_bind_text(stmt,2,answer,-1,SQLITE_STATIC)==SQLITE_OK);
    CHECK(sqlite3_step(stmt)==SQLITE_DONE&&sqlite3_finalize(stmt)==SQLITE_OK);
    sql(db,"COMMIT"); /* synthetic barrier can pause before this call returns */
    return written;
}
static sqlite3 *open_exact(struct run *r, sqlite3_vfs *v, bool verify_only) {
    r->verify_only=verify_only;
    CHECK(acquire(&r->scope,r->parent,r->lock_inode,&r->lease)==lease_held);
    *v=callbacks(r);
    sqlite3 *db=NULL;
    CHECK(sqlite3_vfs_register(v,0)==SQLITE_OK);
    CHECK(sqlite3_open_v2(main_name,&db,(verify_only?SQLITE_OPEN_READONLY:SQLITE_OPEN_READWRITE)|
        SQLITE_OPEN_NOFOLLOW|SQLITE_OPEN_PRIVATECACHE,vfs_name)==SQLITE_OK);
    if(!verify_only){
        sql(db,"PRAGMA journal_mode=DELETE;PRAGMA synchronous=EXTRA;PRAGMA temp_store=MEMORY;PRAGMA mmap_size=0;");
        CHECK(scalar(db,"PRAGMA synchronous")==3);
        CHECK(scalar(db,"SELECT count(*) FROM pragma_journal_mode WHERE journal_mode='delete'")==1);
    }
    return db;
}
static void close_exact(struct run *r,sqlite3_vfs *v,sqlite3 *db) {
    CHECK(lease_live(r));
    CHECK(sqlite3_close(db)==SQLITE_OK&&sqlite3_vfs_unregister(v)==SQLITE_OK);
    close_checked(r->lease);r->lease=-1;
}
static void inspect(sqlite3 *db,int generation) {
    CHECK(scalar(db,"SELECT count(*) FROM snapshot")==1);
    CHECK(scalar(db,"SELECT count(*) FROM receipt")==generation);
    CHECK(scalar(db,"SELECT count(*) FROM receipt WHERE generation=1 AND operation='" SEED "' AND canonical='" SEED_RECEIPT "'")==1);
    if(generation==1) {
        CHECK(scalar(db,"SELECT count(*) FROM snapshot WHERE id=1 AND generation=1 AND operation='" SEED "' AND frame='" SEED_FRAME "'")==1);
    }else{
        CHECK(scalar(db,"SELECT count(*) FROM snapshot WHERE id=1 AND generation=2 AND operation='" ADVANCE "' AND frame='" ADVANCE_FRAME "'")==1);
        CHECK(scalar(db,"SELECT count(*) FROM receipt WHERE generation=2 AND operation='" ADVANCE "' AND canonical='" ADVANCE_RECEIPT "'")==1);
    }
    CHECK(scalar(db,"SELECT count(*) FROM pragma_integrity_check WHERE integrity_check='ok'")==1);
}
static void kill_at(struct run r,enum fence barrier) {
    int report[2],alive[2];CHECK(pipe(report)==0&&pipe(alive)==0);
    const pid_t worker=fork();CHECK(worker>=0);
    if(worker==0){
        close_checked(report[0]);close_checked(alive[1]);
        r.barrier=barrier;r.fence_fd=report[1];r.keepalive=alive[0];
        sqlite3_vfs v;sqlite3 *db=open_exact(&r,&v,false);
        inspect(db,1);
        (void)advance(db,ADVANCE,ADVANCE_FRAME,ADVANCE_RECEIPT);
        _exit(94); /* Should never complete or send a reply. */
    }
    close_checked(report[1]);close_checked(alive[0]);
    struct pollfd p={.fd=report[0],.events=POLLIN};char token=0;
    const bool seen=poll(&p,1,5000)==1&&(p.revents&POLLIN)&&read(report[0],&token,1)==1&&token==(char)barrier;
    close_checked(report[0]);
    int other=-1;
    const enum lease_state busy=seen?acquire(&r.scope,r.parent,r.lock_inode,&other):lease_rejected;
    const int killed=kill(worker,SIGKILL);
    close_checked(alive[1]);
    const int status=wait_child(worker);
    CHECK(seen&&busy==lease_busy&&other<0&&killed==0&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
}
#ifdef AKC_COMBINED_BRIDGE
static bool combined_bridge(struct run r);
#endif
#ifdef AKC_COMBINED_BRIDGE
static int receipt_fixture(void) {
#else
int main(void) {
#endif
    CHECK(getuid()!=0&&getuid()==geteuid()&&sqlite3_libversion_number()==3054001&&!strcmp(sqlite3_sourceid(),sqlite_source));
    umask(077);
    char temp[]="/tmp/akc-broker-receipt-XXXXXX";CHECK(mkdtemp(temp)!=NULL);
    const int top=open(temp,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    CHECK(top>=0&&mkdirat(top,"pilot",0700)==0);
    const int dir=openat(top,"pilot",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat d,l,original,after;CHECK(dir>=0&&fstat(dir,&d)==0);
    struct run r={.scope={dir,d.st_dev,d.st_uid,d.st_ino},.parent=top,.lease=-1,.fence_fd=-1};
    const int lock=openat(dir,lease_name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    CHECK(lock>=0&&fstat(lock,&l)==0&&fsync(lock)==0&&fsync(dir)==0);
    r.lock_inode=l.st_ino;close_checked(lock);
    CHECK(acquire(&r.scope,top,r.lock_inode,&r.lease)==lease_held);
    /* Seed schema only in-memory; the pending row/receipt are committed by
     * the actual named, descriptor-relative writable VFS further below. */
    sqlite3 *seed=NULL;CHECK(sqlite3_open(":memory:",&seed)==SQLITE_OK);
    sql(seed,"CREATE TABLE snapshot(id INTEGER PRIMARY KEY CHECK(id=1),generation INTEGER NOT NULL,operation TEXT NOT NULL,frame TEXT NOT NULL);"
        "CREATE TABLE receipt(generation INTEGER PRIMARY KEY,operation TEXT NOT NULL UNIQUE,canonical TEXT NOT NULL);"
        "CREATE TRIGGER no_receipt_update BEFORE UPDATE ON receipt BEGIN SELECT raise(ABORT,'receipt immutable');END;"
        "CREATE TRIGGER no_receipt_delete BEFORE DELETE ON receipt BEGIN SELECT raise(ABORT,'receipt immutable');END;");
    sqlite3_int64 n=0;unsigned char *payload=sqlite3_serialize(seed,"main",&n,0);
    CHECK(payload&&n>0&&n<=maximum);
    const int mainfd=gate_open(&r.scope,main_name,true,true);
    CHECK(mainfd>=0&&write(mainfd,payload,(size_t)n)==n&&fstat(mainfd,&original)==0&&fsync(mainfd)==0&&fsync(dir)==0);
    close_checked(mainfd);sqlite3_free(payload);CHECK(sqlite3_close(seed)==SQLITE_OK);
    close_checked(r.lease);r.lease=-1;

    sqlite3_vfs v;sqlite3 *db=open_exact(&r,&v,false);
    sql(db,"BEGIN IMMEDIATE;INSERT INTO snapshot VALUES(1,1,'" SEED "','" SEED_FRAME "');"
        "INSERT INTO receipt VALUES(1,'" SEED "','" SEED_RECEIPT "');COMMIT;");
    close_exact(&r,&v,db);
    r=(struct run){.scope={dir,d.st_dev,d.st_uid,d.st_ino},.parent=top,.lease=-1,.fence_fd=-1,.lock_inode=l.st_ino};
#ifdef AKC_COMBINED_BRIDGE
    if(!combined_bridge(r)){
        CHECK(acquire(&r.scope,top,r.lock_inode,&r.lease)==lease_held);
        CHECK(unlinkat(dir,main_name,0)==0&&unlinkat(dir,lease_name,0)==0);
        close_checked(r.lease);close_checked(dir);CHECK(unlinkat(top,"pilot",AT_REMOVEDIR)==0);
        close_checked(top);CHECK(rmdir(temp)==0);return 77;
    }
#else
    kill_at(r,first_dirty);
    CHECK(gate_access(&r.scope,rollback_name)==1);
    /* An independently reopened connection must recover both old rows. */
    db=open_exact(&r,&v,false);inspect(db,1);close_exact(&r,&v,db);
    CHECK(gate_access(&r.scope,rollback_name)==0);
    r=(struct run){.scope={dir,d.st_dev,d.st_uid,d.st_ino},.parent=top,.lease=-1,.fence_fd=-1,.lock_inode=l.st_ino};
    kill_at(r,commit_durable);
    CHECK(gate_access(&r.scope,rollback_name)==0);
    db=open_exact(&r,&v,false);inspect(db,2);
    CHECK(advance(db,ADVANCE,ADVANCE_FRAME,ADVANCE_RECEIPT)==replayed);
    CHECK(advance(db,ADVANCE,ADVANCE_FRAME,"contradictory canonical receipt")==denied);
    CHECK(advance(db,ADVANCE,SEED_FRAME,ADVANCE_RECEIPT)==denied);
    CHECK(advance(db,conflict,ADVANCE_FRAME,ADVANCE_RECEIPT)==denied);
    CHECK(sqlite3_exec(db,"UPDATE receipt SET canonical='wrong' WHERE generation=2",NULL,NULL,NULL)==SQLITE_CONSTRAINT);
    CHECK(sqlite3_extended_errcode(db)==SQLITE_CONSTRAINT_TRIGGER);
    CHECK(sqlite3_exec(db,"DELETE FROM receipt WHERE generation=2",NULL,NULL,NULL)==SQLITE_CONSTRAINT);
    CHECK(sqlite3_extended_errcode(db)==SQLITE_CONSTRAINT_TRIGGER);
    inspect(db,2);CHECK(r.deletions==0);close_exact(&r,&v,db);

#endif
    db=open_exact(&r,&v,true);
#ifdef AKC_NATIVE_INSPECT_ONLY
    inspect(db,1);
#else
    inspect(db,2);
#endif
    close_exact(&r,&v,db);
    CHECK(gate_access(&r.scope,rollback_name)==0);
    CHECK(acquire(&r.scope,top,r.lock_inode,&r.lease)==lease_held);
    CHECK(fstatat(dir,main_name,&after,AT_SYMLINK_NOFOLLOW)==0&&after.st_ino==original.st_ino);
    CHECK(unlinkat(dir,main_name,0)==0&&unlinkat(dir,lease_name,0)==0);
    close_checked(r.lease);close_checked(dir);CHECK(unlinkat(top,"pilot",AT_REMOVEDIR)==0);
    close_checked(top);CHECK(rmdir(temp)==0);
#if defined(AKC_NATIVE_INSPECT_ONLY)
    puts("PASS authenticated canonical native inspect returns exact read-only durable snapshot; signed mutation denied (fixture only)");
#elif defined(AKC_COMBINED_BRIDGE)
    puts("PASS native peer + signed fixed handoff + descriptor-relative durable receipt replay (synthetic only)");
#else
    puts("PASS pinned SQLite snapshot+receipt atomic rollback, lost reply and exact replay (synthetic fixture only)");
#endif
    return 0;
}
