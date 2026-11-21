/* Test-only one-broker rollback transaction with pinned SQLite and real flock.
 * Never link into product. No user paths, keys, schema, or caller SQL. */
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define AKC_LEASE_PRIMITIVES_ONLY 1
#include "pilot_sqlite_writer_lease.c"
#include <sqlite3.h>
#include <time.h>
#include <stdint.h>

enum { maximum = 1024 * 1024 };
enum role { main_db, journal };
struct run {
    struct scope scope;
    int parent, lease, fence_fd, keepalive;
    ino_t lock_inode;
    bool main_open, journal_open, journal_synced, dirty, main_synced, fault, verify_only;
    unsigned deletions;
    int level;
};
struct file { sqlite3_file base; struct run *r; int fd; enum role role; };
static const char vfs_name[] = "akc-test-rollback-v1";
static const char sqlite_source[] = "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76";
static int lease_live(struct run *r) {
    struct stat held, name;
    return !r->fault && r->lease >= 0 && location_matches(&r->scope, r->parent) &&
        fstat(r->lease,&held)==0 && matches_lock(&r->scope,&held,r->lock_inode) &&
        fstatat(r->scope.directory,lease_name,&name,AT_SYMLINK_NOFOLLOW)==0 &&
        matches_lock(&r->scope,&name,r->lock_inode);
}
static int fail(struct run *r,int code) {r->fault=true;return code;}
static bool bounds(int n,sqlite3_int64 offset) {return n>=0 && offset>=0 && offset<=maximum && n<=maximum-offset;}
static bool live_file(struct file *f) {
    struct stat held,named;
    const char *n=f->role==main_db?main_name:rollback_name;
    return lease_live(f->r) && fstat(f->fd,&held)==0 && allowed_stat(&f->r->scope,&held) &&
        fstatat(f->r->scope.directory,n,&named,AT_SYMLINK_NOFOLLOW)==0 &&
        allowed_stat(&f->r->scope,&named) && held.st_ino==named.st_ino;
}
static int close_file(sqlite3_file *p) {
    struct file *f=(struct file *)p;
    if(f->role==main_db){f->r->main_open=false;f->r->level=SQLITE_LOCK_NONE;}
    else f->r->journal_open=false;
    return close(f->fd)==0?SQLITE_OK:SQLITE_IOERR_CLOSE;
}
static int read_file(sqlite3_file *p,void *dest,int n,sqlite3_int64 offset) {
    struct file *f=(struct file *)p;
    if(!live_file(f)||!bounds(n,offset))return fail(f->r,SQLITE_IOERR_READ);
    unsigned char *b=dest;size_t done=0;
    while(done<(size_t)n){
        const ssize_t got=pread(f->fd,b+done,(size_t)n-done,(off_t)(offset+(sqlite3_int64)done));
        if(got<0&&errno==EINTR)continue;
        if(got<0)return fail(f->r,SQLITE_IOERR_READ);
        if(got==0){memset(b+done,0,(size_t)n-done);return SQLITE_IOERR_SHORT_READ;}
        done+=(size_t)got;
    }
    return SQLITE_OK;
}
static bool may_mutate(struct file *f) {
    return !f->r->verify_only && live_file(f) && (f->role==journal || (f->r->level==SQLITE_LOCK_EXCLUSIVE && f->r->journal_synced));
}
static void main_change(struct file *f,bool can_fence) {
    if(f->role!=main_db)return;
    f->r->main_synced=false;
    if(can_fence&&!f->r->dirty&&f->r->fence_fd>=0){
        /* Pager must have durably flushed a usable journal before this write.
         * Pause AFTER actual data changed, BEFORE SQLite can sync/delete. */
        if(write(f->r->fence_fd,"W",1)!=1)_exit(94);
        /* Parent normally SIGKILLs. If the test itself is interrupted, its
         * pipe closes and the child exits without an orphaned lease. */
        char dummy;
        while(read(f->r->keepalive,&dummy,1)<0&&errno==EINTR){}
        _exit(93);
    }
    f->r->dirty=true;
}
static int write_file(sqlite3_file *p,const void *src,int n,sqlite3_int64 offset) {
    struct file *f=(struct file *)p;
    if(!may_mutate(f)||!bounds(n,offset))return fail(f->r,SQLITE_IOERR_WRITE);
    const unsigned char *b=src;size_t done=0;
    while(done<(size_t)n){
        const ssize_t got=pwrite(f->fd,b+done,(size_t)n-done,(off_t)(offset+(sqlite3_int64)done));
        if(got<0&&errno==EINTR)continue;
        if(got<=0)return fail(f->r,SQLITE_IOERR_WRITE);
        done+=(size_t)got;
    }
    if(n){
        if(f->role==journal)f->r->journal_synced=false;
        else main_change(f,true);
    }
    return SQLITE_OK;
}
static int truncate_file(sqlite3_file *p,sqlite3_int64 length) {
    struct file *f=(struct file *)p;
    if(!may_mutate(f)||!bounds(0,length)||ftruncate(f->fd,(off_t)length)!=0)return fail(f->r,SQLITE_IOERR_TRUNCATE);
    if(f->role==journal)f->r->journal_synced=false;else main_change(f,false);
    return SQLITE_OK;
}
static int verified_sync(int fd) {
#if defined(__APPLE__)
    /* Fail closed until tested on actual macOS filesystem. Do not substitute
     * ordinary fsync for a failed full sync on a regular file. */
    return fcntl(fd,F_FULLFSYNC)==0?0:-1;
#else
    return fsync(fd);
#endif
}
static int sync_file(sqlite3_file *p,int flags) {
    struct file *f=(struct file *)p;
    if(f->r->verify_only||!live_file(f)||((flags&0xf)!=SQLITE_SYNC_NORMAL&&(flags&0xf)!=SQLITE_SYNC_FULL)||verified_sync(f->fd)!=0)
        return fail(f->r,SQLITE_IOERR_FSYNC);
    if(f->role==journal){
        if(fsync(f->r->scope.directory)!=0)return fail(f->r,SQLITE_IOERR_DIR_FSYNC);
        f->r->journal_synced=true;
    }else f->r->main_synced=true;
    return SQLITE_OK;
}
static int file_size(sqlite3_file *p,sqlite3_int64 *n) {
    struct file *f=(struct file *)p;struct stat st;
    if(!live_file(f)||fstat(f->fd,&st)!=0||st.st_size<0||st.st_size>maximum)return fail(f->r,SQLITE_IOERR_FSTAT);
    *n=st.st_size;return SQLITE_OK;
}
/* Real exclusive flock held for the entire single connection. These levels
 * are SQLite pager state only; not a public interoperability lock protocol. */
static int upgrade(sqlite3_file *p,int level) {
    struct file *f=(struct file *)p;
    if(f->role!=main_db||!live_file(f)||level<SQLITE_LOCK_SHARED||level>SQLITE_LOCK_EXCLUSIVE)
        return fail(f->r,SQLITE_IOERR_LOCK);
    if(level>f->r->level)f->r->level=level;
    return SQLITE_OK;
}
static int downgrade(sqlite3_file *p,int level) {
    struct file *f=(struct file *)p;
    if(f->role!=main_db||!live_file(f)||(level!=SQLITE_LOCK_NONE&&level!=SQLITE_LOCK_SHARED))
        return fail(f->r,SQLITE_IOERR_UNLOCK);
    if(level<f->r->level)f->r->level=level;
    return SQLITE_OK;
}
static int reserved(sqlite3_file *p,int *out) {
    struct file *f=(struct file *)p;
    if(f->role!=main_db||!live_file(f))return fail(f->r,SQLITE_IOERR_CHECKRESERVEDLOCK);
    *out=f->r->level>=SQLITE_LOCK_RESERVED;return SQLITE_OK;
}
static int controls(sqlite3_file *p,int op,void *arg) {(void)p;(void)op;(void)arg;return SQLITE_NOTFOUND;}
static int sector_size(sqlite3_file *p) {(void)p;return 4096;}
static int features(sqlite3_file *p) {(void)p;return 0;}
static const sqlite3_io_methods methods={.iVersion=1,.xClose=close_file,.xRead=read_file,.xWrite=write_file,
    .xTruncate=truncate_file,.xSync=sync_file,.xFileSize=file_size,.xLock=upgrade,.xUnlock=downgrade,
    .xCheckReservedLock=reserved,.xFileControl=controls,.xSectorSize=sector_size,.xDeviceCharacteristics=features};
static int open_file(sqlite3_vfs *v,const char *name,sqlite3_file *p,int flags,int *got) {
    struct run *r=v->pAppData;struct file *f=(struct file *)p;p->pMethods=NULL;
    if(!lease_live(r)||!allowed_name(name))return SQLITE_CANTOPEN;
    const bool main=!strcmp(name,main_name);
    const int allowed=SQLITE_OPEN_READONLY|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_EXCLUSIVE|
        SQLITE_OPEN_NOFOLLOW|SQLITE_OPEN_PRIVATECACHE|(main?SQLITE_OPEN_MAIN_DB:SQLITE_OPEN_MAIN_JOURNAL);
    if((flags&~allowed)||!(flags&(main?SQLITE_OPEN_MAIN_DB:SQLITE_OPEN_MAIN_JOURNAL))||
       (!!(flags&SQLITE_OPEN_READONLY)==!!(flags&SQLITE_OPEN_READWRITE))||
       (main?r->main_open||(r->verify_only?!(flags&SQLITE_OPEN_READONLY):!(flags&SQLITE_OPEN_READWRITE)):
              r->verify_only||r->journal_open))return SQLITE_CANTOPEN;
    int present=gate_access(&r->scope,name);
    if(present<0||(main&&!present)||(!present&&!(flags&SQLITE_OPEN_CREATE))||
       (present&&(flags&SQLITE_OPEN_EXCLUSIVE)))return SQLITE_CANTOPEN;
    bool writable=(flags&SQLITE_OPEN_READWRITE)!=0;
    int fd=gate_open(&r->scope,name,writable,!present);
    if(fd<0)return SQLITE_CANTOPEN;
    f->r=r;f->fd=fd;f->role=main?main_db:journal;
    if(!live_file(f)){close(fd);return SQLITE_CANTOPEN;}
    if(!main&&present){
        /* For startup hot journal, make the validated existing entry durable
         * before allowing SQLite to restore any main DB bytes. */
        if(verified_sync(fd)!=0||fsync(r->scope.directory)!=0){close(fd);return fail(r,SQLITE_IOERR_FSYNC);}
        r->journal_synced=true;
    }
    if(!main&&!present)r->journal_synced=false;
    if(main)r->main_open=true;else r->journal_open=true;
    if(got)*got=writable?SQLITE_OPEN_READWRITE:SQLITE_OPEN_READONLY;
    p->pMethods=&methods;return SQLITE_OK;
}
static int access_file(sqlite3_vfs *v,const char *name,int flags,int *present) {
    struct run *r=v->pAppData;
    if(!lease_live(r)||!allowed_name(name)||(flags!=SQLITE_ACCESS_EXISTS&&flags!=SQLITE_ACCESS_READ&&flags!=SQLITE_ACCESS_READWRITE))
        return SQLITE_IOERR_ACCESS;
    int result=gate_access(&r->scope,name);
    if(result<0)return SQLITE_IOERR_ACCESS;
    *present=result;return SQLITE_OK;
}
static int delete_file(sqlite3_vfs *v,const char *name,int sync) {
    struct run *r=v->pAppData;(void)sync;
    if(r->verify_only||!lease_live(r)||!name||strcmp(name,rollback_name)||(r->dirty&&(!r->main_synced||gate_access(&r->scope,name)!=1)))
        return fail(r,SQLITE_IOERR_DELETE);
    if(gate_delete_journal(&r->scope,name,true)!=0)return fail(r,SQLITE_IOERR_DELETE);
    r->deletions++;r->journal_synced=false;r->dirty=false;r->main_synced=false;return SQLITE_OK;
}
static int canonical_path(sqlite3_vfs *v,const char *name,int n,char *out) {
    struct run *r=v->pAppData;
    if(!lease_live(r)||!name||strcmp(name,main_name)||n<(int)sizeof main_name)return SQLITE_CANTOPEN;
    memcpy(out,main_name,sizeof main_name);return SQLITE_OK;
}
static int randomness(sqlite3_vfs *v,int n,char *out) {
    (void)v;if(n<0)return 0;
    for(int off=0;off<n;){
        size_t count=(size_t)(n-off);if(count>256)count=256;
        if(getentropy(out+off,count)!=0)return 0;
        off+=(int)count;
    }
    return n;
}
static int sleep_for(sqlite3_vfs *v,int micros) {(void)v;struct timespec t={micros/1000000,(micros%1000000)*1000L};nanosleep(&t,NULL);return micros;}
static int clock_now(sqlite3_vfs *v,double *out) {(void)v;*out=2440587.5+(double)time(NULL)/86400;return SQLITE_OK;}

static int scalar(sqlite3 *db,const char *sql) {
    sqlite3_stmt *st=NULL;CHECK(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK);
    CHECK(sqlite3_step(st)==SQLITE_ROW);const int n=sqlite3_column_int(st,0);
    CHECK(sqlite3_step(st)==SQLITE_DONE && sqlite3_finalize(st)==SQLITE_OK);return n;
}
static void sql(sqlite3 *db,const char *statement) {
    const int rc=sqlite3_exec(db,statement,NULL,NULL,NULL);
    if(rc!=SQLITE_OK)fprintf(stderr,"SQL fixed fixture failure %d / %d: %s\n",rc,sqlite3_extended_errcode(db),sqlite3_errmsg(db));
    CHECK(rc==SQLITE_OK);
}
static void writer(struct run r,int fence,int keepalive,bool read_committed) {
    CHECK(acquire(&r.scope,r.parent,r.lock_inode,&r.lease)==lease_held);
    r.fence_fd=fence;r.keepalive=keepalive;r.verify_only=read_committed;
    sqlite3_vfs v={.iVersion=1,.szOsFile=sizeof(struct file),.mxPathname=128,.zName=vfs_name,.pAppData=&r,
        .xOpen=open_file,.xDelete=delete_file,.xAccess=access_file,.xFullPathname=canonical_path,.xRandomness=randomness,
        .xSleep=sleep_for,.xCurrentTime=clock_now};
    CHECK(sqlite3_vfs_register(&v,0)==SQLITE_OK);
    int had_journal=gate_access(&r.scope,rollback_name);
    CHECK(had_journal==0||had_journal==1);
    sqlite3 *db=NULL;
    CHECK(sqlite3_open_v2(main_name,&db,(read_committed?SQLITE_OPEN_READONLY:SQLITE_OPEN_READWRITE)|SQLITE_OPEN_NOFOLLOW|SQLITE_OPEN_PRIVATECACHE,vfs_name)==SQLITE_OK);
    if(!read_committed) {
        sql(db,"PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0;");
        CHECK(scalar(db,"PRAGMA synchronous")==3);
        CHECK(scalar(db,"SELECT count(*) FROM pragma_journal_mode WHERE journal_mode='delete'")==1);
    }
    /* Read verifies the previous full state, not an aggregate coincidence.
     * SQLite must replay before the second child can observe old rows. */
    const char *old="SELECT count(*) FROM witness WHERE (rowid=1 AND i=10) OR (rowid=2 AND i=11) OR (rowid=3 AND i=12)";
    const char *updated="SELECT count(*) FROM witness WHERE (rowid=1 AND i=20) OR (rowid=2 AND i=21) OR (rowid=3 AND i=22)";
    CHECK(scalar(db,"SELECT count(*) FROM witness")==3 && scalar(db,read_committed?updated:old)==3);
    CHECK(scalar(db,"SELECT count(*) FROM pragma_integrity_check WHERE integrity_check='ok'")==1);
    CHECK(r.deletions==(unsigned)had_journal&&gate_access(&r.scope,rollback_name)==0);
    if(!read_committed){
        sql(db,"BEGIN IMMEDIATE; UPDATE witness SET i=i+10; COMMIT;");
        CHECK(fence<0 && r.deletions==(unsigned)had_journal+1 && lease_live(&r) && scalar(db,updated)==3);
    }else CHECK(r.deletions==0&&lease_live(&r));
    CHECK(sqlite3_close(db)==SQLITE_OK && sqlite3_vfs_unregister(&v)==SQLITE_OK);
    close_checked(r.lease);
}
static int wait_child(pid_t p) {
    int st;pid_t got=0;
    for(int i=0;i<750&&got==0;i++){
        do{got=waitpid(p,&st,WNOHANG);}while(got<0&&errno==EINTR);
        if(got==0){const struct timespec delay={0,20000000};nanosleep(&delay,NULL);}
    }
    if(got==0){
        kill(p,SIGKILL);
        do{got=waitpid(p,&st,0);}while(got<0&&errno==EINTR);
        CHECK(false); /* No test considers a timed-out child success. */
    }
    CHECK(got==p);return st;
}
int main(void) {
    CHECK(getuid()!=0&&getuid()==geteuid()&&sqlite3_libversion_number()==3054001&&!strcmp(sqlite3_sourceid(),sqlite_source));
    umask(077);
    char tmp[]="/tmp/akc-rollback-XXXXXX";CHECK(mkdtemp(tmp)!=NULL);
    const int top=open(tmp,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    CHECK(top>=0&&mkdirat(top,"pilot",0700)==0);
    const int dir=openat(top,"pilot",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    struct stat d,l;CHECK(dir>=0&&fstat(dir,&d)==0);
    struct run r={.scope={dir,d.st_dev,d.st_uid,d.st_ino},.parent=top,.lease=-1,.fence_fd=-1};
    const int bootstrap=openat(dir,lease_name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    CHECK(bootstrap>=0&&fstat(bootstrap,&l)==0&&fsync(bootstrap)==0&&fsync(dir)==0);
    r.lock_inode=l.st_ino;close_checked(bootstrap);
    CHECK(acquire(&r.scope,top,r.lock_inode,&r.lease)==lease_held);
    sqlite3 *seed=NULL;CHECK(sqlite3_open(":memory:",&seed)==SQLITE_OK);
    sql(seed,"CREATE TABLE witness(i,p BLOB); INSERT INTO witness VALUES(10,zeroblob(3000)),(11,zeroblob(3000)),(12,zeroblob(3000));");
    sqlite3_int64 n=0;unsigned char *data=sqlite3_serialize(seed,"main",&n,0);
    CHECK(data&&n>0&&n<=maximum);
    int fd=gate_open(&r.scope,main_name,true,true);struct stat original;
    CHECK(fd>=0&&write(fd,data,(size_t)n)==n&&fstat(fd,&original)==0&&fsync(fd)==0&&fsync(dir)==0);
    close_checked(fd);sqlite3_free(data);CHECK(sqlite3_close(seed)==SQLITE_OK);
    close_checked(r.lease);r.lease=-1; /* no inherited lease */
    int pipefd[2],alive[2];CHECK(pipe(pipefd)==0&&pipe(alive)==0);
    const pid_t first=fork();CHECK(first>=0);
    if(first==0){close_checked(pipefd[0]);close_checked(alive[1]);writer(r,pipefd[1],alive[0],false);_exit(95);}
    close_checked(pipefd[1]);close_checked(alive[0]);
    struct pollfd pollfd={.fd=pipefd[0],.events=POLLIN};char token=0;
    const bool fence_hit=poll(&pollfd,1,5000)==1&&(pollfd.revents&POLLIN)&&read(pipefd[0],&token,1)==1&&token=='W';
    close_checked(pipefd[0]);
    int contender=-1;
    const enum lease_state while_first=fence_hit?acquire(&r.scope,top,r.lock_inode,&contender):lease_rejected;
    const int killed=kill(first,SIGKILL);close_checked(alive[1]);
    const int status=wait_child(first);
    CHECK(fence_hit&&while_first==lease_busy&&contender<0&&killed==0&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    CHECK(gate_access(&r.scope,rollback_name)==1);
    const pid_t second=fork();CHECK(second>=0);
    if(second==0){writer(r,-1,-1,false);_exit(0);}
    const int reopened=wait_child(second);CHECK(WIFEXITED(reopened)&&WEXITSTATUS(reopened)==0);
    CHECK(gate_access(&r.scope,rollback_name)==0);
    const pid_t third=fork();CHECK(third>=0);
    if(third==0){writer(r,-1,-1,true);_exit(0);}
    const int committed=wait_child(third);CHECK(WIFEXITED(committed)&&WEXITSTATUS(committed)==0);
    CHECK(gate_access(&r.scope,rollback_name)==0);
    struct stat after;CHECK(fstatat(dir,main_name,&after,AT_SYMLINK_NOFOLLOW)==0&&after.st_ino==original.st_ino);
    /* Teardown only, after all transaction/recovery children are reaped,
     * under a fresh exact lease. Do not use this as a database delete API. */
    CHECK(acquire(&r.scope,top,r.lock_inode,&r.lease)==lease_held);
    CHECK(unlinkat(dir,main_name,0)==0&&unlinkat(dir,lease_name,0)==0);
    close_checked(r.lease);
    close_checked(dir);CHECK(unlinkat(top,"pilot",AT_REMOVEDIR)==0);
    close_checked(top);CHECK(rmdir(tmp)==0);
    puts("PASS pinned SQLite rollback after SIGKILL and exact protected retry (synthetic only)");
    return 0;
}
