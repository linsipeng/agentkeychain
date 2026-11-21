/* First actual SQLite callback probe, not a broker or production/writer VFS. */
#define main phase_zero_main
#include "pilot_sqlite_dirfd_gate.c"
#undef main
#include <sqlite3.h>
#include <stdint.h>
#include <time.h>

struct bound {struct scope scope; int parent; unsigned opens;};
struct reader {sqlite3_file base; int fd;};
static const char source_id[] =
    "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76";

static int reader_close(sqlite3_file *f) {
    return close(((struct reader *)f)->fd) == 0 ? SQLITE_OK : SQLITE_IOERR_CLOSE;
}
static int reader_read(sqlite3_file *f, void *dest, int size, sqlite3_int64 offset) {
    if (size < 0 || offset < 0 || offset > 1048576 || size > 1048576 - offset) return SQLITE_IOERR_READ;
    unsigned char *p = dest;
    size_t done = 0;
    while (done < (size_t)size) {
        ssize_t n = pread(((struct reader *)f)->fd, p + done, (size_t)size - done, (off_t)(offset + (sqlite3_int64)done));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return SQLITE_IOERR_READ;
        if (n == 0) break;
        done += (size_t)n;
    }
    if (done == (size_t)size) return SQLITE_OK;
    memset(p + done, 0, (size_t)size - done);
    return SQLITE_IOERR_SHORT_READ;
}
static int reject_write(sqlite3_file *f, const void *p, int n, sqlite3_int64 o) {
    (void)f; (void)p; (void)n; (void)o; return SQLITE_READONLY;
}
static int reject_truncate(sqlite3_file *f, sqlite3_int64 n) {(void)f;(void)n;return SQLITE_READONLY;}
static int reject_sync(sqlite3_file *f, int flags) {(void)f;(void)flags;return SQLITE_READONLY;}
static int reader_size(sqlite3_file *f, sqlite3_int64 *n) {
    struct stat st;
    if (fstat(((struct reader *)f)->fd, &st) != 0 || st.st_size < 0 || st.st_size > 1048576)
        return SQLITE_IOERR_FSTAT;
    *n = st.st_size;
    return SQLITE_OK;
}
/* One private read-only connection in fixture; no writer lock protocol. */
static int only_shared(sqlite3_file *f, int level) {
    if (level != SQLITE_LOCK_SHARED) return SQLITE_READONLY;
    struct flock lock = {.l_type=F_RDLCK,.l_whence=SEEK_SET};
    return fcntl(((struct reader *)f)->fd,F_SETLK,&lock)==0 ? SQLITE_OK : SQLITE_BUSY;
}
static int only_unlock(sqlite3_file *f, int level) {
    if (level != SQLITE_LOCK_NONE) return SQLITE_IOERR_UNLOCK;
    struct flock lock = {.l_type=F_UNLCK,.l_whence=SEEK_SET};
    return fcntl(((struct reader *)f)->fd,F_SETLK,&lock)==0 ? SQLITE_OK : SQLITE_IOERR_UNLOCK;
}
static int no_reserved(sqlite3_file *f, int *out) {(void)f; *out=0;return SQLITE_OK;}
static int no_control(sqlite3_file *f, int op, void *p) {(void)f;(void)op;(void)p;return SQLITE_NOTFOUND;}
static int no_characteristics(sqlite3_file *f) {(void)f;return 0;}
static int sector(sqlite3_file *f) {(void)f;return 4096;}
static const sqlite3_io_methods reader_io = {
    .iVersion=1,.xClose=reader_close,.xRead=reader_read,.xWrite=reject_write,.xTruncate=reject_truncate,
    .xSync=reject_sync,.xFileSize=reader_size,.xLock=only_shared,.xUnlock=only_unlock,
    .xCheckReservedLock=no_reserved,.xFileControl=no_control,.xSectorSize=sector,.xDeviceCharacteristics=no_characteristics
};
static int open_main(sqlite3_vfs *v, const char *name, sqlite3_file *out, int flags, int *actual) {
    out->pMethods=NULL;
    struct bound *b=v->pAppData;
    const int mask=SQLITE_OPEN_READONLY|SQLITE_OPEN_MAIN_DB|SQLITE_OPEN_NOFOLLOW|SQLITE_OPEN_PRIVATECACHE;
    if (!name || strcmp(name,main_name) || (flags & ~mask) ||
        (flags & (SQLITE_OPEN_READONLY|SQLITE_OPEN_MAIN_DB))!=(SQLITE_OPEN_READONLY|SQLITE_OPEN_MAIN_DB) ||
        !location_matches(&b->scope,b->parent) || gate_access(&b->scope,rollback_name)!=0) return SQLITE_CANTOPEN;
    const int fd=gate_open(&b->scope,main_name,false,false);
    if (fd<0) return SQLITE_CANTOPEN;
    ((struct reader *)out)->fd=fd;out->pMethods=&reader_io;b->opens++;
    if(actual) *actual=SQLITE_OPEN_READONLY;
    return SQLITE_OK;
}
static int no_delete(sqlite3_vfs *v, const char *name, int sync) {(void)v;(void)name;(void)sync;return SQLITE_READONLY;}
static int files_access(sqlite3_vfs *v, const char *name, int mode, int *out) {
    struct bound *b=v->pAppData;
    if (!allowed_name(name)||!location_matches(&b->scope,b->parent)||mode==SQLITE_ACCESS_READWRITE) return SQLITE_IOERR_ACCESS;
    int state=gate_access(&b->scope,name);
    if (state<0 || (!strcmp(name,rollback_name)&&state!=0)) return SQLITE_IOERR_ACCESS;
    *out=state;
    return SQLITE_OK;
}
static int fixed_path(sqlite3_vfs *v, const char *name, int bytes, char *out) {
    (void)v;
    if (!name||strcmp(name,main_name)||bytes<(int)sizeof main_name) return SQLITE_CANTOPEN;
    memcpy(out,main_name,sizeof main_name);return SQLITE_OK;
}
/* Fixture only: no secrets or production randomness. No stock path callback. */
static int fixture_random(sqlite3_vfs *v, int n, char *out) {(void)v;memset(out,0x53,(size_t)n);return n;}
static int fixture_sleep(sqlite3_vfs *v, int micros) {(void)v;struct timespec t={micros/1000000,(micros%1000000)*1000L};nanosleep(&t,NULL);return micros;}
static int fixture_time(sqlite3_vfs *v, double *out) {(void)v;*out=2440587.5+(double)time(NULL)/86400;return SQLITE_OK;}
static void must_deny(const char *name,int flags) {
    sqlite3 *db=NULL;
    CHECK(sqlite3_open_v2(name,&db,flags,"pilot-readonly-fixture")!=SQLITE_OK);
    sqlite3_close(db);
}
int main(void) {
    CHECK(getuid()!=0 && getuid()==geteuid());
    CHECK(sqlite3_libversion_number()==3054001 && !strcmp(sqlite3_sourceid(),source_id));
    umask(077);
    char tmp[]="/tmp/akc-sqlite-engine-XXXXXX";
    CHECK(mkdtemp(tmp)!=NULL);
    const int top=open(tmp,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    CHECK(top>=0 && mkdirat(top,"pilot",0700)==0);
    const int dirfd=openat(top,"pilot",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat dir;
    CHECK(dirfd>=0 && fstat(dirfd,&dir)==0);
    struct bound b={.scope={dirfd,dir.st_dev,dir.st_uid,dir.st_ino},.parent=top};

    /* Stock SQLite is used ONLY as an in-memory fixture generator; the
     * tested on-disk open below MUST use the non-default named VFS. */
    sqlite3 *seed=NULL;
    CHECK(sqlite3_open(":memory:",&seed)==SQLITE_OK);
    CHECK(sqlite3_exec(seed,"CREATE TABLE witness(i);INSERT INTO witness VALUES(73);",NULL,NULL,NULL)==SQLITE_OK);
    sqlite3_int64 length=0;
    unsigned char *payload=sqlite3_serialize(seed,"main",&length,0);
    CHECK(payload && length>0 && length<=1048576);
    const int fd=gate_open(&b.scope,main_name,true,true);
    CHECK(fd>=0 && write(fd,payload,(size_t)length)==length && fsync(fd)==0);
    close_checked(fd);sqlite3_free(payload);CHECK(sqlite3_close(seed)==SQLITE_OK);

    sqlite3_vfs v={.iVersion=1,.szOsFile=sizeof(struct reader),.mxPathname=128,
        .zName="pilot-readonly-fixture",.pAppData=&b,.xOpen=open_main,.xDelete=no_delete,.xAccess=files_access,
        .xFullPathname=fixed_path,.xRandomness=fixture_random,.xSleep=fixture_sleep,.xCurrentTime=fixture_time};
    CHECK(sqlite3_vfs_register(&v,0)==SQLITE_OK);
    sqlite3 *db=NULL;
    int ro=SQLITE_OPEN_READONLY|SQLITE_OPEN_NOFOLLOW|SQLITE_OPEN_PRIVATECACHE;
    CHECK(sqlite3_open_v2(main_name,&db,ro,v.zName)==SQLITE_OK && b.opens==1);
    sqlite3_stmt *stmt=NULL;
    CHECK(sqlite3_prepare_v2(db,"SELECT i FROM witness",-1,&stmt,NULL)==SQLITE_OK);
    CHECK(sqlite3_step(stmt)==SQLITE_ROW && sqlite3_column_int(stmt,0)==73 && sqlite3_step(stmt)==SQLITE_DONE);
    CHECK(sqlite3_finalize(stmt)==SQLITE_OK);
    CHECK(sqlite3_exec(db,"DELETE FROM witness",NULL,NULL,NULL)==SQLITE_READONLY);
    CHECK(sqlite3_close(db)==SQLITE_OK);
    must_deny(main_name,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOFOLLOW);
    must_deny("../pilot.sqlite",ro);
    CHECK(symlinkat(main_name,dirfd,rollback_name)==0);
    must_deny(main_name,ro);
    CHECK(unlinkat(dirfd,rollback_name,0)==0);
    close_checked(gate_open(&b.scope,rollback_name,true,true));
    must_deny(main_name,ro);
    CHECK(gate_delete_journal(&b.scope,rollback_name,true)==0);
    CHECK(linkat(dirfd,main_name,dirfd,"alias",0)==0);
    must_deny(main_name,ro);
    CHECK(unlinkat(dirfd,"alias",0)==0);
    CHECK(renameat(top,"pilot",top,"moved")==0 && mkdirat(top,"pilot",0700)==0);
    must_deny(main_name,ro);
    CHECK(b.opens==1 && sqlite3_vfs_unregister(&v)==SQLITE_OK);
    CHECK(unlinkat(dirfd,main_name,0)==0);
    close_checked(dirfd);
    CHECK(unlinkat(top,"moved",AT_REMOVEDIR)==0 && unlinkat(top,"pilot",AT_REMOVEDIR)==0);
    close_checked(top);
    CHECK(rmdir(tmp)==0);
    puts("PASS pinned SQLite real engine, named dirfd read-only VFS; no rollback writer");
}
