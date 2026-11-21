/*
 * Disposable POSIX path-gate scaffold. Not a registered SQLite VFS.
 * No production inputs, SQLite engine, writes to a user profile, or root.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct scope {
    int directory;
    dev_t device;
    uid_t owner;
    ino_t inode;
};

static const char main_name[] = "pilot.sqlite";
static const char rollback_name[] = "pilot.sqlite-journal";

/* Production must also retain and check every verified ancestor. This
 * fixture binds a single directory entry under its already-held parent. */
static bool location_matches(const struct scope *s, int parent) {
    struct stat named;
    return fstatat(parent, "pilot", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(named.st_mode) && named.st_dev == s->device && named.st_ino == s->inode &&
        named.st_uid == s->owner && (named.st_mode & 07777) == 0700;
}

static bool allowed_name(const char *name) {
    return name && (!strcmp(name, main_name) || !strcmp(name, rollback_name));
}

static bool allowed_stat(const struct scope *s, const struct stat *st) {
    return S_ISREG(st->st_mode) && st->st_dev == s->device &&
        st->st_uid == s->owner && (st->st_mode & 07777) == 0600 && st->st_nlink == 1;
}

/* A path operation is not an authorization token for a later open. */
static int gate_access(const struct scope *s, const char *name) {
    struct stat st;
    if (!allowed_name(name)) { errno = EPERM; return -1; }
    if (fstatat(s->directory, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? 0 : -1;
    if (!allowed_stat(s, &st)) { errno = EPERM; return -1; }
    return 1;
}

static int gate_open(const struct scope *s, const char *name, bool writable, bool create_exclusive) {
    struct stat st;
    if (!allowed_name(name) || (create_exclusive && !writable)) { errno = EPERM; return -1; }
    /* ACCESS is not a security fence. It avoids initiating even a read on
     * known-denied special files; the actual held descriptor is checked again.
     * O_NONBLOCK prevents a changed named pipe from hanging this test. */
    if (!create_exclusive && gate_access(s, name) != 1) return -1;
    const int fd = openat(s->directory, name,
        (writable ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
            (create_exclusive ? O_CREAT | O_EXCL : 0), 0600);
    if (fd < 0) return -1;
    if (fstat(fd, &st) < 0 || !allowed_stat(s, &st)) {
        close(fd); errno = EPERM; return -1;
    }
    return fd;
}

/* Only the rollback journal is disposable. Caller owns a single-writer
 * broker lock. The POSIX stat+unlink sequence is NOT an atomic inode check
 * against another directory writer; unlinkat never follows a final symlink. */
static int gate_delete_journal(const struct scope *s, const char *name, bool sync_directory) {
    if (!name || strcmp(name, rollback_name)) { errno = EPERM; return -1; }
    int state = gate_access(s, name);
    if (state < 0) return -1;
    if (state == 0) return 0;
    if (unlinkat(s->directory, name, 0) < 0) return -1;
    return sync_directory ? fsync(s->directory) : 0;
}

static void check_at(bool ok, const char *label, int line) {
    if (!ok) { fprintf(stderr, "line %d: %s (errno %d)\n", line, label, errno); exit(1); }
}
#define CHECK(value) check_at((value), #value, __LINE__)
static void close_checked(int fd) { CHECK(fd >= 0); CHECK(close(fd) == 0); }

int main(void) {
    /* Always disposable and never recursive; paths are mechanically named
     * below the private one-run directory. Do not run under elevation. */
    CHECK(getuid() != 0 && getuid() == geteuid());
    umask(077);
    char tmp[] = "/tmp/akc-dirfd-XXXXXX";
    CHECK(mkdtemp(tmp) != NULL);
    int top = open(tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(top >= 0);
    CHECK(mkdirat(top, "pilot", 0700) == 0);
    int path = openat(top, "pilot", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(path >= 0);
    struct stat dir;
    CHECK(fstat(path, &dir) == 0 && S_ISDIR(dir.st_mode) && (dir.st_mode & 07777) == 0700 && dir.st_uid == getuid());
    struct scope s = {path, dir.st_dev, dir.st_uid, dir.st_ino};
    CHECK(location_matches(&s, top));

    CHECK(gate_access(&s, main_name) == 0);
    int db = gate_open(&s, main_name, true, true);
    CHECK(db >= 0);
    CHECK(write(db, "owned", 5) == 5);
    CHECK(fsync(db) == 0);
    CHECK(gate_access(&s, main_name) == 1);
    CHECK(gate_open(&s, main_name, true, true) == -1);
    CHECK(gate_delete_journal(&s, main_name, false) == -1);
    CHECK(fchmod(db, 0644) == 0);
    CHECK(gate_access(&s, main_name) == -1);
    CHECK(gate_open(&s, main_name, false, false) == -1);
    CHECK(fchmod(db, 0600) == 0);
    const char *bad[] = {NULL, "/pilot.sqlite", "../pilot.sqlite", "pilot.sqlite-shm",
                         "pilot.sqlite-wal", "another.sqlite", "./pilot.sqlite"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        CHECK(gate_access(&s, bad[i]) == -1);
        CHECK(gate_open(&s, bad[i], true, true) == -1);
        CHECK(gate_delete_journal(&s, bad[i], true) == -1);
    }
    CHECK(gate_open(&s, rollback_name, false, true) == -1);

    /* Marker outside pilot object is never reached through aliased names. */
    int marker = openat(top, "outside", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    CHECK(marker >= 0 && write(marker, "outside", 7) == 7);
    close_checked(marker);
    CHECK(symlinkat("../outside", path, rollback_name) == 0);
    CHECK(gate_access(&s, rollback_name) == -1);
    CHECK(gate_open(&s, rollback_name, true, false) == -1);
    CHECK(gate_open(&s, rollback_name, true, true) == -1);
    CHECK(gate_delete_journal(&s, rollback_name, true) == -1);
    CHECK(unlinkat(path, rollback_name, 0) == 0);
    CHECK(linkat(top, "outside", path, rollback_name, 0) == 0);
    CHECK(gate_access(&s, rollback_name) == -1);
    CHECK(gate_open(&s, rollback_name, false, false) == -1);
    CHECK(gate_delete_journal(&s, rollback_name, false) == -1);
    CHECK(unlinkat(path, rollback_name, 0) == 0);
    CHECK(mkfifoat(path, rollback_name, 0600) == 0);
    CHECK(gate_open(&s, rollback_name, false, false) == -1);
    CHECK(gate_delete_journal(&s, rollback_name, false) == -1);
    CHECK(unlinkat(path, rollback_name, 0) == 0);

    close_checked(gate_open(&s, rollback_name, true, true));
    close_checked(gate_open(&s, rollback_name, false, false));
    CHECK(gate_delete_journal(&s, rollback_name, true) == 0);
    CHECK(gate_access(&s, rollback_name) == 0);

    /* The held dirfd references the original directory, never the new name.
     * An eventual broker must DENY name replacement, not reuse the moved file. */
    CHECK(renameat(top, "pilot", top, "moved") == 0);
    CHECK(mkdirat(top, "pilot", 0700) == 0);
    int replacement = openat(top, "pilot", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(replacement >= 0);
    CHECK(symlinkat("../outside", replacement, main_name) == 0);
    int held = gate_open(&s, main_name, false, false);
    struct stat a, b;
    CHECK(held >= 0 && fstat(held, &a) == 0 && fstat(db, &b) == 0);
    CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
    close_checked(held);
    CHECK(!location_matches(&s, top));
    CHECK(unlinkat(replacement, main_name, 0) == 0);
    close_checked(replacement);

    marker = openat(top, "outside", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char data[7];
    CHECK(marker >= 0 && read(marker, data, sizeof data) == 7 && !memcmp(data, "outside", 7));
    close_checked(marker);
    close_checked(db);
    CHECK(unlinkat(path, main_name, 0) == 0);
    close_checked(path);
    CHECK(unlinkat(top, "moved", AT_REMOVEDIR) == 0);
    CHECK(unlinkat(top, "pilot", AT_REMOVEDIR) == 0);
    CHECK(unlinkat(top, "outside", 0) == 0);
    close_checked(top);
    CHECK(rmdir(tmp) == 0);
    puts("PASS synthetic held-dirfd fixed-name open/access/delete gate (not a SQLite VFS)");
    return 0;
}
