/* Actual lease dependency for the test-only rollback writer. No SQLite or
 * production paths. Only fresh children independently open the lock. */
#define main phase_zero_main
#include "pilot_sqlite_dirfd_gate.c"
#undef main
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/wait.h>

static const char lease_name[] = "pilot.sqlite.lock";
enum lease_state { lease_held, lease_busy, lease_rejected };

static bool matches_lock(const struct scope *s, const struct stat *st, ino_t inode) {
    return allowed_stat(s, st) && st->st_ino == inode && st->st_size == 0;
}

static enum lease_state acquire(const struct scope *s, int parent, ino_t inode, int *leasefd) {
    struct stat held, named;
    *leasefd = -1;
    if (!location_matches(s, parent)) return lease_rejected;
    const int fd = openat(s->directory, lease_name, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return lease_rejected;
    if (fstat(fd, &held) != 0 || !matches_lock(s, &held, inode)) {
        close(fd);
        return lease_rejected;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        const int error = errno;
        close(fd);
        return error == EWOULDBLOCK || error == EAGAIN ? lease_busy : lease_rejected;
    }
    if (!location_matches(s, parent) ||
        fstat(fd, &held) != 0 || !matches_lock(s, &held, inode) ||
        fstatat(s->directory, lease_name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !matches_lock(s, &named, inode)) {
        close(fd);
        return lease_rejected;
    }
    *leasefd = fd;
    return lease_held;
}

#ifndef AKC_LEASE_PRIMITIVES_ONLY
static int waited(pid_t child) {
    int status;
    pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    CHECK(got == child);
    return status;
}

/* New process, fresh open. Do not use an inherited or duplicated lock FD:
 * flock tracks an open file description. */
static enum lease_state contend(const struct scope *s, int parent, ino_t inode) {
    const pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int fd;
        const enum lease_state got = acquire(s, parent, inode, &fd);
        if (fd >= 0 && close(fd) != 0) _exit(99);
        _exit(got);
    }
    const int status = waited(child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) <= lease_rejected);
    return (enum lease_state)WEXITSTATUS(status);
}

int main(void) {
    CHECK(getuid() != 0 && getuid() == geteuid());
    umask(077);
    char temp[] = "/tmp/akc-sqlite-lease-XXXXXX";
    CHECK(mkdtemp(temp) != NULL);
    const int parent = open(temp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(parent >= 0 && mkdirat(parent, "pilot", 0700) == 0);
    const int directory = openat(parent, "pilot", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat dir, locked;
    CHECK(directory >= 0 && fstat(directory, &dir) == 0);
    struct scope s = {directory, dir.st_dev, dir.st_uid, dir.st_ino};
    CHECK(location_matches(&s, parent));

    const int bootstrap = openat(directory, lease_name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    CHECK(bootstrap >= 0 && fstat(bootstrap, &locked) == 0 && matches_lock(&s, &locked, locked.st_ino));
    CHECK(fsync(bootstrap) == 0 && fsync(directory) == 0);
    close_checked(bootstrap); /* Parent must hold no lease FD when forking. */

    int ready[2], keepalive[2];
    CHECK(pipe(ready) == 0 && pipe(keepalive) == 0);
    const pid_t owner = fork();
    CHECK(owner >= 0);
    if (owner == 0) {
        close_checked(ready[0]);
        close_checked(keepalive[1]);
        int fd;
        if (acquire(&s, parent, locked.st_ino, &fd) != lease_held) _exit(98);
        if (write(ready[1], "L", 1) != 1) _exit(97);
        close_checked(ready[1]);
        /* Normally SIGKILL. Parent failure instead closes the pipe, so the
         * bounded synthetic test cannot leave an orphan holding the lease. */
        char dummy;
        while (read(keepalive[0], &dummy, 1) < 0 && errno == EINTR) {}
        close(fd);
        _exit(96);
    }
    close_checked(ready[1]);
    close_checked(keepalive[0]);
    struct pollfd signal = {.fd = ready[0], .events = POLLIN};
    char marker = 0;
    const bool owned = poll(&signal, 1, 3000) == 1 && (signal.revents & POLLIN) && read(ready[0], &marker, 1) == 1 && marker == 'L';
    close_checked(ready[0]);
    const enum lease_state during = owned ? contend(&s, parent, locked.st_ino) : lease_rejected;
    const int killed = kill(owner, SIGKILL);
    close_checked(keepalive[1]);
    const int stopped = waited(owner);
    CHECK(killed == 0);
    CHECK(owned && during == lease_busy && WIFSIGNALED(stopped) && WTERMSIG(stopped) == SIGKILL);
    CHECK(contend(&s, parent, locked.st_ino) == lease_held);
    CHECK(contend(&s, parent, locked.st_ino) == lease_held); /* after a clean release too */

    /* A new otherwise-valid file has no old authorization. Do not place or
     * remove a lock as part of ordinary startup, even after an owner crash. */
    CHECK(linkat(directory, lease_name, directory, "alias", 0) == 0);
    CHECK(contend(&s, parent, locked.st_ino) == lease_rejected);
    CHECK(unlinkat(directory, "alias", 0) == 0);
    CHECK(renameat(directory, lease_name, directory, "preserved") == 0);
    CHECK(contend(&s, parent, locked.st_ino) == lease_rejected);
    CHECK(symlinkat("preserved", directory, lease_name) == 0);
    CHECK(contend(&s, parent, locked.st_ino) == lease_rejected);
    CHECK(unlinkat(directory, lease_name, 0) == 0);
    const int replacement = openat(directory, lease_name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    CHECK(replacement >= 0);
    close_checked(replacement);
    CHECK(contend(&s, parent, locked.st_ino) == lease_rejected);
    CHECK(unlinkat(directory, lease_name, 0) == 0);
    CHECK(renameat(directory, "preserved", directory, lease_name) == 0);
    CHECK(contend(&s, parent, locked.st_ino) == lease_held);
    struct stat stable;
    CHECK(fstatat(directory, lease_name, &stable, AT_SYMLINK_NOFOLLOW) == 0 && matches_lock(&s, &stable, locked.st_ino));

    /* Teardown only, under the disposable test owner's control. */
    CHECK(unlinkat(directory, lease_name, 0) == 0);
    close_checked(directory);
    CHECK(unlinkat(parent, "pilot", AT_REMOVEDIR) == 0);
    close_checked(parent);
    CHECK(rmdir(temp) == 0);
    puts("PASS POSIX independent lease deny, crash release, and exact-inode reacquisition");
    return 0;
}

#endif
