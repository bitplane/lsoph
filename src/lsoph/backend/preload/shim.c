/*
 * lsoph LD_PRELOAD shim.
 *
 * Interposes libc file calls, and writes one tab-separated record per call to
 * the fd opened on the FIFO named by $LSOPH_PIPE:
 *
 *     OP \t pid \t fd \t ret \t errno \t path [\t path2] \n
 *
 * lsoph creates the FIFO, sets LD_PRELOAD and LSOPH_PIPE, and reads the records.
 * The format is ours, so the Python parser is trivial. Records are <= PIPE_BUF,
 * so concurrent writes from threads/children stay atomic.
 *
 * Limitations: run-mode only (affects newly-launched, dynamically-linked,
 * non-setuid programs that make file calls through libc). Static binaries,
 * setuid binaries, and raw syscalls (e.g. Go) bypass it.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int lsoph_fd = -1;

static void record(const char *op, long fd, long ret, int err,
                   const char *path, const char *path2) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (lsoph_fd < 0)
        return;
    if (!real_write)
        real_write = dlsym(RTLD_NEXT, "write");
    if (!real_write)
        return;
    char buf[8192];
    int n = snprintf(buf, sizeof buf, "%s\t%ld\t%ld\t%ld\t%d\t%s%s%s\n",
                     op, (long)getpid(), fd, ret, err, path ? path : "",
                     path2 ? "\t" : "", path2 ? path2 : "");
    if (n < 0)
        return;
    if (n > (int)sizeof buf)
        n = sizeof buf;
    /* Real write, so we don't re-enter our own write() wrapper. */
    real_write(lsoph_fd, buf, (size_t)n);
}

__attribute__((constructor)) static void lsoph_init(void) {
    const char *p = getenv("LSOPH_PIPE");
    if (!p)
        return;
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    if (real_open)
        lsoph_fd = real_open(p, O_WRONLY); /* blocks until lsoph opens the read end */
}

/* --- open family (recorded as OPEN; fd is the return value) --- */

#define OPEN_BODY(realname, path)                                              \
    mode_t mode = 0;                                                           \
    if (flags & O_CREAT) {                                                     \
        va_list ap;                                                            \
        va_start(ap, flags);                                                   \
        mode = va_arg(ap, int);                                                \
        va_end(ap);                                                            \
    }                                                                          \
    int ret = realname;                                                        \
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;                  \
    record("OPEN", ret, ret, err, path, NULL);                                 \
    errno = saved_errno;                                                       \
    return ret;

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "open");
    OPEN_BODY(real(path, flags, mode), path)
}

int open64(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "open64");
    OPEN_BODY(real(path, flags, mode), path)
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "openat");
    OPEN_BODY(real(dirfd, path, flags, mode), path)
}

int openat64(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "openat64");
    OPEN_BODY(real(dirfd, path, flags, mode), path)
}

int creat(const char *path, mode_t mode) {
    static int (*real)(const char *, mode_t) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "creat");
    int ret = real(path, mode);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("OPEN", ret, ret, err, path, NULL);
    errno = saved_errno;
    return ret;
}

/* --- fd-based calls (skip our own pipe fd) --- */

int close(int fd) {
    static int (*real)(int) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "close");
    int ret = real(fd);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    if (fd != lsoph_fd)
        record("CLOSE", fd, ret, err, NULL, NULL);
    errno = saved_errno;
    return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real)(int, void *, size_t) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "read");
    ssize_t ret = real(fd, buf, count);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    if (fd != lsoph_fd)
        record("READ", fd, (long)ret, err, NULL, NULL);
    errno = saved_errno;
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real)(int, const void *, size_t) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "write");
    ssize_t ret = real(fd, buf, count);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    if (fd != lsoph_fd)
        record("WRITE", fd, (long)ret, err, NULL, NULL);
    errno = saved_errno;
    return ret;
}

/* --- path-based calls --- */

int access(const char *path, int mode) {
    static int (*real)(const char *, int) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "access");
    int ret = real(path, mode);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("STAT", -1, ret, err, path, NULL);
    errno = saved_errno;
    return ret;
}

int stat(const char *path, struct stat *st) {
    static int (*real)(const char *, struct stat *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "stat");
    int ret = real(path, st);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("STAT", -1, ret, err, path, NULL);
    errno = saved_errno;
    return ret;
}

int lstat(const char *path, struct stat *st) {
    static int (*real)(const char *, struct stat *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "lstat");
    int ret = real(path, st);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("STAT", -1, ret, err, path, NULL);
    errno = saved_errno;
    return ret;
}

int unlink(const char *path) {
    static int (*real)(const char *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "unlink");
    int ret = real(path);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("UNLINK", -1, ret, err, path, NULL);
    errno = saved_errno;
    return ret;
}

int rename(const char *oldp, const char *newp) {
    static int (*real)(const char *, const char *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "rename");
    int ret = real(oldp, newp);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("RENAME", -1, ret, err, oldp, newp);
    errno = saved_errno;
    return ret;
}
