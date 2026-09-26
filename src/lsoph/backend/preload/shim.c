/*
 * lsoph LD_PRELOAD shim.
 *
 * Interposes libc file calls, and writes one tab-separated record per call to
 * the fd opened on the FIFO named by $LSOPH_PIPE:
 *
 *     OP \t pid \t fd \t ret \t errno \t path [\t path2] \n
 *
 * where a backslash, tab or newline in a path is escaped as \\, \t or \n.
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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int lsoph_fd = -1;
/* Identity of the FIFO, to notice the program replacing our fd behind our
 * back (dup2 onto it, close_range, a raw close syscall...). */
static dev_t lsoph_dev;
static ino_t lsoph_ino;

static int lsoph_fd_ok(void) {
    struct stat st;
    if (lsoph_fd < 0)
        return 0;
    if (fstat(lsoph_fd, &st) != 0 || st.st_dev != lsoph_dev ||
        st.st_ino != lsoph_ino) {
        lsoph_fd = -1; /* never write records into the program's own file */
        return 0;
    }
    return 1;
}

/* Append src to buf at *len, escaping the record's separators (\\, \t, \n).
 * Returns 0 if it doesn't fit. */
static int put_escaped(char *buf, size_t cap, size_t *len, const char *src) {
    for (; *src; src++) {
        char esc = *src == '\\' ? '\\' : *src == '\t' ? 't' : *src == '\n' ? 'n' : 0;
        if (*len + (esc ? 2 : 1) > cap)
            return 0;
        if (esc) {
            buf[(*len)++] = '\\';
            buf[(*len)++] = esc;
        } else {
            buf[(*len)++] = *src;
        }
    }
    return 1;
}

static void record(const char *op, long fd, long ret, int err,
                   const char *path, const char *path2) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!lsoph_fd_ok())
        return;
    if (!real_write)
        real_write = dlsym(RTLD_NEXT, "write");
    if (!real_write)
        return;
    /* One write of at most PIPE_BUF bytes is atomic, so records from
     * concurrent threads and processes never interleave. */
    char buf[PIPE_BUF];
    const size_t cap = sizeof buf - 1; /* room for the final newline */
    int n = snprintf(buf, sizeof buf, "%s\t%ld\t%ld\t%ld\t%d\t", op,
                     (long)getpid(), fd, ret, err);
    if (n < 0 || (size_t)n > cap)
        return;
    size_t len = (size_t)n;
    if (path && !put_escaped(buf, cap, &len, path))
        return; /* too long to send whole: drop rather than send it cut */
    if (path2) {
        if (len + 1 > cap)
            return;
        buf[len++] = '\t';
        if (!put_escaped(buf, cap, &len, path2))
            return;
    }
    buf[len++] = '\n';
    /* Real write, so we don't re-enter our own write() wrapper. */
    real_write(lsoph_fd, buf, len);
}

__attribute__((constructor)) static void lsoph_init(void) {
    const char *p = getenv("LSOPH_PIPE");
    if (!p)
        return;
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    if (!real_open)
        return;
    int fd = real_open(p, O_WRONLY); /* blocks until lsoph opens the read end */
    if (fd < 0)
        return;
    /* Park it above the fds programs normally use, and close-on-exec: an
     * exec'd child reopens the FIFO from its own constructor. */
    int high = fcntl(fd, F_DUPFD_CLOEXEC, 512);
    if (high >= 0) {
        close(fd); /* lsoph_fd is still -1, so this isn't recorded */
        fd = high;
    }
    struct stat st;
    if (fstat(fd, &st) != 0)
        return;
    lsoph_dev = st.st_dev;
    lsoph_ino = st.st_ino;
    lsoph_fd = fd;
}

/* --- open family (recorded as OPEN; fd is the return value) --- */

/* As glibc's __OPEN_NEEDS_MODE: O_TMPFILE takes a mode too. */
#ifdef O_TMPFILE
#define NEEDS_MODE(flags)                                                      \
    (((flags) & O_CREAT) != 0 || ((flags) & O_TMPFILE) == O_TMPFILE)
#else
#define NEEDS_MODE(flags) (((flags) & O_CREAT) != 0)
#endif

#define OPEN_BODY(realname, path)                                              \
    mode_t mode = 0;                                                           \
    if (NEEDS_MODE(flags)) {                                                   \
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
    if (fd == lsoph_fd && lsoph_fd >= 0)
        return 0; /* e.g. a daemon's close-all loop: keep our pipe */
    if (!real)
        real = dlsym(RTLD_NEXT, "close");
    int ret = real(fd);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
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
