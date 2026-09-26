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
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
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
        char esc = *src == '\\'   ? '\\'
                   : *src == '\t' ? 't'
                   : *src == '\n' ? 'n'
                                  : 0;
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

/* Write one record without letting a closed FIFO (lsoph exited or is
 * stopping) SIGPIPE the traced program: block SIGPIPE around the write, and
 * swallow the one it raised -- unless one was already pending for the
 * program. On EPIPE, stop recording. */
static void write_record(ssize_t (*real_write)(int, const void *, size_t),
                         const char *buf, size_t len) {
    sigset_t pipe_set, old_set, pending;
    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    sigprocmask(SIG_BLOCK, &pipe_set, &old_set);
    sigpending(&pending);
    int was_pending = sigismember(&pending, SIGPIPE);
    /* Real write, so we don't re-enter our own write() wrapper. */
    if (real_write(lsoph_fd, buf, len) < 0 && errno == EPIPE) {
        lsoph_fd = -1;
        if (!was_pending) {
            struct timespec zero = {0, 0};
            sigtimedwait(&pipe_set, NULL, &zero);
        }
    }
    sigprocmask(SIG_SETMASK, &old_set, NULL);
}

/* Make path absolute as of now: relative to dirfd (or the cwd), which may
 * have changed by the time lsoph reads the record. Returns path unchanged if
 * already absolute or unresolvable. */
static const char *absolute(int dirfd, const char *path, char *out,
                            size_t cap) {
    if (!path || path[0] == '/' || path[0] == 0)
        return path;
    char base[PATH_MAX];
    if (dirfd == AT_FDCWD) {
        if (!getcwd(base, sizeof base))
            return path;
    } else {
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);
        ssize_t n = readlink(link, base, sizeof base - 1);
        if (n <= 0)
            return path;
        base[n] = 0;
    }
    int n = snprintf(out, cap, "%s%s%s", base, base[1] ? "/" : "", path);
    return n > 0 && (size_t)n < cap ? out : path;
}

static void record(const char *op, long fd, long ret, int err, int dirfd,
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
    char abs1[PATH_MAX], abs2[PATH_MAX];
    path = absolute(dirfd, path, abs1, sizeof abs1);
    path2 = absolute(dirfd, path2, abs2, sizeof abs2);
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
    write_record(real_write, buf, len);
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

#define OPEN_BODY(realname, dirfd, path)                                       \
    mode_t mode = 0;                                                           \
    if (NEEDS_MODE(flags)) {                                                   \
        va_list ap;                                                            \
        va_start(ap, flags);                                                   \
        mode = va_arg(ap, int);                                                \
        va_end(ap);                                                            \
    }                                                                          \
    int ret = realname;                                                        \
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;                  \
    record("OPEN", ret, ret, err, dirfd, path, NULL);                          \
    errno = saved_errno;                                                       \
    return ret;

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "open");
    OPEN_BODY(real(path, flags, mode), AT_FDCWD, path)
}

int open64(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "open64");
    OPEN_BODY(real(path, flags, mode), AT_FDCWD, path)
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "openat");
    OPEN_BODY(real(dirfd, path, flags, mode), dirfd, path)
}

int openat64(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char *, int, ...) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "openat64");
    OPEN_BODY(real(dirfd, path, flags, mode), dirfd, path)
}

int creat(const char *path, mode_t mode) {
    static int (*real)(const char *, mode_t) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "creat");
    int ret = real(path, mode);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("OPEN", ret, ret, err, AT_FDCWD, path, NULL);
    errno = saved_errno;
    return ret;
}

/* _FORTIFY_SOURCE builds call these checked variants (no mode argument). */
#define OPEN_2(name, ...)                                                      \
    static int (*real)(__VA_ARGS__) = NULL;                                    \
    if (!real)                                                                 \
        real = dlsym(RTLD_NEXT, name)

int __open_2(const char *path, int flags) {
    OPEN_2("__open_2", const char *, int);
    int ret = real(path, flags);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("OPEN", ret, ret, err, AT_FDCWD, path, NULL);
    errno = saved_errno;
    return ret;
}

int __open64_2(const char *path, int flags) {
    OPEN_2("__open64_2", const char *, int);
    int ret = real(path, flags);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("OPEN", ret, ret, err, AT_FDCWD, path, NULL);
    errno = saved_errno;
    return ret;
}

int __openat_2(int dirfd, const char *path, int flags) {
    OPEN_2("__openat_2", int, const char *, int);
    int ret = real(dirfd, path, flags);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("OPEN", ret, ret, err, dirfd, path, NULL);
    errno = saved_errno;
    return ret;
}

int __openat64_2(int dirfd, const char *path, int flags) {
    OPEN_2("__openat64_2", int, const char *, int);
    int ret = real(dirfd, path, flags);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("OPEN", ret, ret, err, dirfd, path, NULL);
    errno = saved_errno;
    return ret;
}

/* --- stdio: glibc opens and closes FILEs through internal, uninterposable
 * calls, so fopen/fclose are wrapped themselves. --- */

#define FOPEN_BODY(name)                                                       \
    static FILE *(*real)(const char *, const char *) = NULL;                   \
    if (!real)                                                                 \
        real = dlsym(RTLD_NEXT, name);                                         \
    FILE *ret = real(path, mode);                                              \
    int saved_errno = errno;                                                   \
    int fd = ret ? fileno(ret) : -1;                                           \
    record("OPEN", fd, fd, ret ? 0 : saved_errno, AT_FDCWD, path, NULL);       \
    errno = saved_errno;                                                       \
    return ret;

FILE *fopen(const char *path, const char *mode) { FOPEN_BODY("fopen") }

FILE *fopen64(const char *path, const char *mode) { FOPEN_BODY("fopen64") }

int fclose(FILE *stream) {
    static int (*real)(FILE *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "fclose");
    int fd = fileno(stream);
    int ret = real(stream);
    int saved_errno = errno, err = ret != 0 ? saved_errno : 0;
    if (fd >= 0)
        record("CLOSE", fd, ret, err, AT_FDCWD, NULL, NULL);
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
    record("CLOSE", fd, ret, err, AT_FDCWD, NULL, NULL);
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
        record("READ", fd, (long)ret, err, AT_FDCWD, NULL, NULL);
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
        record("WRITE", fd, (long)ret, err, AT_FDCWD, NULL, NULL);
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
    record("STAT", -1, ret, err, AT_FDCWD, path, NULL);
    errno = saved_errno;
    return ret;
}

int stat(const char *path, struct stat *st) {
    static int (*real)(const char *, struct stat *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "stat");
    int ret = real(path, st);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("STAT", -1, ret, err, AT_FDCWD, path, NULL);
    errno = saved_errno;
    return ret;
}

int lstat(const char *path, struct stat *st) {
    static int (*real)(const char *, struct stat *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "lstat");
    int ret = real(path, st);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("STAT", -1, ret, err, AT_FDCWD, path, NULL);
    errno = saved_errno;
    return ret;
}

int unlink(const char *path) {
    static int (*real)(const char *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "unlink");
    int ret = real(path);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("UNLINK", -1, ret, err, AT_FDCWD, path, NULL);
    errno = saved_errno;
    return ret;
}

int rename(const char *oldp, const char *newp) {
    static int (*real)(const char *, const char *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "rename");
    int ret = real(oldp, newp);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    record("RENAME", -1, ret, err, AT_FDCWD, oldp, newp);
    errno = saved_errno;
    return ret;
}

/* --- *at and 64-bit variants (what glibc >= 2.33 programs call directly) */

#define PATH_CALL(op, name, proto, call, dirfd, path)                          \
    static int(*real) proto = NULL;                                            \
    if (!real)                                                                 \
        real = dlsym(RTLD_NEXT, name);                                         \
    int ret = real call;                                                       \
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;                  \
    record(op, -1, ret, err, dirfd, path, NULL);                               \
    errno = saved_errno;                                                       \
    return ret;

int stat64(const char *path, struct stat64 *st) {
    PATH_CALL("STAT", "stat64", (const char *, struct stat64 *), (path, st),
              AT_FDCWD, path)
}

int lstat64(const char *path, struct stat64 *st) {
    PATH_CALL("STAT", "lstat64", (const char *, struct stat64 *), (path, st),
              AT_FDCWD, path)
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    PATH_CALL("STAT", "fstatat", (int, const char *, struct stat *, int),
              (dirfd, path, st, flags), dirfd, path)
}

int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags) {
    PATH_CALL("STAT", "fstatat64", (int, const char *, struct stat64 *, int),
              (dirfd, path, st, flags), dirfd, path)
}

#ifdef STATX_BASIC_STATS
int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *stx) {
    PATH_CALL("STAT", "statx",
              (int, const char *, int, unsigned int, struct statx *),
              (dirfd, path, flags, mask, stx), dirfd, path)
}
#endif

int faccessat(int dirfd, const char *path, int mode, int flags) {
    PATH_CALL("STAT", "faccessat", (int, const char *, int, int),
              (dirfd, path, mode, flags), dirfd, path)
}

int unlinkat(int dirfd, const char *path, int flags) {
    PATH_CALL("UNLINK", "unlinkat", (int, const char *, int),
              (dirfd, path, flags), dirfd, path)
}

int rmdir(const char *path) {
    PATH_CALL("UNLINK", "rmdir", (const char *), (path), AT_FDCWD, path)
}

int renameat(int olddirfd, const char *oldp, int newdirfd, const char *newp) {
    static int (*real)(int, const char *, int, const char *) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "renameat");
    int ret = real(olddirfd, oldp, newdirfd, newp);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    char a[PATH_MAX], b[PATH_MAX];
    record("RENAME", -1, ret, err, AT_FDCWD,
           absolute(olddirfd, oldp, a, sizeof a),
           absolute(newdirfd, newp, b, sizeof b));
    errno = saved_errno;
    return ret;
}

int renameat2(int olddirfd, const char *oldp, int newdirfd, const char *newp,
              unsigned int flags) {
    static int (*real)(int, const char *, int, const char *, unsigned int) =
        NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "renameat2");
    int ret = real(olddirfd, oldp, newdirfd, newp, flags);
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;
    char a[PATH_MAX], b[PATH_MAX];
    record("RENAME", -1, ret, err, AT_FDCWD,
           absolute(olddirfd, oldp, a, sizeof a),
           absolute(newdirfd, newp, b, sizeof b));
    errno = saved_errno;
    return ret;
}

/* --- positional and vectored I/O --- */

#define IO_CALL(op, name, proto, call, fd)                                     \
    static ssize_t(*real) proto = NULL;                                        \
    if (!real)                                                                 \
        real = dlsym(RTLD_NEXT, name);                                         \
    ssize_t ret = real call;                                                   \
    int saved_errno = errno, err = ret < 0 ? saved_errno : 0;                  \
    if (fd != lsoph_fd)                                                        \
        record(op, fd, (long)ret, err, AT_FDCWD, NULL, NULL);                  \
    errno = saved_errno;                                                       \
    return ret;

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
    IO_CALL("READ", "pread", (int, void *, size_t, off_t),
            (fd, buf, count, offset), fd)
}

ssize_t pread64(int fd, void *buf, size_t count, off64_t offset) {
    IO_CALL("READ", "pread64", (int, void *, size_t, off64_t),
            (fd, buf, count, offset), fd)
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    IO_CALL("WRITE", "pwrite", (int, const void *, size_t, off_t),
            (fd, buf, count, offset), fd)
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
    IO_CALL("WRITE", "pwrite64", (int, const void *, size_t, off64_t),
            (fd, buf, count, offset), fd)
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    IO_CALL("READ", "readv", (int, const struct iovec *, int),
            (fd, iov, iovcnt), fd)
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    IO_CALL("WRITE", "writev", (int, const struct iovec *, int),
            (fd, iov, iovcnt), fd)
}

/* --- fd duplication: an OPEN of the new fd under the file's path, after a
 * CLOSE if dup2/dup3 replaced an fd that was open. --- */

static void record_dup(int newfd, int replaced) {
    char link[64], path[PATH_MAX];
    if (replaced)
        record("CLOSE", newfd, 0, 0, AT_FDCWD, NULL, NULL);
    snprintf(link, sizeof link, "/proc/self/fd/%d", newfd);
    ssize_t n = readlink(link, path, sizeof path - 1);
    if (n <= 0 || path[0] != '/')
        return; /* a pipe, socket, ...: not a file */
    path[n] = 0;
    record("OPEN", newfd, newfd, 0, AT_FDCWD, path, NULL);
}

int dup(int oldfd) {
    static int (*real)(int) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "dup");
    int ret = real(oldfd);
    int saved_errno = errno;
    if (ret >= 0)
        record_dup(ret, 0);
    errno = saved_errno;
    return ret;
}

int dup2(int oldfd, int newfd) {
    static int (*real)(int, int) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "dup2");
    int was_open = oldfd != newfd && fcntl(newfd, F_GETFD) != -1;
    int ret = real(oldfd, newfd);
    int saved_errno = errno;
    if (ret >= 0 && oldfd != newfd)
        record_dup(ret, was_open);
    errno = saved_errno;
    return ret;
}

int dup3(int oldfd, int newfd, int flags) {
    static int (*real)(int, int, int) = NULL;
    if (!real)
        real = dlsym(RTLD_NEXT, "dup3");
    int was_open = fcntl(newfd, F_GETFD) != -1;
    int ret = real(oldfd, newfd, flags);
    int saved_errno = errno;
    if (ret >= 0)
        record_dup(ret, was_open);
    errno = saved_errno;
    return ret;
}
