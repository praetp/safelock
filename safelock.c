/* Safelock - robust file-based locking between threads and processes.
 *
 * Copyright (c) 2012  Mark Pulford <mark@kyne.com.au>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Safelock implementation
 *
 * A Safelock consistents of:
 * - open_mutex:  Used to block multiple ownership attempts. May be
 *                held for an extended period by a thread.
 * - data_mutex:  Used to synchronised ownership/data changes. Only held
 *                briefly during safelock_t updates/checking
 * - owner_mutex: Used to determine ownership status. May be held for
 *                an extended period by a thread.
 *
 * - taken:   Timestamp the owner_mutex was taken, otherwise 0 before
 *            use or after clean release.
 * - PID:     PID of the last process to own the lock, or 0 if never
 *            used.
 * - data:    A simple "int" which can be used by the application to
 *            atomically store some lock specific data.
 * - removed: A flag which indicates whether this safelock has been
 *            removed. All further lock/in_use operations will return
 *            EINVAL indicating the safelock should be closed and
 *            reopened.
 * - data_valid: A flag indicating the safelock data is missing or may
 *               have been corrupted. Cleared after the next successful
 *               lock.
 *
 * data_mutex must be held whenever the owner_mutex or other data is
 * read or updated. This ensures that safelock fields (pid, taken,
 * ownership, data) are updated atomically.
 *
 * data_mutex is only held briefly within a single safelock_* call
 * to prevent extended waiting.
 *
 * open_mutex is required to prevent a pending safelock_lock() attempt
 * from holding the data_mutex indefinitely.
 */

/* Error handling rationale.
 *
 * Errors that can occur due to normal operation, or factors outside of
 * the program should result in an error return.
 *
 * Shared memory corruption should result in an error return (if
 * possible). However if the window of opportunity is slight, an
 * exit failure may to used to simplify error handling. Eg,
 * data_mutex_lock() works, but unlock fails with EINVAL.
 *
 * Bugs may be handled by exiting.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>

#include "safelock.h"

#define NOFAIL(x)           \
    do {                    \
        int _err = (x);     \
        if (_err) {         \
            safelock_die(_err, "%s:%d: %s", __FILE__, __LINE__, #x); \
        }                   \
    } while (0)

#define SYS_NOFAIL(x)       \
    do {                    \
        int _ret = (x);     \
        if (_ret < 0)       \
            safelock_die(errno, "%s:%d: %s", __FILE__, __LINE__, #x); \
    } while (0)

typedef struct {
    pthread_mutex_t open_mutex;
    pthread_mutex_t data_mutex;
    pthread_mutex_t owner_mutex;
    int removed;    /* Safelock has been removed, must re-open */
    int data_valid; /* Lock data exists */
    pid_t pid;      /* Current or last PID to own lock (0 = never) */
    uint64_t taken; /* 0 = never used, or clean exit. */
    int data;       /* Last data set */
} lock_data_t;

struct _safelock {
    char *filename;
    int fd;
    lock_data_t *shared;
    int locked;     /* Set when safelock has been taken */
};

void safelock_die(int err, const char *fmt, ...)
{
    char msg[256];
    char errmsg[256] = "unknown error";
    va_list arg;

    if (err) {
        /* Support both GNU/POSIX strerror_r() */
        snprintf(errmsg, sizeof(errmsg), "Unknown error %d", err);
        strerror_r(err, errmsg, sizeof(errmsg));
    }

    va_start(arg, fmt);
    /* Truncate long messages */
    if (vsnprintf(msg, sizeof(msg), fmt, arg) < 0)
        strcpy(msg, "safelock_die: unknown");
    va_end(arg);

    if (err)
        fprintf(stderr, "%s: %s\n", msg, errmsg);
    else
        fprintf(stderr, "%s\n", msg);

    exit(EXIT_FAILURE);
}

static int pid_exists(pid_t pid)
{
    int ret;

    /* Success, EPERM: PID must exist.
     * ESRCH: PID doesn't exist.
     * Other errors cannot occur. */
    ret = kill(pid, 0);
    if (!ret || errno == EPERM)
        return 1;

    assert(errno == ESRCH);
    return 0;
}

static lock_data_t *mmap_lock_data(int fd)
{
    return mmap(NULL, sizeof(lock_data_t), PROT_READ|PROT_WRITE,
                MAP_SHARED, fd, 0);
}

static void munmap_lock_data(lock_data_t *shared)
{
    /* Munmap should only be asked to free a mapping returned by
     * mmap_lock_data. Failure indicates a local bug. */
    SYS_NOFAIL(munmap(shared, sizeof(*shared)));
}

/* Lock a mutex and handle EOWNERDEAD.
 *
 * Arguments:
 * - deadline: lock deadline in microseconds since the epoch
 * - *dirty: optionally reports whether the previous lock owner crashed
 *
 * Handles EOWNERDEAD from robust mutexes if "dirty" is not set,
 * otherwise sets *dirty and leaves cleanup for the caller.
 *
 * Returns 0 on success, and errno on failure:
 *
 * EBUSY            SAFELOCK_LOCK_TRY set, and already locked
 * EDEADLK          The mutex is already locked by the current thread
 * ENOTRECOVERABLE  The mutex is corrupted and needs to be re-init
 * ETIMEDOUT        The mutex could not be locked within the timeout
 *                  specified
 */
static int mutex_lock(pthread_mutex_t *lock, uint64_t deadline,
                      int *dirty)
{
    struct timespec ts;
    int err;

    if (deadline == SAFELOCK_LOCK_WAIT) {
        err = pthread_mutex_lock(lock);
    } else if (deadline == SAFELOCK_LOCK_TRY) {
        err = pthread_mutex_trylock(lock);
    } else {
        ts.tv_sec = deadline / 1000000;
        ts.tv_nsec = (deadline % 1000000) * 1000;
        err = pthread_mutex_timedlock(lock, &ts);
    }

    if (dirty)
        *dirty = 0;
    if (err == EOWNERDEAD) {
#ifdef __USE_XOPEN2K8
        /* pthread_mutex_consistent should only fail when
         * the lock isn't robust, or the state is already
         * consistent - either indicates a bug */
        NOFAIL(pthread_mutex_consistent(lock));
        if (dirty)
            *dirty = 1;
#else
        return ENOTRECOVERABLE;
#endif
    } else if (err == EINVAL) {
        /* If a mutex has been corrupted the safelock will need
         * to be removed in a race free manner (Eg, manually) */
        return ENOTRECOVERABLE;
    } else if (err) {
        return err;
    }

    return 0;
}

/* Lock "data_mutex" and detect whether the safelock has been removed.
 *
 * Used when the caller intends to lock "owner_mutex" */
static int data_mutex_lock(safelock_t lock, int *dirty)
{
    lock_data_t *shared;
    int err;

    assert(lock);
    assert(lock->shared);

    shared = lock->shared;

    err = mutex_lock(&shared->data_mutex, SAFELOCK_LOCK_WAIT, dirty);
    if (err) {
        assert(err != EDEADLK); /* BUG: Locked twice within 1 thread.. */
        return err;
    }

    if (shared->removed) {
        /* dead safelock - return EINVAL to advise the
         * caller the safelock should be re-opened. */
        NOFAIL(pthread_mutex_unlock(&shared->data_mutex));
        return EINVAL;
    }

    return 0;
}

/* Write "length" zeros at the start of fd (sparse). */
static ssize_t write_sparse_zeros(int fd, size_t length)
{
    int ret, try;

    assert(length > 0);

    try = 1;
    errno = EINTR;  /* Force EINTR if ret == 0 below */
    do {
        ret = pwrite(fd, "", 1, length - 1);
    } while (ret <= 0 && errno == EINTR && try++ < 3);

    if (!ret)
        ret = -1;

    return ret;
}

/* Return time since epoch in microseconds. */
static uint64_t gettimeofday_us()
{
    struct timeval now;
    int err;

    err = gettimeofday(&now, NULL);
    assert(!err);

    return now.tv_sec * (uint64_t)1000000 + now.tv_usec;
}

/* Generate a "unique" enough seed.
 *
 * Generate different random sequences using:
 * - getpid() for process separation
 * - stack address of "seed" for thread separation since each thread has
 *   a different location on the stack. Divide by 16 to handle 16 byte
 *   aligned variables. Many operating systems use Address Space Layout
 *   Randomization (ASLR) which greatly increases the effectiveness of
 *   using the stack address as a seed.
 * - The time is used to ensure the same thread receives a different
 *   sequence after each call to seed_init()
 */
static void seed_init(unsigned short seed[3])
{
    seed[0] = gettimeofday_us() % 0x10000;
    seed[1] = getpid() % 0x10000;
    seed[2] = ((unsigned long)seed / 16) % 0x10000;
}

/* Atomically create and open a file with a unique filename
 *
 * mkstemp_mode allows the mode to be specifed, unlike mkstemp. */
static int mkstemp_mode(char *filename, mode_t mode)
{
    unsigned short seed[3];
    int fd, try, prefix_len;
    char *suffix;

    assert(filename);

    seed_init(seed);

    /* Calculate suffix pointer and ensure suffix is XXXXXX */
    prefix_len = strlen(filename) - 6;
    suffix = &filename[prefix_len];
    if (prefix_len < 0 || strcmp(suffix, "XXXXXX")) {
        errno = EINVAL;
        return -1;
    }

    try = 1;
    do {
        sprintf(suffix, "%06x", (unsigned)nrand48(seed) & 0xFFFFFF);
        fd = open(filename, O_CREAT|O_EXCL|O_RDWR, mode);
    } while (fd < 0 && errno == EEXIST && try++ < 10);

    return fd;
}

/* Create a shared lock file with a unique filename.
 *
 * Returns allocated string containing the new filename.
 * On failure, returns NULL and sets errno.
 */
static char *safelock_create_unique(const char *lock_prefix, mode_t mode)
{
    const char *lock_suffix = "XXXXXX";
    const mode_t owner_rw = S_IRUSR | S_IWUSR;
    char *lockfile;
    lock_data_t *shared;
    pthread_mutexattr_t attr;
    int fd, ret, err;

    /* All processes using the lock file must have read/write access.
     * Require owner access as a minimum */
    if ((mode & owner_rw) != owner_rw) {
        errno = EACCES;
        return NULL;
    }

    /* Allocate and init filename pattern. Leave space for the
     * NULL terminator. */
    lockfile = malloc(strlen(lock_prefix) + strlen(lock_suffix) + 1);
    if (!lockfile) {
        errno = ENOMEM;
        return NULL;
    }
    strcpy(lockfile, lock_prefix);
    strcat(lockfile, lock_suffix);

    fd = mkstemp_mode(lockfile, mode);
    if (fd < 0) {
        err = errno;
        goto error_free_lockfile;
    }

    /* Allocate file on disk for the shared lock data */
    ret = write_sparse_zeros(fd, sizeof(*shared));
    if (ret < 0) {
        err = errno;
        goto error_close_lockfile;
    }

    shared = mmap_lock_data(fd);
    if (!shared) {
        err = errno;
        goto error_close_lockfile;
    }

    if ((err = pthread_mutexattr_init(&attr)) ||
        (err = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) ||
#ifdef __USE_XOPEN2K
        (err = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST)) ||
#endif
        (err = pthread_mutexattr_settype(&attr,
                                         PTHREAD_MUTEX_ERRORCHECK)) ||
        (err = pthread_mutex_init(&shared->open_mutex, &attr)) ||
        (err = pthread_mutex_init(&shared->data_mutex, &attr)) ||
        (err = pthread_mutex_init(&shared->owner_mutex, &attr)) ||
        (err = pthread_mutexattr_destroy(&attr))) {
        munmap_lock_data(shared);
        goto error_close_lockfile;
    }

    munmap_lock_data(shared);

    /* Skip handling close() errors. The file descriptor state is
     * undefined after an error, but is likely closed. Worst case,
     * the file descriptor may be leaked. */
    close(fd);

    return lockfile;

error_close_lockfile:
    close(fd);
    unlink(lockfile);
error_free_lockfile:
    free(lockfile);
    errno = err;
    return NULL;
}

/* Create a new lock file and atomically move it into place.
 *
 * Returns 0 on success, otherwise errno.
 * If another thread creates the lock file first, return success */
static int safelock_create(const char *filename, mode_t mode)
{
    char *filename_tmp;
    int ret, err;

    filename_tmp = safelock_create_unique(filename, mode);
    if (!filename_tmp)
        return errno;

    ret = link(filename_tmp, filename);
    /* Ignore EEXIST, assume another process created the lock first */
    err = (ret < 0 && errno != EEXIST) ? errno : 0;

    /* Unlink shouldn't fail except during very exceptional race
     * conditions:
     * - Another process removed the file
     * - Another process changed the permissions
     * - The filesystem was remounted read-only
     * - ..
     *
     * Skip error checking, if the file couldn't be unlinked, some
     * littering may occur. */
    unlink(filename_tmp);
    free(filename_tmp);

    return err;
}

/* Free a safelock_t object and its resources */
int safelock_close(safelock_t *lock)
{
    lock_data_t *shared;
    int err;

    assert(lock && *lock);

    /* Don't unlink() since a new locker may be pending.
     * Allow applications to make that policy decision by using
     * safelock_remove() before calling safelock_close(). */

    shared = (*lock)->shared;

    err = 0;
    if ((*lock)->locked)
        err = safelock_unlock(*lock);

    /* Skip returning EINVAL since the caller will have to
     * re-open the lock anyway.. */
    if (err == EINVAL)
        err = 0;

    munmap_lock_data(shared);

    /* Skip handling close() errors. The file descriptor state is
     * undefined after an error, but is likely closed. Worst case,
     * the file descriptor may be leaked. */
    close((*lock)->fd);

    free((*lock)->filename);
    free(*lock);

    *lock = NULL;

    return err;
}

/* Initialise a safelock_t object for a lock file.
 *
 * Create the lock file if necessary (provided mode is non-zero).
 * safelock_t is returned in an unlocked state.
 *
 * Returns 0 on success, otherwise errno
 */
int safelock_open(safelock_t *lock, const char *filename, mode_t mode)
{
    lock_data_t *shared;
    int fd;
    safelock_t newlock;
    int err;

    fd = open(filename, O_RDWR);
    if (fd < 0 && errno == ENOENT && mode) {
            err = safelock_create(filename, mode);
            if (err)
                return err;
            fd = open(filename, O_RDWR);
    }
    if (fd < 0)
        return errno;

    shared = mmap_lock_data(fd);
    if (!shared) {
        err = errno;
        /* The fd may leak if close fails (undefined), but this is
         * the lesser evil.. */
        close(fd);
        return err;
    }

    newlock = malloc(sizeof(*newlock));
    if (!newlock)
        goto error_nomem;
    newlock->filename = strdup(filename);
    if (!newlock->filename) {
        free(newlock);
        goto error_nomem;
    }
    newlock->shared = shared;
    newlock->fd = fd;
    newlock->locked = 0;

    *lock = newlock;

    return 0;

error_nomem:
    munmap_lock_data(shared);
    close(fd);
    return ENOMEM;
}

/* Attempt to lock an open Safelock
 *
 * safelock_lock will fail if it is unable to lock the file within
 * "timeout" microseconds. "timeout == 0" will wait for success.
 *
 * Return 0 on success, otherwise returns errno:
 * - ETIMEDOUT: Lock attempt timed out
 * - EDEADLK: Caller owners the lock
 * - EINVAL: Safelock removed, need to close and re-open the lock file
 * - ..
 */
int safelock_lock(safelock_t lock, uint64_t timeout, int data)
{
    lock_data_t *shared;
    uint64_t deadline;
    int err;

    assert(lock);

    deadline = timeout;
    if (deadline > SAFELOCK_LOCK_TRY)
        deadline += gettimeofday_us();

    shared = lock->shared;

    /* Wait for owner mutex to be freed here */
    err = mutex_lock(&shared->open_mutex, deadline, NULL);
    /* After a timeout, check whether the safelock is broken */
    if (err == ETIMEDOUT) {
        safelock_status_t status;
        /* Check the lock status after a timeout.
         * ENOTRECOVERABLE: Caller must remove lock
         * EINVAL: Caller must re-open lock */
        err = safelock_fetch_status(lock, &status);
        if (err == ENOTRECOVERABLE || err == EINVAL)
            return err;

        return ETIMEDOUT;
    }

    if (err)
        return err;

    err = data_mutex_lock(lock, NULL);
    if (err) {
        NOFAIL(pthread_mutex_unlock(&shared->open_mutex));
        return err;
    }

    /* By definition, owner_mutex must be free since we have
     * acquired the open_mutex. owner_mutex is always released before
     * open_mutex. */
    err = mutex_lock(&shared->owner_mutex, SAFELOCK_LOCK_TRY, NULL);
    if (err) {
        NOFAIL(pthread_mutex_unlock(&shared->open_mutex));
        /* Failure to obtain the owner_mutex indicates the safelock
         * is unusable or a bug:
         * - corrupted owner_mutex
         * - another process has incorrectly locked owner_mutex */
        return ENOTRECOVERABLE;
    }

    shared->pid = getpid();
    shared->taken = gettimeofday_us();
    shared->data = data;
    shared->data_valid = 1;

    NOFAIL(pthread_mutex_unlock(&shared->data_mutex));

    lock->locked = 1;

    return 0;
}

/* Open/create and then lock a safelock */
int safelock_lock_file(safelock_t *lock, const char *filename,
                       mode_t mode, uint64_t timeout, int data)
{
    int err;

    err = safelock_open(lock, filename, mode);
    if (err)
        return err;

    err = safelock_lock(*lock, timeout, data);
    if (err)
        safelock_close(lock);

    return err;
}

/* Create and open a safelock with a unique filename */
int safelock_open_unique(safelock_t *lock, const char *file_prefix,
                         mode_t mode)
{
    char *lockfile;
    int err;

    lockfile = safelock_create_unique(file_prefix, mode);
    if (!lockfile)
        return errno;

    err = safelock_open(lock, lockfile, 0);

    free(lockfile);

    return err;
}

/* Create and lock a new unique safelock */
int safelock_lock_unique_file(safelock_t *lock, const char *file_prefix,
                              mode_t mode, int data)
{
    int err;

    err = safelock_open_unique(lock, file_prefix, mode);
    if (err)
        return err;

    err = safelock_lock(*lock, SAFELOCK_LOCK_TRY, data);
    if (err) {
        safelock_remove(*lock);
        safelock_close(lock);
    }

    return err;
}

/* Return the filename for an open Safelock.
 *
 * The string will exist until safelock_close() is called. */
char *safelock_filename(safelock_t lock)
{
    return lock->filename;
}

/* Atomically update the Safelock custom data */
int safelock_update_data(safelock_t lock, int data)
{
    int err;

    assert(lock);
    assert(lock->shared);

    /* Only allow the current owner to update the lock data. This helps
     * to guarantee that the lock data is consistent unless both
     * data_mutex and owner_mutex report EOWNERDEAD. */
    if (!lock->locked)
        return EPERM;

    err = data_mutex_lock(lock, NULL);
    if (err)
        return err;

    lock->shared->data = data;

    NOFAIL(pthread_mutex_unlock(&lock->shared->data_mutex));

    return 0;
}

/* Unlock a Safelock.
 *
 * Called with open_mutex and owner_mutex, locked */
int safelock_unlock(safelock_t lock)
{
    lock_data_t *shared;
    int err;

    assert(lock);

    if (!lock->locked)
        return EPERM;

    /* Pre-emptively mark as unlocked before returning to caller */
    lock->locked = 0;

    shared = lock->shared;

    err = data_mutex_lock(lock, NULL);
    if (err) {
        /* Attempt to release the open_mutex to give another thread
         * a chance to notice the safelock is broken. */
        pthread_mutex_unlock(&shared->open_mutex);
        return err;
    }

    /* Release the owner_mutex */
    err = pthread_mutex_unlock(&shared->owner_mutex);
    if (err) {
        NOFAIL(pthread_mutex_unlock(&shared->data_mutex));
        /* We are the current owner of the safelock, but the
         * owner mutex is broken. Remove the safelock and allow other
         * threads to try again */
        err = safelock_remove(lock);
        err |= pthread_mutex_unlock(&shared->open_mutex);
        /* Return EINVAL on success, and ENOTRECOVERABLE if the cleanup
         * failed */
        return !err ? EINVAL : ENOTRECOVERABLE;
    }

    /* Reset "taken" since the lock has been closed cleanly */
    shared->taken = 0;

    /* Release data_mutex. safelock_fetch_status() allowed. */
    NOFAIL(pthread_mutex_unlock(&shared->data_mutex));

    /* Release open_mutex. safelock_lock() allowed. */
    err = pthread_mutex_unlock(&shared->open_mutex);
    if (err) {
        err = safelock_remove(lock);
        return !err ? EINVAL : ENOTRECOVERABLE;
    }

    return 0;
}

/* Returns the current status of the lock in *inuse.
 *
 * Checks if there are recent lock owner(s) of the data_mutex and
 * owner_mutex lock that have crashed. In this case there is a chance
 * the Safelock data was being updated and cannot be trusted.
 *
 * May return EINVAL if the lock is corrupted. */
static int owner_mutex_in_use(safelock_t lock, int data_mutex_dirty,
                              int *inuse)
{
    lock_data_t *shared;
    int dirty;
    int err;

    assert(lock);
    assert(lock->shared);
    assert(inuse);

    shared = lock->shared;

    err = mutex_lock(&shared->owner_mutex, SAFELOCK_LOCK_TRY, &dirty);
    if (err == EBUSY || err == EDEADLK) {
        /* EBUSY: Someone else has the lock
         * EDEADLK: We have the lock */
        *inuse = 1;
        return 0;
    }

    if (err)
        return err;

    /* The previous owner may have died holding both data_mutex and the
     * owner_mutex while locking or updating the safelock. Hence the data
     * protected by the data_mutex may have been corrupted. Tag safelock
     * data as undefined to ensure it is not trusted. */
    if (data_mutex_dirty && dirty)
        shared->data_valid = 0;

    /* Lock was not in use */
    NOFAIL(pthread_mutex_unlock(&shared->owner_mutex));

    *inuse = 0;
    return 0;
}

/* Remove a safelock lock file.
 *
 * Use the "removed" flag to ensure only the first attempt removes
 * the actual file.
 *
 * Any further attempts to use the safelock will return EINVAL
 * indicating the safelock needs to be re-opened.
 *
 * Note: This doesn't inform the current owner that the lock
 * has been invalidated.
 */
int safelock_remove(safelock_t lock)
{
    int ret, err;

    assert(lock && lock->shared);

    err = data_mutex_lock(lock, NULL);
    if (err == EINVAL)
        return 0;   /* Already removed by another thread */
    if (err)
        return err;

    /* Attempt to remove the safelock first. If unlink fails,
     * the safelock won't be tagged as "removed". */
    ret = unlink(lock->filename);
    if (ret < 0) {
        err = errno;
    } else {
        lock->shared->removed = 1;
        err = 0;
    }

    NOFAIL(pthread_mutex_unlock(&lock->shared->data_mutex));

    return err;
}

/* Atomically fetch the status from an open Safelock */
int safelock_fetch_status(safelock_t lock, safelock_status_t *status)
{
    lock_data_t *shared;
    int pid_alive, err;
    int lock_in_use = 0;
    int data_mutex_dirty;

    assert(lock);
    assert(status);

    shared = lock->shared;

    err = data_mutex_lock(lock, &data_mutex_dirty);
    if (err)
        return err;

    pid_alive = pid_exists(shared->pid);

    err = owner_mutex_in_use(lock, data_mutex_dirty, &lock_in_use);
    if (err) {
        NOFAIL(pthread_mutex_unlock(&shared->data_mutex));
        return err;
    }

    /* Check whether the safelock has been left in a "locked" state
     * (lock in use, but PID doesn't exist). Eg, the robust mutex
     * didn't get cleaned up after a power loss or OS crash.
     *
     * The PID check above must be done before the lock check to ensure
     * there is no false positive when a lock holder dies between the
     * checks.
     *
     * Note, this check is not perfect. A new process may have been
     * created with the same PID. In this situtation the lock will still
     * appear to be in use.
     *
     * The best way to avoid these issues is to remove any lock files
     * after a system crash or power failure. Putting lock files on a
     * TMPFS filesystem is one option. */
    if (!pid_alive && lock_in_use) {
        NOFAIL(pthread_mutex_unlock(&shared->data_mutex));
        err = safelock_remove(lock);
        /* Return EINVAL if the Safelock has been successfully removed
         * by this (or another) thread. Otherwise advise the caller
         * that the lock must be manually fixed */
        return !err ? EINVAL : ENOTRECOVERABLE;
    }

    status->locked = lock_in_use;
    /* safelock_unlock() zero's shared->taken to indicate the lock
     * has been cleanly unlocked. */
    status->crashed = !lock_in_use && shared->taken;
    /* The pid, age and data fields are only valid when:
     * - A safelock owner hasn't crashed holding the data mutex
     * - The safelock has been used at least once */
    status->data_valid = shared->data_valid;
    status->pid = shared->pid;
    status->data = shared->data;
    if (lock_in_use) {
        uint64_t now = gettimeofday_us();
        /* Set to 1 if time went backwards */
        status->age = (now > shared->taken)
                      ? now - shared->taken
                      : 1;
    } else {
        status->age = 0;
    }

    NOFAIL(pthread_mutex_unlock(&shared->data_mutex));

    return 0;
}

/* Atomically fetch the status for a Safelock on disk */
int safelock_fetch_file_status(const char *filename,
                               safelock_status_t *status)
{
    safelock_t lock;
    int ret;
    int err;

    assert(filename);
    assert(status);

    /* Does the lock file exist? */
    ret = access(filename, F_OK);
    if (ret < 0) {
        /* Return !locked if it doesn't exist */
        if (errno == ENOENT) {
            /* locked = 0, crashed = 0, data_valid = 0 */
            memset(status, 0, sizeof(*status));
            return 0;
        }
        /* Return an error if the access() check failed */
        return errno;
    }

    /* Lockfile exists, check lock status */

    err = safelock_open(&lock, filename, 0);
    if (err)
        return err;

    err = safelock_fetch_status(lock, status);

    safelock_close(&lock);

    return err;
}

/* vi:ai et sw=4 ts=4:
 */
