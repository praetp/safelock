#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#include "safelock.h"

#define TRY(x) do {             \
    int err;                    \
    msg(#x);                    \
    err = (x);                  \
    die_if(err, #x " failed");  \
} while(0)

const char *boolstr(int val)
{
    return val ? "yes" : "no";
}

void status(int argc, char **argv)
{
    safelock_status_t status;
    int err, i;

    for (i = 1; i < argc; i++ ) {
        err = safelock_fetch_file_status(argv[i], &status);
        if (err)
            safelock_die(err, "Unable to fetch status: %s", argv[i]);

        printf("%s: locked = %s, crashed = %s", argv[i],
               boolstr(status.locked), boolstr(status.crashed));
        if (status.data_valid)
            printf(", PID = %ld, age = %ld, data = %d",
                   (long)status.pid, (long)status.age, status.data);
        printf("\n");
    }
}

void msg(const char *str)
{
    static pid_t pid = 0;

    if (!pid)
        pid = getpid();

    printf("%ld: %s..\n", (long)pid, str);
}

void die_if(int err, const char *msg)
{
    if (err)
        safelock_die(err, "%ld: %s", (long)getpid(), msg);
}

/* usage: safelock-example [LOCKFILE..] */
int main(int argc, char **argv)
{
    const char *lockfile_unique = "lock.dat.";
    const char *lockfile = "lock.dat";
    safelock_t lock_unique, lock;
    int serial;

    if (argc > 1) {
        status(argc, argv);
        return 0;
    }

    /* Arbitrary "serial" */
    serial = getpid() + 100000;

    TRY(safelock_lock_unique_file(&lock_unique, lockfile_unique, 0666, serial));

    TRY(safelock_open(&lock, lockfile, 0666));
    TRY(safelock_lock(lock, 5e6, serial));

    msg("sleep(5)");
    sleep(5);

    TRY(safelock_update_data(lock, serial + 100000));

    /* kill(getpid(), SIGKILL); */

    TRY(safelock_unlock(lock));
    TRY(safelock_close(&lock));

    TRY(safelock_remove(lock_unique));
    TRY(safelock_close(&lock_unique));

	return 0;
}

/* vi:ai et sw=4 ts=4:
 */
