Safelock
========

Safelock is a file-based locking primitive which provides mutual
exclusion between unrelated processes and threads.

Safelock offers advantages over POSIX and BSD file locks such as:

- Compatible with multi-threaded applications
- Support for lock attempt timeouts
- Detection of crashed lock holders
- Detailed lock status (PID, lock age, custom data)

Safelock requires POSIX.1-2008 robust mutexes. Tested under Linux 2.6.32
and Solaris 11.

Review `safelock.h` or http://mpx.github.com/safelock/ for detailed
documentation.

**License:** MIT

_Mark Pulford &lt;mark@kyne.com.au&gt;_

Example
-------

```c
#include "safelock.h"
...
safelock_t lock;
err = safelock_open(&lock, "lock.dat", 0660);
err = safelock_lock(lock, SAFELOCK_LOCK_WAIT, 42);
...
err = safelock_unlock(lock);
err = safelock_close(&lock);
```
