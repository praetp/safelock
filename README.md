Safelock
========

Safelock is a file-based locking primitive which provides mutual
exclusion between unrelated processes and threads.

Safelock offers advantages over POSIX and BSD file locks such as:

- Compatible with multi-threaded applications
- Support for lock attempt timeouts
- Detection of crashed lock holders
- Detailed lock status (PID, lock age, custom data)

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
safelock_open(&lock, "lock.dat", 0660);
safelock_lock(lock, SAFELOCK_LOCK_WAIT, 42);
...
safelock_unlock(lock);
safelock_close(&lock);
```
