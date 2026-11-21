# Native kernel peer check (synthetic, not installed)

Build with `cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 tests/native/pilot_broker_unix_peer.c -o "$out/peer"`
and run as an ordinary non-root account on disposable Linux/macOS runners.
No dependency install, user keys, security settings or TCP involved.
A runner that denies AF_UNIX creation/bind reports exit 77 (unverified),
never a successful runtime test. A cross-compile is not runtime evidence.

Listener creates an exact mode-0600 socket in its fresh mode-0700 directory.
The two child clients each create their own socket after fork. Both verify
the exact live parent PID and effective UID/GID from kernel peer data. The
listener checks an independently spawned same-account but wrong PID and
closes it without reading or responding. Only the expected child may reach
a one-byte request/response after mutual checks. This intentionally does
not test inherited socketpair peer credentials or consider pathname, mode,
or account match an authorization decision. Each child has bounded waits;
only test-created resources are used.

Linux uses [SO_PEERCRED](https://www.man7.org/linux/man-pages/man7/unix.7.html).
Darwin uses [LOCAL_PEERPID](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h)
and getpeereid; [XNU records a peer socket PID](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c),
not a notarized application or verified executable image. This test knows
the processes individually since it spawned both fixture children and
retains them through the handshake. Kernel PID/UID/GID alone does not
authenticate a stable signing identity, prevent exec/FD transfer, or
exclude other same-UID writers. The test does not pass any FD over the
connection. Production requires independent exact process-image and spawn
provenance, lifetime binding that cannot be confused by PID reuse, the
reviewed per-run signed protocol and broker permissions. No runtime
dispatch, persistence, real credential or activation is added.
