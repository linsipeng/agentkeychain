# Disposable native SQLite filesystem gate, phase 0

`pilot_sqlite_dirfd_gate.c` is a portable POSIX acceptance scaffold. It uses a
synthetic temporary directory, fixed names and actual held file descriptors;
it is **not registered in SQLite** and must not be imported into product code.
SQLite development headers are not needed for this step. On an ordinary
non-root account:

```sh
out=$(mktemp -d)
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 tests/native/pilot_sqlite_dirfd_gate.c -o "$out/gate"
"$out/gate"
status=$?
rm -rf "$out"
exit "$status"
```

The test proves exclusive mode-0600 creation and exact-name open/access/delete
logic for one main file and one rollback journal under a held dirfd. It
rejects symlink/hardlink/special-file/wrong-mode and unsupported names,
including WAL and SHM, and refuses main-file delete by design. The test
demonstrates that the held descriptor cannot silently resolve into a different
replacement directory. The original still exists after rename; the eventual
broker must reject that changed visible identity, not continue under the moved
path. A stat/unlink pair does not atomically refuse inode replacement by an
independent same-directory writer. The broker must enforce one namespace
writer, not claim that these primitives alone exclude unrestricted same-UID
processes. A failed mkdir or I/O path only touches the one generated fixture;
tests accept no arbitrary paths, SQL or flags.

## Next implementation contract, not enabled

1. Use a separate, fixed-purpose native broker. Verify the signed profile
   grant and independently pinned executable; open and hold each verified
   parent with no-follow and the exact private pilot directory. Assert
   dev/inode/owner/type/mode before the next operation or returning success.
   No ordinary vault resolution, ambient location, exposed credential slots
   or caller-supplied SQL/filenames. One broker owner/lease across restarts;
   IPC names explicit pilot operations and replies only after durable commit.
2. Start with a reviewed pinned SQLite and a named VFS for **new** pilot-only
   rollback mode; standard `CloudStore` currently requires WAL and cannot
   use this scaffold unchanged. Map `xFullPathname` to one canonical logical
   database name, `xOpen` to the same fixed-main / fixed-journal capabilities
   (and validate SQLite flags), `xAccess` to no-follow metadata, `xDelete` only
   for the journal and explicitly preserve the sync-directory request. Deny
   any unimplemented flag/op, extension, attachment, temporary on-disk file,
   and all WAL/SHM operations. Never delegate path/locking methods to a VFS
   that independently resolves caller or database-relative path strings.
3. Implement and separately audit real SQLite file I/O, coarse concurrency/
   locking between real broker instances, sync order of journal/database and
   containing directory (plus reviewed macOS durability semantics), recovery
   reopens, and xFileControl/error contracts. Prove via real SQLite CREATE/
   commit/close/reopen, synthetic competing broker and lease checks, process
   interruption at each journal/sync/commit boundary, original/altered
   generation rollback denial, unsupported operations failing closed, and
   explicit checks that no unapproved descriptor/path is touched. Repeat on
   non-root Linux and macOS arm64/x64. Root, unavailable APIs or unverified
   platform semantics do not clear the gate.
4. Integrate native protected slots and original-device session only in a
   subsequent separately authorized design. This scaffold holds markers,
   not passwords, CSK/VDK, credentials, or other vault contents.

References: [SQLite VFS API](https://sqlite.org/c3ref/vfs.html),
[SQLite rollback-mode atomic commit](https://sqlite.org/atomiccommit.html),
[SQLite file open options](https://sqlite.org/c3ref/open.html).

## Phase 1: actual pinned SQLite in read-only mode

`pilot_sqlite_engine_readonly.c` registers a non-default named VFS against the
official SQLite 3.54.1 amalgamation. It must never be linked into a shipped
binary. Build input is [SQLite’s official ZIP](https://sqlite.org/2026/sqlite-amalgamation-3540100.zip);
[the project download page](https://sqlite.org/download.html) gives the ZIP
SHA3-256, and [the release log](https://sqlite.org/releaselog/3_54_1.html) gives
the source SHA3-256 and source ID. Nothing here installs a system package.

- ZIP SHA3-256: `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`.
- Extracted `sqlite3.c` SHA3-256: `e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81`.
- Source ID enforced by the test: `2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76`.

Use verified extracted `sqlite3.c` and matching bundled `sqlite3.h` together
from the same pinned ZIP, not the operating system library or Bun. Example
after verifying hashes, where `src` is the extracted source directory and
`out` is a fresh private writable build directory:

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic -I"$src" \
  -c tests/native/pilot_sqlite_engine_readonly.c -o "$out/fixture.o"
cc -O2 -DSQLITE_OMIT_WAL=1 -DSQLITE_OMIT_LOAD_EXTENSION=1 -DSQLITE_TEMP_STORE=3 \
  -c "$src/sqlite3.c" -o "$out/sqlite.o"
cc "$out/fixture.o" "$out/sqlite.o" -lm -lpthread -o "$out/pilot-sqlite-test"
"$out/pilot-sqlite-test"
```

The ordinary SQLite in-memory connection emits the synthetic database image
only. Seed bytes are created through phase-0's held FD; the actual query
opens and reads them only through the named VFS. It never delegates a path
method to a stock VFS. It allows a single read-only test connection, only
when no journal exists. A journal of any kind, alias, moved directory,
unsupported open mode, or write cannot return usable SQLite data. It does not
establish write or recovery correctness. In particular its fixture locking
and randomness callbacks are not eligible for reuse in a writer: reserved
locks, real exclusion across processes, failure-safe journal create/delete,
fsync, crash replay, production trust wiring, and Darwin execution are still
separate gates.

## Phase 2 dependency: independent operating-system lease

`pilot_sqlite_writer_lease.c` is a separate test-only process fixture. It
checks that a fresh contender cannot acquire an existing, exact-inode lease
while another process holds it, then can claim that same inode after the
owner is killed. It rejects a missing, linked or substituted file instead
of creating or unlinking a lock at startup. Build and run as an ordinary
user on a disposable host:

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 \
  tests/native/pilot_sqlite_writer_lease.c -o "$out/pilot-lease-test"
"$out/pilot-lease-test"
```

This is only a prerequisite for the rollback writer. It does not exercise
any SQLite write, journal, or recovery. The POSIX lock coordinates
cooperating brokers, not arbitrary writers using the same UID.
