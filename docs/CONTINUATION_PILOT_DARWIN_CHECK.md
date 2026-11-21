# Separate Darwin installed-candidate location check

This is a native **read-only location check**, not a Keychain item provider or
an enabled client command. The normal package, native helper, installer, CLI
dispatcher, release jobs and Linux storage path are unchanged. The existing
pilot check-installation still fails closed on transport. Neither client ever
executes this helper. The disposable PR workflow type-checks the source with
placeholder public literals; that step does not build a distributable binary,
execute it, issue a grant, or open a keychain. The separate fixture exercise
is not performed by this helper.

## Reviewing the candidate and its trust

Only a freshly disposable GitHub-hosted macOS runner and exact trusted source
may use the test compiler. Run its type/compiled test profile first.
Explicit companion command:

```sh
bun scripts/build-continuation-pilot-darwin-check.ts \
  --artifact /absolute/signed-test-installation.json \
  --root-public-key /absolute/fixture-root.pub \
  --outfile /new-private-output/agentkeychain-continuation-pilot-darwin-check
```

The runner must set the explicit fixture marker
`AKC_DARWIN_NATIVE_CANDIDATE=check-signed-disposable-v1`. Build verifies the
exact architecture/platform and signed installation; it embeds its existing
accepted rollout public pin plus installation digest and expiry. It writes
only a separately named, no-overwrite fixture executable. The fixture compiler
requires Xcode 16.4 at a fixed Developer directory, uses its default toolchain
with a resolved in-bundle SDK, and gives subprocesses a fresh allowlisted
environment. The application
never learns a helper-supplied trust pin or accepts runtime trust overrides.

The signed location grant has a new Darwin-only domain, independent of
the Linux empty-location gate. The matching-version JSON is sorted ASCII
keys, UTF-8 compact JSON without escaped slash. It is signed over the exact
canonical bytes. It binds embedded installation digest/key ID, exact
`/private/tmp/akc-pilot-native-<32 hex>`, signed directory and file
device/inode decimal strings, exact non-root UID and short lifetime (≤15m
and no later than installation expiry). The only file is the fixed
`pilot-primary.keychain-db`; the claim has no selectable file or account.
The namespace is `agentkeychain.pilot.` plus SHA-256 of a compact JSON
array of location domain, installation digest, directory, decimal UID,
directory device and inode (all strings). No old namespace accepted.

A second purpose-separated signed helper appendix binds installation,
approved target and SHA-256 of the examined helper. The pure TypeScript contract checks the supplied digest against the
approved signed appendix and an already verified installation and returns
the canonical signed native input. It neither computes an executable
digest nor verifies code provenance, package identity or anything about
what would execute. There is no installed dispatch. For disposable acceptance, independently verify ad-hoc native
signing/code validity and pinned helper hash in a private immutable
fixture install tree out of reach of other writers; run only the approved
fixture binary there. Distributed integration needs stable signing identity,
an independently approved exact executable provenance path and a verified
binding from the file checked to the file executed; do not add a mutable
hash-then-spawn runtime fallback.

The Swift probe verifies the complete signed bounded input before any
filesystem path resolution or Keychain calls. Then it opens fixed ancestors
and the signed directory by held no-follow directory descriptors; compares
bounded no-follow child metadata with its visible name and signed identity.
Security.framework's SecKeychainOpen receives the exact absolute pathname,
not an FD. The probe checks the held parent and file identity around that
pathname-based API, and requires the exact raw Security.framework path
spelling without expanding aliases. This is not descriptor-bound Keychain
opening or protection against another writer racing pathname resolution.
It rejects default/search-list paths and their aliases without item reads.
Only ENOENT corroborated by lstat (or a terminal symlink still dangling on
a second POSIX canonical lookup) is permitted as an absent configured file;
permission, malformed path and other I/O failures deny. It repeats its
guards and the unlocked/readable status check before returning. No create, unlock, userspace prompts, item IPC, protection changes,
or state writes. On success it returns only
`{"version":1,"state":"scoped-native-location-verified-not-active"}`.

## Proposed hosted fixture gate (manual; not installed)

1. Compile-only CI is safe to review separately: compile/typecheck the
   exact sources with synthetic public trust literals on disposable hosted
   macOS. Do not run any helper, set the runtime enable marker, issue a
   location grant, or create/open a Keychain in compile-only jobs.
   Compile/typecheck exact candidate under both reviewed Darwin CPU
   targets, with synthetic per-run public material; no production private
   key or normal Keychain. Verify its Mach-O architecture and signature and
   issue a short-lived reviewed synthetic helper appendix only after hash
   computation in the isolated private install tree.
2. Provide a fresh exact /private/tmp file fixture from the previously
   approved disposable native create procedure. Sign only the observed
   finalized no-follow directory+file identities. Verify the independent
   default/search-list metadata before and after (including failure). Send
   no vault data, roles, real credential or secret through the helper.
3. Run approved standalone companion with bounded stdin/time, expect only
   versioned success. Wrong/unsigned/stale grants, different helper hash,
   missing or replaced file, same-prefix different directory, alias and
   wrong UID all deny. On failure output fixed category only.
4. Signed inode is intentionally **immutable** for this read-only check.
   Successful Security writes in the disposable harness legitimately
   replaced file identity; that does not justify automatic trust on
   another process start. A future persistent provider requires audited
   synchronization and a signed crash-safe file generation/rotation
   protocol, privacy review of exact allowed secret slots, Linux/Darwin
   native persistence review, and separate SQLite and hosted transport
   gates. Until then this companion cannot unlock activation/sync.
