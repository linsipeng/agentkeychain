# Separate installed continuation pilot gate (no runtime transport)

The normal package, CLI, release workflow, and installer do not contain a caller
for the pilot entrypoint. Local operators may separately compile an inert
`agentkeychain-continuation-pilot` executable. It is a gate/rehearsal artifact,
not a usable enrollment client, helper installer, or release candidate.

```sh
bun scripts/build-continuation-pilot.ts \
  --artifact /absolute/path/to/signed-pilot-artifact.json \
  --root-public-key /absolute/path/to/pilot-root.pub \
  --outfile /new/private/output/agentkeychain-continuation-pilot
/absolute/path/to/new/private/output/agentkeychain-continuation-pilot check-installation
```

Operator input is limited to public material supplied at build: a distinct
offline public root and an object with the signed `manifest`,
`authOriginAppendix`, `authAppendix`, `commitAppendix`, `rolloutAppendix`,
and `installation`. Use the usual signed-operation envelope for each.
The new installation claim is independently signed with the pilot root and
bound to exact canonical JSON in this order:

```text
version, domain, mode, contract, target, manifestDigest, authOriginDigest,
authPinDigest, mainPinDigest, rolloutPinDigest, genesisPin, issuedAt, expiresAt
```

- Version 1, domain `AgentKeychain-continuation-installed-pilot-build-v1`,
  mode `disposable-only`, contract `continuation-https-pilot-v1`, exact
  host platform/architecture (e.g. `linux-x64`). Time window ≤7 days. Each
  named artifact digest hashes the JSON array of its canonical and signature
  strings; the new claim also pins the separate Auth genesis key as
  `{keyId,publicKey}` (ordered as written).
- Exact HTTPS origins use `web-pilot-<name>.<approved-zone>`,
  `api.web-pilot-<name>.<approved-zone>`,
  and `auth-pilot-<name>.<approved-zone>` excluding the repository's
  current Web namespace and any current role or root key. Pin reuse across
  current/pilot roles rejects by key ID or public key. Signed names do not
  prove zone/account ownership; that needs independent operator verification.
- The gate revalidates embedded material at invocation; runtime arguments,
  environment and files cannot replace it. No output file is published before
  checks and successful compilation; an existing path is never overwritten.
  No standard install name, release wiring, test-mode behavior, vault,
  secure-store, native helper, browser launch or HTTPS call is enabled.
- `check-installation` reports `transport_unavailable` even with valid signed
  artifacts. This avoids claiming real readiness based on signatures alone.
  The isolated Auth entrypoint and narrow Main post-proof route do not yet
  cover the enrolled client lifecycle. Enabling a future command still
  requires the independently owned Auth onboarding/session and approval
  ceremony, exact authenticated Main precommit/commit reconciliation + private
  Custody pre/post checks, genuine pilot secure-store/lease integration and
  full compiled response-loss/revocation acceptance. Runtime operators must
  validate those services against the same pinned graph before using it.

## Installed narrow transport adapter

A verified installation now creates a private branded transport scope. It cannot
be reconstructed from the public `check-installation` output. The compiled
command constructs that adapter but still does not invoke any operation.

- Auth prepare and poll use only the exact signed Auth origin and existing
  typed paths. Existing protected state helpers build and verify the
  device-signed request and the Auth approval. The adapter supplies only a
  credential-free HTTPS POST, no redirected or cross-origin response, and no
  browser cookies, access token, or pair code in the request. Preparation
  requires an explicit exact-stage pre-publish authorizer from composition.
- The Main adapter exposes only the post-commit proof query, against the
  signed Main origin and shared canonical wire. It requires exact protected
  staged evidence under the existing local enrollment lease plus a currently
  issued short-lived, original-device session from the caller. It locally
  checks the device's request signature and independently checks the exact
  nonce-bound returned Custody proof against retained staged evidence before
  returning. It does not store the session, log its contents, kick off sync,
  provision a session, or activate a profile.

These ports do not enable a continuation command. Independently provisioned
short-lived permit, compatible shared enrollment writers, pilot-only secure
state and session acquisition, authenticated published Main preflight and
commit-or-read, and complete enrolled-client acceptance are still required.

## Explicit invocation after independent approval

The installed adapter additionally composes the exact Main `preflight`,
`commit-or-read`, and `post-commit-proof` ports for the approved original
package stage. The composition is finite, requires a short-lived original
device session, carries no Auth cookie or device private key, and independently
checks the Main and Custody signatures. The additive scope permit is signed
by the installation's distinct rollout pin over exact canonical JSON in
this order:

```text
version, domain, keyId, installationDigest, intentDigest, approvalDigest, issuedAt, expiresAt
```

Version 1, domain `AgentKeychain-installed-continuation-pilot-commit-v1`.
The install and approval digests hash the JSON pair of canonical bytes and
signature; intent hashes canonical bytes. The permit is positive for at most
300 seconds, expires no later than the signed installation, and cannot renew
the Auth approval or Custody proof. Under the lease the CLI-side composition
retains one original nonce and exact independently verified preflight
evidence before entering Main's atomic commit. A lost response retries the
same exact body with a newly signed request-envelope nonce; no new package or
grant is created. Expired or revoked evidence refuses rather than replaying
after the permitted window. The only positive result from this adapter is
`commit-verified-not-active`; it neither writes the active profile nor
starts sync.

This path is exercised in an isolated in-memory secure store and a new local
SQLite database, with independently signed typed fixture responses; the
separate compiled binary still only checks installation. To surface an
installed operational command, first bind a signed installation to a newly
provisioned same-owner private directory and verify real path + inode/no
symlink (never inherit HOME or AGENTKEYCHAIN_HOME for the pilot). Derive a
distinct pilot-only native secret namespace from that installation + directory,
allow it in a separately compiled, reviewed macOS helper, and provision an
isolated Linux secret collection. Ensure the normal CLI resolves neither
namespace, and that pilot setup establishes exact original approved enrollment
there without copying normal vault credentials. Session acquisition must
target the same signed pilot origin and only the original protected device.
Until acceptance of that native base and an actual hosted transport rehearsal,
normal and standalone CLI dispatch remain closed.

## Linux empty-directory inspection (not a native storage capability)

The pilot now has a local-only inspection gate for a newly created Linux
directory. An installation's distinct rollout pin signs canonical JSON fields
in this order, domain `AgentKeychain-installed-continuation-pilot-location-v1`:

```text
version, domain, keyId, installationDigest, path, uid, device, inode, issuedAt, expiresAt
```

Version 1. The exact normalized absolute path ends in
`agentkeychain-pilot-<name>`, never contains an ordinary `.agentkeychain`
component, and identifies an owner-only 0700 directory. Device and inode
are decimals from `stat` of that exact directory; UID must match the current
non-root effective and real UID. Grant lifetime is at most 24 hours and
cannot outlast the verified installation. Only root- or caller-owned
ancestors are accepted, and other-writable ancestors must be root-owned
and sticky. Home and vault environment variables are not consulted.
Checks include canonical real path, final directory `O_NOFOLLOW`, repeated
stat comparison and empty directory listing through `/proc/self/fd`.
No path, directory, file or native credential is created or modified.
MacOS and systems without the needed Unix primitives deny in this gate.

Inspection derives a separate `agentkeychain.pilot.<sha256>` namespace
from the installation and exact directory identity. The macOS helper
currently allows only ordinary `agentkeychain.vault` and
`agentkeychain.cloud.*` services, so it cannot read, write or clear this
namespace. The existing Linux Secret Service wrapper selects by service
attributes and does not isolate the secret collection. Neither is wired or
changed here. The returned namespace describes membership, not permission
to call a native backend. A real installation still needs a separately
reviewed pilot helper/collection, descriptor-relative profile/lock opening
and revalidation (including safe SQLite sidecars), pilot initialization and
session acquisition. The check assumes the local UID/kernel are trusted;
it is not isolation from an adversarial process already running as the same
UID. Normal and standalone CLI dispatch remain closed.

### Why the current Bun Linux runtime stays closed

The OS can create a new 0600 fixture child through the verified directory FD
with `O_CREAT|O_EXCL|O_NOFOLLOW` and reject an existing hardlink or symlink.
The application's Bun 1.4.5 SQLite runtime cannot safely take over that child:
`SQLITE_OPEN_NOFOLLOW` rejects `/proc/self/fd/<dirfd>/profile.sqlite` as
`SQLITE_CANTOPEN_SYMLINK` (1550), because the FD bridge itself is a symbolic
link. There is no supported SQLite-by-FD constructor here. Do not remove the
flag, reopen a different path, enable normal Vault resolution, or store a CSK,
VDK, device key or session in a filesystem workaround. The regression uses
only an empty private file in a test temporary directory.

**Next prerequisite:** choose a disposable Linux account with its own audited
Secret Service collection and normal-vault access absent. Provision that
collection through a dedicated native pilot adapter: pin the actual service
peer/collection identity and signed installation namespace, enforce exact
allowed account slots and never fall back to a default collection or ambient
normal CLI. Separately use a reviewed native SQLite VFS/adapter grounded in a
verified directory FD (for database, lock and sidecars), prove symlink and
hardlink refusal and interruption/restart under that disposable account, then
bind it to the same signed pilot location and exact original-device session.
In-memory enrollment fixtures remain test-only and cannot clear either gate.
No persistent pilot profile, fallback seal, or OS secret access is enabled.

## Offline transfer fixture (PR only)

The disposable AMD64/ARM64 Ubuntu fixture builds the actual standalone pilot
binary with one-run synthetic trust, signs a separate exact-target package
descriptor, copies the binary from an offline fixture directory to a fresh
owner-only alternate install directory, and then invokes the transferred
binary after deleting the source and public build inputs. The test-only
admission utility reads through no-follow descriptors, limits the copy and
checks the signed byte count and SHA-256 before no-overwrite publication; it
does not unpack archives. Wrong signer, stale claim, wrong architecture,
wrong hash, changed bytes, symlink input, or occupied destination deny.

The installed command still reports `transport_unavailable`. Neither
environment overrides nor the ordinary synthetic Vault marker allow login,
continuation or native dispatch. No ordinary install directory is modified.
The fixture assumes a single owner on a disposable runner and does not establish
publisher identity, provide a distributor/installer, touch native stores,
or enable runtime transport. No changes to normal installer, build/release, or
CLI code.
