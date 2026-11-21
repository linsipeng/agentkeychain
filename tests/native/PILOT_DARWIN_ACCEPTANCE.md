# Disposable macOS Keychain acceptance

The harness tests only the legacy **file-based macOS Keychain** Security
framework path on the designated disposable GitHub-hosted Darwin runner.
It is not a native helper for installation, not a Data Protection Keychain
or iCloud test, and not evidence of signed namespace/location plumbing.
On Linux, only a source-structure review is possible. Do not run on the
owner's Mac or a self-hosted runner.

1. Review and compile only, without opening any keychain:
   `xcrun swiftc -typecheck tests/native/pilot_darwin_keychain.swift`.
   The hosted macOS candidate workflow does this type-check only. The
   program does not execute in the candidate/release workflow.
2. Before separately authorizing a run, provision two new empty,
   unlocked **file-based** fixture stores in the disposable runner identity,
   without touching ability to use or actually changing its default
   keychain/search list. Use a canonical absolute, owner-only 0700
   directory whose basename is `akc-pilot-native-` plus 32 lowercase hex
   characters, and direct owner-only 0600 single-link files named
   `pilot-primary.keychain-db` and `pilot-sibling.keychain-db`. If no
   reviewed provisioning mechanism can meet that contract, do not
   execute. In particular, don't use `security create-keychain` as a
   substitute: Apple's Security tool advertises adding it to the search
   list. Neither keychain file may be the default or listed, including
   via symlink alias. Make only this disposable runner/session available;
   no ordinary data/device secrets may be present. The parent directory
   must stay under an immutable trusted ancestor throughout the run. A
   path-based inode check alone is not an open-file confinement guarantee.
   Provisioning/unlock
   secrets never go in arguments, job logs, source, or an artifact.
3. Compile a temporary executable and run it with explicit marker
   `AKC_DISPOSABLE_DARWIN_FIXTURE=explicit-two-keychains-v1` and exactly
   one argument (the fixture directory). It checks GitHub-hosted runner
   flags as a guard, not as proof of isolation. It uses `SecKeychainOpen`
   and `SecKeychainGetPath` for both specific file identities,
   `kSecUseKeychain` for each synthetic add, and
   `kSecMatchSearchList=[exactKeychain]` for every read/delete. It
   denies wrong local namespace/slot before item IPC, verifies the same
   new namespace and account remain independent across the two stores,
   and compares read-only before/after default/search-list metadata
   without printing paths. It prints no actual item value or credential.
   Neither fixture store is provisioned, unlocked, or deleted by the
   harness. No normal Keychain helper behavior or build changes.
4. Discard the runner. Do not compensate for setup failure with a
   change to the original or default search list. A future signed,
   runtime-scoped pilot helper requires separate platform acceptance,
   stable helper identity and explicit directory/security scope.

Sources: [Apple TN3137: macOS Keychain API behavior](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains),
[explicit search list key](https://developer.apple.com/documentation/security/ksecmatchsearchlist),
[Apple's Security tool source](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/security.c).

## Direct provisioner in the disposable PR test

Apple's open-source Security implementation distinguishes the direct API
from the CLI. `SecKeychainCreate` calls `StorageManager::make` and then
`KeychainImpl::create`, which notifies `StorageManager::created`. Both list
update paths use `shouldAddToSearchList`: outside App Sandbox it opts in only
the special system or login paths, not an explicitly named private file under
`/private/tmp`. This is implementation evidence, not a cross-version guarantee.
The process independently compares the observed default/search-list metadata
before and after each call, and bails out without attempting to restore
preferences if the installed implementation behaves differently.

The separate Disposable Darwin Keychain acceptance workflow invokes the
reviewed provisioner only on fresh GitHub-hosted macOS 15 runners for the
same-repository takeover PR. It is not invoked by the candidate/release
workflow or the CLI and does not prove compatibility outside those images.
An independently supervised runtime job must take out-of-process metadata
snapshots before and after (including after failure), never expose the paths
in logs, and reject any drift without restoring preferences. It must use a
fresh hosted VM, no imported credentials or certificates, no retained
checkout credentials and no unrelated steps under the same user.
Use a GitHub-hosted runner destroyed after that job; a temporary HOME on an
existing Mac does not isolate its Security session. No system Keychain values
are read: only configuration identity is observed and all item calls use the
two new explicit file objects. A new owner-only child directory is created
inside a fixed canonical root-owned sticky scratch parent, without accepting
environment path overrides. Each fixture uses independent random synthetic
UTF-8 bytes generated and used solely in process memory, noninteractive new
file creation, and an explicit unlock only if the proven new fixture is
locked. If exact path, identity, mode or status does not match, stop; no
normal-store fallback, no preference edits, and no recursive cleanup.

The isolated workflow runs the reviewed, temporary executable as follows:

```sh
AKC_DISPOSABLE_DARWIN_FIXTURE=create-two-private-keychains-v1 \
  "$standalone_harness" --provision-disposable
```

Sources: [SecKeychainCreate public API](https://developer.apple.com/documentation/security/seckeychaincreate%28_%3A_%3A_%3A_%3A_%3A_%3A%29?language=objc),
[Security SecKeychain.cpp](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecKeychain.cpp),
[Keychains.cpp create hook](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/Keychains.cpp),
and [StorageManager.cpp list guards](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/StorageManager.cpp).
