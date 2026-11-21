# Managed Cloud release packaging

The **Release candidate packaging** workflow checks out the exact pull request
head and produces a GitHub Actions artifact, not a public release. It uses an
ephemeral synthetic signing root and reserved `.invalid` service origins
regardless of the checkout's generated staging manifest. Smoke checks read only
version, compatibility and cloud status in an empty private test directory.
There is no network cloud login, native Keychain lookup or production deploy.

Four native runners package the CLI for Linux/macOS x64 and arm64. On each macOS
runner, Xcode 16.4 also builds the matching secure-store helper; the workflow
checks its architecture and helper ABI/version against the CLI. Assembly rejects
anything other than the four CLI files and two helpers, then produces and verifies
a sorted SHA256SUMS in the installer format. The candidate artifact is synthetic
and **must never be used as a production installer release**.

## Before authorizing a production release

1. Set the intended version in both package.json and src/index.ts. Confirm
   isolated acceptance on the immutable release commit and the two native
   macOS packaging jobs. Native signing/notarization and production deployment
   are separate gates.
2. Independently verify the public release-root fingerprint and exact signed
   production trust policy, including the production API/Web origins and the
   checkpoint, witness, recovery service and recovery authority public pins.
   Configure repository Actions variables `AKC_RELEASE_MANIFEST` (the signed
   JSON), `AKC_RELEASE_ROOT_PUBLIC_KEY` (the canonical base64 public root), and
   `AKC_RELEASE_ID` (the separately approved manifest release ID). Never place
   private roots, private keys or credentials in these variables. There is no
   fallback to the checked-in staging artifact.
3. Configure `managed-cloud-release` with required release reviewers and
   restrict it to the protected version tags. Protect tags against unauthorized
   creation, movement and deletion. These repository controls must be set
   separately; writing an environment name in YAML does not turn on reviewers.
   Set the environment variable `AKC_RELEASE_APPROVED_SHA` to the exact separately
   approved commit; the publish step rejects an unset or mismatched value.
4. Only after separate authorization, push the exact stable version tag
   (`vMAJOR.MINOR.PATCH`) for the verified commit. The workflow checks version,
   signed production policy and downloaded asset checksums before the protected
   publication job. That job checks the remote tag still resolves to the built
   commit and uploads the explicit asset list to the existing tag.
