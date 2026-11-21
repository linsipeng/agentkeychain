#!/bin/bash
# Read only user-domain configuration, never items. Emit only SHA-256, not
# configured file paths. A failed query invalidates the observation.
set -euo pipefail
export LC_ALL=C
[[ "$(/usr/bin/uname -s)" == Darwin && "${GITHUB_ACTIONS:-}" == true &&
   "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || exit 1
{
  printf 'akc-explicit-darwin-user-config-v1\0default\0'
  /usr/bin/security default-keychain -d user 2>/dev/null || exit 1
  printf '\0search-list\0'
  /usr/bin/security list-keychains -d user 2>/dev/null || exit 1
  printf '\0'
} | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
