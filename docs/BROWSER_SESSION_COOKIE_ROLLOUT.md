# Managed Cloud browser cookie separation

The console now separates the signed-in, provisional sign-in/registration and restricted-recovery cookie namespaces. Each browser route accepts only its own pair; a stale provisional response cannot replace the authenticated or restricted pairs. Existing authenticated cookies keep the same names and validity rules. Signed-out `/session` may report `authenticated: false` with a valid provisional context; an invalid authenticated cookie never falls back to another credential.

## Rollout and rollback

Ship the API Worker and its bundled web assets together. The updated browser uses `/v1/auth/bootstrap/v2`: an old Worker rejects this path instead of overwriting a valid auth cookie. The legacy bootstrap path on the updated Worker emits **only** the provisional pair; a pre-update browser page must reload before starting or resuming sign-in, signup, or restricted recovery. Already issued legacy provisional and restricted cookies in the old shared names are intentionally not upgraded or accepted; only those in-flight flows must restart. Preserve signed-in sessions, do not ask working sessions to sign out. Do not dual-write any provisional token to the auth-cookie namespace. Old Workers still have the original behavior; an API rollback to one requires treating old tabs as affected again. Never roll back just static assets.

This eliminates cross-scope cookie replacement, not all concurrency. Concurrent provisional flows can still invalidate one another. Expiry and request binding still apply; restart only the failed provisional flow, without signing out an existing session. This is not evidence of the exact historical staging 401 cause, and does not change Passkey, CSRF, rate-limit or account authorization requirements.
