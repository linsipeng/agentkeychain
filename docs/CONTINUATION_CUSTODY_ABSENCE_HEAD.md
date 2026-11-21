# Custody head proof for package-absence observation (inert)

This module is not imported by deployed workers. It authorizes no write. It does not
observe Main's package table and does not prove absence. Its only positive output
is a short-lived proof that the original independently admitted first-device roster
is still Custody's exact active genesis head with no known independent veto.

The caller needs the original canonical expired grant, exact signed roster,
the historical initial Auth GenesisApproval, and original-device possession.
The caller supplies a fresh 32-byte base64url round nonce, and authenticates
it and the exact grant/request/roster scope using the request-specific domain.
Neither caller-supplied evidence nor a Main assertion establishes original grant
scope: the Custody primary must have the matching append-only admission joined to
the exact sequence-0 witness. Admission's immutable attempt digest commits all of
the original Auth proof, grant, roster, and checkpoint. Historical verification
checks that exact consumed approval without renewing it. A missing or unverifiable
historical proof, absent admission, or unavailable recognized historical Auth pin
fails closed. This does not bootstrap legacy grants whose initial admission was
never recorded. The test-only Auth Genesis receipt readback does not currently
provide a supported replay path for already expired legacy grants; the signed
historical bytes would have to be retained or supplied by a separately reviewed
read-only authority integration. Do not retroactively synthesize them.

The read directly queries Custody's primary before and after signature. It rejects
successor witnesses, immutable recovery revocation, an operator device veto
(or inconsistent signing key or expired operator record), and an operator
account veto or expired record. Missing optional operator rows are not
affirmative authorization: that is provided by the exact independently admitted
single-active-device roster. An observation is capped by the round nonce window
(30 seconds), roster, and any earlier-expiring current operator record. It
identifies the exact historic witness by hash of canonical bytes and signature.
The pinned current signer must differ from the historic witness, original device
keys, original Auth, checkpoint, recovery, and other release keys. The caller
must derive these roles from its verified release policy rather than a response.

No nonce ledger is written. A verifier must use only its locally initiated fresh
nonce, pair this response with an independent Main absence attestation, and
never treat either as activation, a new grant, reapproval, or proof of future
current state. A racing update can occur after the last read; any future write
requires independent fresh approval and atomic still-allowed validation.
No live keys, deployments, routes, migrations, or data changes are included.
