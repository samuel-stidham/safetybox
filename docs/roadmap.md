# Roadmap

Work planned for after 2.0.0. The 2.0.0 review left several items open.
The low-priority ones are now done: rekey streams its envelopes, every
secret reader wipes the buffers it outgrows, including the interactive
prompt and the identity loader, the vault methods take a caller
context, and the minor comment and warning notes are resolved. The
size bound those items also proposed was judged unnecessary for a
single-user CLI and deliberately dropped, so the reads stay unbounded.
The no-echo prompt now has a pseudo-terminal test, added in 2.0.1. One
item remains, the one with real security weight.

## Authenticated vault contents

Priority: high. Touches the on-disk format.

The 2.0.0 release added a recipient check. Every read verb compares the
vault's stored recipient to the loaded identity and refuses on a
mismatch. A swapped recipient is caught on the next read. The check does
not reach the rest of the vault. An attacker with write access can still
alter `env_name`, `expires_at`, or a version's state, and nothing
detects it.

The same gap covers a secret's value. The recipient is a public key, so
a write attacker can seal a chosen plaintext to it with the correct
address and overwrite a row. The forged value passes the address binding
and the recipient check. Authenticating a value needs a signing secret
at write time, which the asymmetric write model deliberately lacks, so
closing this without giving every producer machine a signing key is the
open design tension.

The fix is an authenticated structure over the metadata and the
value-to-row binding, so any tampering fails a check on read. That
changes the on-disk format, so it needs a format bump and a migration.
This is the one deferred item with real security weight. It belongs in
its own release.
