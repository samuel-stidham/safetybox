# Roadmap

Work planned for after 2.0.0. The 2.0.0 review left several items open.
The low-priority ones are now done: rekey streams its envelopes, every
secret reader wipes the buffers it outgrows, including the interactive
prompt and the identity loader, the vault methods take a caller
context, and the minor comment and warning notes are resolved. The
size bound those items also proposed was judged unnecessary for a
single-user CLI and deliberately dropped, so the reads stay unbounded.
One item remains, the one with real security weight.

## Authenticated vault metadata

Priority: high. Touches the on-disk format.

The 2.0.0 release added a recipient check. Every read verb compares the
vault's stored recipient to the loaded identity and refuses on a
mismatch. A swapped recipient is caught on the next read. The check does
not reach the rest of the metadata. An attacker with write access to the
vault can still alter `env_name`, `expires_at`, or a version's state,
and nothing detects it.

The fix is an authenticated structure over the metadata, so any
tampering fails a check on read. That changes the on-disk format, so it
needs a format bump and a migration. This is the one deferred item with
real security weight. It belongs in its own release.
