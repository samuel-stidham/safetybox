# Roadmap

Work planned for after 2.0.0. The 2.0.0 review left several items open.
The low-priority ones are now done: rekey streams its envelopes, the
secret and passphrase readers and the envelope decrypt drain wipe the
buffers they outgrow, the vault methods take a caller context, and the
minor comment and warning notes are resolved. The size bound those
items also proposed was judged unnecessary for a single-user CLI and
deliberately dropped, so the reads stay unbounded. Two reader gaps
remain below, along with the one item that has real security weight.

## Wipe the remaining unhardened readers

Priority: low.

The interactive prompt reads through `term.ReadPassword`, which grows
its line buffer without wiping, so a typed passphrase can leave
unzeroed prefixes inside the library's abandoned buffers. The identity
loader drains its decrypted key file through `io.ReadAll`. Today the
identity plaintext sits under the reader's 512-byte initial capacity,
so nothing reallocates. The loader should move to
`secret.ReadAllWiping` so a larger future format cannot regress, and
the prompt needs a small no-echo reader that wipes as it grows.

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
