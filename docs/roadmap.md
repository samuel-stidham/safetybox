# Roadmap

This file is closed. From 3.0.0 on, bugs and security findings are
tracked as [GitHub issues](https://github.com/samuel-stidham/safetybox/issues),
and this file will not be updated again. The sections below stay as a
record of the earlier review items and where they landed.

The 2.0.0 security review left a set of items open. They are all done
now. The low-priority ones shipped across 2.0.x: rekey streams its
envelopes, every secret reader wipes the buffers it outgrows, the vault
methods take a caller context, and the no-echo prompt gained a
pseudo-terminal test. The size bound those items also proposed was
judged unnecessary for a single-user CLI and deliberately dropped, so
the reads stay unbounded.

The one item with real security weight, binding the mutable metadata
into the envelope, shipped in 3.0.0. See the
[security model](security.md) for what it protects and its limits.

## Done in 3.0.0: metadata binding

Every read verb already compared the vault's stored recipient to the
loaded identity and refused on a mismatch. That check did not reach the
rest of the vault, so a write attacker could edit `env_name` or
`expires_at` undetected.

3.0.0 seals the env name and expiry into each version's envelope. A read
returns them and compares them to the plaintext columns, so an edit to a
column without the value is caught. Re-sealing needs the plaintext, so
the write path stays keyless. The limit, documented in the security
model, is that an attacker who re-forges the whole envelope with a
chosen value and matching metadata still passes, and that version state
and deletion are not bound.

## Open

Nothing is tracked here anymore. safetybox is feature complete for its
single-user scope. Future work is security fixes and bug fixes, filed
as GitHub issues and released as patch and minor versions. The final
3.0.0 review rounds left five open issues, #10 through #14, which are
the release freeze gate.
