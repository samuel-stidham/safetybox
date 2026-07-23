# Roadmap

Work planned for after 2.0.0. The 2.0.0 review left several items open.
The low-priority ones are now done: rekey streams its envelopes, every
secret reader wipes the buffers it outgrows, including the interactive
prompt and the identity loader, the vault methods take a caller
context, and the minor comment and warning notes are resolved. The
size bound those items also proposed was judged unnecessary for a
single-user CLI and deliberately dropped, so the reads stay unbounded.
Two items remain. One carries real security weight and needs a format
change. The other is a testing gap left open when the no-echo prompt
shipped.

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

## Terminal behavior test for the passphrase prompt

Priority: low. A testing gap, no security impact.

The interactive passphrase prompt reads through a custom no-echo reader
in `cmd/noecho.go`, rather than `term.ReadPassword`. That reader
disables terminal echo through a termios ioctl, reads the line one byte
at a time into a buffer it wipes as it grows, maps a carriage return to
a newline, and restores the terminal on return. It also restores the
terminal from a signal handler, so a Ctrl-C at the prompt does not
leave the shell with echo disabled.

The tests exercise the reading loop through pipes. They prove the byte
handling, the buffer wiping across its growth boundary, and the
end-of-input behavior. None of them drive the full prompt against a
real terminal. So nothing asserts that echo is actually off while the
line is read, that the carriage-return mapping works, or that the
terminal state returns to its original value after the read and after
an interrupt. A wrong termios flag would echo a passphrase to the
screen, and no test would catch it.

Continuous integration compiles the platform-specific termios
constants, both the Linux build and a macOS cross-build, so a build
break surfaces before a release. The runtime behavior on a real
terminal stays unverified.

The fix is a test that runs the prompt against a pseudo-terminal and
checks three things. The typed bytes never appear on the terminal. The
returned line matches what was typed. The terminal state after the
prompt equals the state before it. This needs a pseudo-terminal helper,
either a small dependency or the `openpty` system calls wired up by
hand. Adding a dependency during a security release was itself review
surface, so the test was deferred to here.
