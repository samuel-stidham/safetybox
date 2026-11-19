# Configuration

safetybox reads no config file. Two paths and a few flags cover
everything.

## Paths

The vault is a SQLite database at
`$XDG_DATA_HOME/safetybox/vault.db`, which resolves to
`~/.local/share/safetybox/vault.db` when `XDG_DATA_HOME` is unset.
The identity is an age-encrypted file at
`$XDG_CONFIG_HOME/safetybox/identity.age`, which resolves to
`~/.config/safetybox/identity.age`.

The identity file gains siblings over time. rekey keeps the previous
key at `identity.age.bak` and stages the next key at
`identity.age.new` mid-rotation. rekey and passwd share a permanent,
empty `identity.age.lock` file that serializes them. Include the
`.bak` in backups and leave the others alone.

Resolution is flag first, then environment, then the XDG default.

```sh
safetybox --vault /path/vault.db --identity /path/identity.age list
SAFETYBOX_VAULT=/path/vault.db safetybox list
```

Environment variables are fine for paths. Passphrases and secret
values never come from the environment or from arguments.

## Global flags

`--vault` and `--identity` override the paths above. They apply to
every verb. A path from a flag or an environment variable is cleaned
before use, so `a/../b/vault.db` is read as `b/vault.db` and every step
of a verb works on the same spelling.

`--passphrase-file` reads the identity passphrase from a file instead
of prompting. Use it for scripts and automation. The file should be
0600 and outside version control. Trailing newlines are trimmed.

`--json` switches output from pretty JSON to compact single-line
JSON for pipes.

```sh
safetybox reveal api/stripe/live --json | jq -r .value
```

Logs are leveled records on stderr. The default level is Info, and
`-v` or `--verbose` adds debug records tracing vault opens, identity
unlocks, and batch decrypts. Records are styled on a terminal and
plain in a pipe. `--log-json` switches them to single-line JSON for
log shippers, and it holds even when the command line fails to
parse. Logs never contain secret material. A redaction backstop
replaces the value of any attribute whose key names secret-bearing
content with `[REDACTED]`.

## Output conventions

Results go to stdout as JSON. Prompts and log records go to stderr.
That split keeps pipes clean. An expired secret logs a warning on
stderr and still resolves on stdout.

Exit codes are 0 on success and 1 on any error. exec is the
exception. It propagates the child's exit code so wrappers behave
like the wrapped command. A child killed by a signal exits 128 plus
the signal number, so a wrapper reads the death the way a shell
would.
