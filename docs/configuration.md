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

Resolution is flag first, then environment, then the XDG default.

```sh
safetybox --vault /path/vault.db --identity /path/identity.age list
SAFETYBOX_VAULT=/path/vault.db safetybox list
```

Environment variables are fine for paths. Passphrases and secret
values never come from the environment or from arguments.

## Global flags

`--vault` and `--identity` override the paths above. They apply to
every verb.

`--passphrase-file` reads the identity passphrase from a file instead
of prompting. Use it for scripts and automation. The file should be
0600 and outside version control. One trailing newline is trimmed.

`--json` switches output from pretty JSON to compact single-line
JSON for pipes.

```sh
safetybox reveal api/stripe/live --json | jq -r .value
```

`-v` enables debug logging and `--log-json` switches log lines to
JSON. Logs go to stderr and never contain secret material.

## Output conventions

Results go to stdout as JSON. Prompts, warnings, and human guidance
go to stderr. That split keeps pipes clean. An expired secret prints
a warning on stderr and still resolves on stdout.

Exit codes are 0 on success and 1 on any error. exec is the
exception. It propagates the child's exit code so wrappers behave
like the wrapped command. A child killed by a signal exits 128 plus
the signal number, so a wrapper reads the death the way a shell
would.
