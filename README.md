# ![SafetyBox](docs/assets/safetybox-lockup.svg)

SafetyBox is a single-user, CLI-first secrets manager for *nix. It keeps
named, versioned secrets in a SQLite vault. Every value is sealed in an
[age](https://age-encryption.org) envelope before it touches disk. There
is no server, no GUI, and no unencrypted storage.

## Status

safetybox is in early development. Every verb works end to end: init,
set, get, reveal, show, list, stale, disable, delete, purge, exec,
passwd, and rekey. The format may still change before 1.0, so keep
backups and do not make it your only copy of anything yet.

## How it works

The vault stores your public key, called the recipient. Writing a secret
only needs that public key. Reading one needs your private identity,
which lives in a passphrase-encrypted file outside the vault. This split
means write operations never touch key material.

Secrets are versioned. Updates append a new version instead of replacing
the old one, so rotation has an overlap window by design. An expiry date
marks a secret stale but never deletes it.

Each envelope is bound to its row in the vault. The plaintext carries its
own address, and decryption fails if the ciphertext was moved or swapped.

## Install

Build from source with Go 1.26 or later.

```sh
git clone https://github.com/samuel-stidham/safetybox.git
cd safetybox
make build
```

The binary lands in `bin/safetybox`. To install it on your PATH, run
`make install` instead. That places the binary in `$GOPATH/bin`, which
is `~/go/bin` by default. Prebuilt binaries for Linux and macOS ship
with each GitHub release.

## Getting started

Create your identity and vault.

```sh
safetybox init
```

init generates an X25519 identity, encrypts it with a passphrase you
choose, and creates the vault. It prints your recipient and runs a
seal-and-open self-test before reporting success.

Back up the identity file immediately. Without it, every secret in the
vault is unrecoverable. The passphrase alone cannot recover them.

For scripted setups, pass `--passphrase-file` instead of typing at the
prompt. Passphrases are never accepted from arguments or environment
variables.

## Documentation

The full documentation lives in [docs/](docs/).

- [Getting started](docs/getting-started.md) takes you from install to
  your first rotated secret.
- [Command reference](docs/commands.md) covers every verb, flag, and
  output shape.
- [Configuration](docs/configuration.md) covers paths, precedence, and
  the global flags.
- [Security model](docs/security.md) explains the layers, the
  invariants, and the limits.
- [Architecture](docs/architecture.md) explains the packages, the data
  model, and the address binding.
- [Development](docs/development.md) covers building, testing, and the
  release pipeline.
- [Linting policy](docs/linting.md) records every linter exception and
  its justification.

## Configuration

The vault lives at `$XDG_DATA_HOME/safetybox/vault.db`. The identity
lives at `$XDG_CONFIG_HOME/safetybox/identity.age`. Both paths can be
overridden. A flag beats an environment variable, and both beat the
default. The [configuration guide](docs/configuration.md) has the
details.

```sh
safetybox --vault /path/to/vault.db --identity /path/to/identity.age ...
```

The environment variables are `SAFETYBOX_VAULT` and `SAFETYBOX_IDENTITY`.
They are fine for paths. Secret values and passphrases never go through
the environment.

## Security model

Plaintext secret bytes live in one Go type, in one package, and leave it
through one method. Formatting, JSON encoding, and logging all render
`[REDACTED]` instead of the value. reveal is the single verb that prints
plaintext, deliberately and only when you ask for it. Everything else
redacts. The vault file is created `0600` and the identity file is
`0600` inside a `0700` directory.

There is no plaintext storage mode and none will be added. The
[security model](docs/security.md) documents the full set of
invariants and what safetybox does not defend against.

## Development

`make help` lists every target. The usual loop is `make dev`,
`make lint`, and `make test`. `make dev` builds a binary into `bin/`
with a `-dev` version suffix, so a test build never masquerades as an
installed one. Linting runs `gofumpt`, `gci`, and
`golangci-lint`, and CI fails if they would change anything. Tests run
against real SQLite and real age keys, with no mocks. The
[development guide](docs/development.md) covers the rest.

## Releases

Commits follow the conventional commit format. CI tags each qualifying
push to `main` automatically. A `feat` commit bumps the minor version
and a `fix` commit bumps the patch. GoReleaser then builds static
binaries and publishes the GitHub release with checksums.

## License

MIT. See `LICENSE`.
