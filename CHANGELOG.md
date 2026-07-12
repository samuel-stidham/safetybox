# Changelog

All notable changes to safetybox are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
versions follow [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-07-12

### Added

- Batch reveal. `reveal` now accepts several names, `--env` for every
  secret with an env name, and `--prefix` for every secret under a
  name prefix. The whole batch decrypts with one passphrase read.
- Shell output for reveal. `--format sh` and `--format fish` emit
  quoted assignment lines ready to source into a session, so shell
  startup and direnv can load secrets in one invocation. Secrets
  without a usable env name are skipped with a warning.
- Single-name reveal output now includes envName when the secret has
  one. The one-object output shape is otherwise unchanged.
- Command documentation in `doc.go`, so pkg.go.dev renders a full
  overview with the verb table and the security model.

### Security

- `reveal --prefix` and `list`/`stale` now match by exact,
  case-sensitive prefix. The previous LIKE match treated `_` and `%`
  in a name as wildcards and folded ASCII case, so a prefix built
  from a name containing `_` could decrypt and print secrets the
  caller never selected.
- `purge` and `rekey` now actually destroy old ciphertext. The vault
  enables SQLite `secure_delete` and checkpoints the write-ahead log
  after each, so erased envelopes and pre-rotation envelopes no
  longer linger in free pages or WAL frames.
- The redaction wall is now total. `secret.Value` implements
  `fmt.Formatter` so numeric verbs like `%d` redact, and holds its
  bytes behind a pointer so a Value in another struct's unexported
  field renders as an address, not plaintext, under fmt reflection.
- The identity write is now crash-safe. `Write` fsyncs the file and
  `Replace` fsyncs the directory, so a crash cannot leave the sole
  private key zero-length or missing.
- Identity load no longer wraps the age parse error, which could
  carry fragments of decrypted file content into a printed error.
- The identity's containing directory is refused if group- or
  world-accessible, on both write and load, matching the file check.
- `--passphrase-file` is refused when it is a regular file with
  group or world permission bits. Process-substitution streams are
  still accepted.
- The structured logger redacts any attribute keyed `passphrase`,
  `value`, `plaintext`, `identity`, or `secret` as a backstop.

### Fixed

- `disable` can no longer resurrect a version that a concurrent
  `purge` destroyed between its check and its update.
- An interrupted `rekey` that left the identity at its `.new` sibling
  now self-heals on the next read instead of reporting the identity
  as missing and suggesting `init`.
- A failed `init` self-test removes the identity and vault it created
  so a re-run is not wedged on "already exists."
- `init` no longer treats a permission error while probing for an
  existing identity as permission to create one.
- `--env-name` is validated as a shell identifier at `set` time,
  rather than only warned about when `reveal --format` runs.
- `Value.Expose` documents that the returned slice aliases internal
  storage, and the decrypted envelope payload is wiped after use.
- Vault write transactions take an immediate lock, avoiding a
  spurious busy error when two invocations write concurrently.

## [1.0.1] - 2026-07-12

A documentation wording pass. reveal has always printed plaintext on
purpose, and the docs now say so consistently instead of implying
that nothing ever reaches the terminal.

### Changed

- The README and this changelog now scope the encryption guarantee
  to storage. There is no unencrypted storage mode. `reveal` is named
  as the single verb that prints plaintext, and everything else
  redacts.

### Fixed

- The `secret.Value.Expose` doc comment claimed `get` was a call
  site. It never was. The comment now lists the real ones: the
  reveal output, the exec environment, the envelope seal path, and
  the init self-test.

## [1.0.0] - 2026-07-12

The first release. A single-user, CLI-first secrets manager for
*nix. Values are sealed in age envelopes, metadata lives in SQLite,
and there is no plaintext storage mode.

### Added

- Full verb set: `init`, `set`, `get`, `reveal`, `show`, `list`,
  `stale`, `disable`, `delete`, `purge`, `exec`, `passwd`, and
  `rekey`.
- Asymmetric model. The vault stores the public recipient, so writes
  never need the private identity or a passphrase.
- Versioned secrets. Updates append, version numbers are monotonic
  and never reused, and rotation keeps an overlap window unless
  `--revoke-previous` is passed.
- Address binding. Every envelope carries its canonical
  `api/v1/<name>/<version>` address and decryption fails if the
  ciphertext was moved or swapped.
- Type-enforced redaction. Plaintext lives in one type with one
  exit, and fmt, JSON, and slog all render `[REDACTED]`. `reveal` is
  the single verb that prints a value.
- Identity file encrypted with an scrypt passphrase, written 0600 in
  a 0700 directory, refused on loose permissions, and held in locked
  memory while in use.
- `exec` injects env-named secrets into a child process and
  propagates its exit code.
- Expiry as a staleness flag. Expired secrets warn and appear in
  `stale` but always resolve.
- `rekey` rotates to a fresh identity and re-encrypts every live
  version inside one transaction, keeping the old identity as a
  `.bak` sibling.
- Soft `delete` with revive-on-set, and irreversible `purge` behind
  a `--yes` confirmation.
- JSON output on every verb, pretty by default and compact with
  `--json`. Warnings and prompts go to stderr.
- XDG default paths with flag and `SAFETYBOX_*` environment
  overrides.
- CI with build, lint, test, and gitleaks gates, conventional-commit
  auto-tagging, and GoReleaser releases for Linux and macOS on amd64
  and arm64.
- Documentation set under `docs/` covering getting started, every
  command, configuration, the security model, architecture, and
  development.

[1.1.0]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.1.0
[1.0.1]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.0.1
[1.0.0]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.0.0
