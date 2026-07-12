# Changelog

All notable changes to safetybox are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
versions follow [Semantic Versioning](https://semver.org/).

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

[1.0.0]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.0.0
