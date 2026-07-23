# Changelog

All notable changes to safetybox are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
versions follow [Semantic Versioning](https://semver.org/).

## [2.0.1] - 2026-07-23

### Added

- A pseudo-terminal test for the no-echo prompt, closing the last
  low-priority roadmap item. It asserts echo is off while the prompt
  reads, the returned line is exact, and the terminal state is
  restored. It adds `github.com/creack/pty` as a test-only dependency,
  which never reaches the shipped binary. CI now runs the suite on a
  macOS runner too, so the darwin termios paths run at runtime, not
  only cross-compiled.

### Security

- The shared wiping reader now also zeroes the unused capacity of the
  slice it returns on a successful read. A reader may leave scratch
  bytes past the count it reports, and for secret input that scratch
  could be plaintext. The readers in use never do this, so the change
  is defense in depth, matching the wipe the error path already does.
- The wiping reader guards its buffer growth against integer overflow.
  A pathologically large input now fails with a clear error instead of
  a panic in `make`. No input a real machine can hold reaches this
  bound, so this matters only to a hypothetical 32-bit build.

## [2.0.0] - 2026-07-22

A security-review release. Several adversarial two-reviewer passes
hardened it. The first found seventeen issues, and later passes over
the v2 changes and the whole release found more. This release fixes
every code-level finding and records the rest on the roadmap. Four
changes alter observable behavior, so this is a major version. The
breaking changes are `exec` exit codes for signal deaths, the
`reveal --json` shape for binary values, the meaning of an empty
`--expires`, and a new refusal when the vault recipient does not
match the identity. The module path also moves to
`github.com/samuel-stidham/safetybox/v2`, which Go requires for a v2
release.

### Added

- Clearing an expiry or an env name. An empty value passed to
  `--expires` or `--env-name` now removes the attribute. Before, an
  empty `--expires` was a silent no-op, and an expiry could never be
  removed at all.
- Base64 output for binary reveal values. A `reveal --json` value that
  is not valid UTF-8 is now base64-encoded and marked with an
  `encoding` field, so a consumer recovers the exact bytes. Before, the
  invalid bytes were replaced with U+FFFD.
- A vulnerability scan in the toolchain. `make vuln` runs a pinned
  govulncheck, the CI test step runs under the race detector, and CI
  gained a govulncheck step.
- A full tutorial and a documentation index under `docs/`. The tutorial
  runs every command in order and covers moving a vault between
  machines.
- A roadmap under `docs/roadmap.md` that tracks the security items the
  review left open for a later release.

### Changed

- `make test` now runs the fast suite for the local loop, and
  `make test-race` runs the same tests under the race detector with
  cgo on. CI runs `make test-race`.
- Lint suppressions moved out of the code. The two gosec G204
  exceptions live in `.golangci.yml` as anchored per-file rules, each
  justified in `docs/linting.md`, and no inline `nolint` comments
  remain.
- The documentation matches the shipped behavior. The security model,
  command reference, tutorial, and configuration guide describe the
  identity lock, the ambiguous-commit handling, and the wiping
  readers. The security model also documents that a vault-write
  attacker can forge a secret's value, which the roadmap's
  authenticated-contents item will address. The command reference
  scopes the recipient guard to the verbs that read the vault, so
  passwd no longer appears under it. The configuration guide documents
  the identity file's `.bak`, `.new`, and `.lock` siblings. The README
  and the security model drop their 1.0-era status text.

### Security

- Read verbs verify the vault recipient against the loaded identity. A
  vault-write attacker could swap the stored recipient so later writes
  seal to their key. safetybox now refuses on a mismatch, so the swap
  surfaces on the next read, even for versions that still decrypt under
  the old key. The write path holds no identity by design, so this is
  detection on read, not prevention at write time.
- A loose vault now warns. safetybox checks the vault file, its
  directory, and the WAL siblings on every run. It warns on stderr when
  any of them grant group or world access. The identity file is still
  refused outright, because it gates key material.
- Decrypted plaintext copies are wiped sooner. `secret.Value` gained a
  `Destroy` method. The reveal, exec, get, set, and rekey paths now call
  it as soon as the value is used, so a copy no longer lingers on the
  heap for the whole run.
- A signal now wipes the identity enclave. `main` installs a memguard
  interrupt handler and routes fatal exits through `SafeExit`, so a
  Ctrl-C during a decrypt scrubs the key before the process exits.
- Every reader that touches secret material wipes each buffer it
  outgrows: the value and passphrase readers, the envelope decrypt
  path, the identity loader, and the interactive prompt, which now
  uses its own no-echo reader instead of `term.ReadPassword`, whose
  line buffer grows without wiping. A failed read wipes its partial
  buffer, including any reader scratch space, and returns nothing. Only
  a bare `io.EOF` counts as end of input, so a wrapped EOF can never
  pass truncated data off as a successful read.
- The interactive prompt restores the terminal on a signal. A Ctrl-C
  during a passphrase entry used to leave the shell with echo disabled,
  because the interrupt handler exited before the deferred restore ran.
- The identity lock resolves symlinks before deriving its path, so two
  spellings of one identity, such as a symlink alias, serialize against
  each other instead of taking two independent locks.
- rekey and passwd now hold an exclusive lock beside the identity file
  for their whole run. Two interleaved rekeys could delete each other's
  staged key and leave the vault sealed to a key that no longer exists
  anywhere. The second run now refuses up front instead.
- A rekey whose commit errors keeps its staged identity. SQLite can
  report a commit error after the commit became durable in the WAL,
  and deleting the staged key then would destroy the only key able to
  read the re-encrypted vault. The error now says to test which key
  opens the vault before deleting either.

### Fixed

- `exec` no longer fails for every command when a single env-named
  secret holds a NUL byte. The offending secret is skipped with a
  warning that names it, and the rest inject.
- A child killed by a signal now exits 128 plus the signal number, not
  255, so a supervisor reads a signal death correctly.
- JSON output no longer exits 0 after a failed stdout write. A full disk
  or a broken pipe returns a write error instead of silently truncating
  the output.
- A half-created vault, the shape a crashed `init` leaves, now reports a
  recovery hint instead of a raw SQL error about a missing table.
- `delete` guards its update against a concurrent delete or purge, so a
  race cannot overwrite the first tombstone's timestamp.
- The `purge` help and the security model now state that a purged secret
  keeps its name in the vault forever.
- A locked or unreadable vault no longer reports as half-created. Open
  reserves the corrupt-vault hint for a missing table or version row,
  and passes operational errors through unwrapped.
- The loose-permission warning now says group or world can access the
  vault, rather than read it. The check flags any group or world bit,
  not only read.
- The module installs at v2. The path now carries the `/v2` suffix that
  Go's semantic import versioning requires. So `go install` and the
  module proxy accept the v2.0.0 tag. The Makefile `PKG` variable, the
  gci import prefix, and the install commands in the README and the
  tutorial carry the suffix too.
- rekey re-encrypts one version at a time instead of holding every
  envelope in memory at once, and prepares its per-version fetch once
  rather than re-parsing it each iteration. This bounds its memory use
  on a large vault.
- CI bumps `actions/setup-go` to v7, moving that step off the deprecated
  Node 20 runtime onto Node 24.
- The vault's exported methods now accept a `context.Context` from the
  caller instead of building their own. This is an internal refactor with
  no behavior change.
- The identity lock reports a filesystem without `flock` support as an
  environment error, instead of claiming another rekey or passwd is
  running. Only a genuine `EWOULDBLOCK` reports contention.
- The no-echo prompt builds on the whole BSD family, not darwin alone.
  The termios constants live in a build-tagged file covering darwin,
  dragonfly, freebsd, netbsd, and openbsd. CI now cross-compiles for
  darwin, so a platform-specific build break surfaces before release.
- rekey no longer reports a false failure when a concurrent read verb
  heals the identity swap. A missing staged key with the identity
  already in place is treated as the swap having completed.
- passwd and rekey on a machine with no config directory now point at
  `safetybox init`, instead of reporting a raw error about a missing
  lock file.

## [1.2.0] - 2026-07-12

### Added

- A version that survives `go install`. Binaries built without the
  ldflags injection now fall back to the module version in the build
  info, so a tagged install reports its tag instead of `dev`.
- Every build path reports the same v-prefixed version. goreleaser
  used to strip the v that git describe and the build info keep, so a
  release archive said 1.2.0 while every other install said v1.2.0.
  All paths now agree on v1.2.0.
- A SAFETYBOX banner and the version at the top of the root help, so
  running the bare command shows what is installed.
- `safetybox --version` continues to print the plain version line.

### Security

- Rekey can no longer destroy the only working key. A rekey that
  committed the vault to its staged key and crashed before the
  identity swap used to leave a trap: the next rekey deleted the
  staged file as stale and every secret was lost forever. Rekey now
  compares the vault's stored recipient against the loaded identity
  before touching anything, refuses when they differ, and names the
  staged file as the live key with recovery steps. A staged key that
  cannot be inspected is reported as its own error rather than as
  absent. Read verbs in that state now hint at the interrupted rekey
  instead of failing with a bare decrypt error.
- The staged identity and the rekey swap are now durable. `Write`
  fsyncs the containing directory after creating a file and the
  post-rekey rename pair is followed by a directory fsync, so a power
  loss can no longer separate the vault from its key.
- `reveal --prefix` and `list` now match whole name segments.
  `projects/myapp` no longer selects the sibling
  `projects/myapp-legacy`, which a raw leading-substring match would
  decrypt and print.
- A blocked WAL scrub is now detected and reported. The checkpoint
  after `purge` and `rekey` reads the pragma's busy result instead of
  discarding it, and both verbs warn on stderr when another process
  pinned the log, instead of silently claiming the old ciphertext was
  destroyed. The warning names the concurrent reader only when the
  checkpoint was actually blocked. Any other failure prints the real
  error, so an I/O or permission problem is not misattributed to
  another process.
- The logger's redaction backstop also covers `password` and `token`
  keys.

### Fixed

- `passwd` now heals an interrupted rekey like every other verb,
  instead of reporting the identity missing and suggesting `init`.
- A failed identity write now removes its partial file, and `passwd`
  clears a stale temp sibling left by a crash, so neither wedges every
  retry on "already exists".
- Two invocations racing the interrupted-rekey heal no longer make
  the loser fail after the winner already fixed things.
- A missing identity in a loose directory reports "run init first"
  before complaining about directory permissions.
- A `passwd` failure after the new passphrase is already live now
  says so, instead of implying the old passphrase still works.
- `reveal <name> --format sh` fails loudly when the named secret has
  no usable env name, instead of exiting 0 with empty output under an
  eval. Filter selections still skip with a warning.
- `reveal --format` and `exec` warn when two secrets share an env
  name, since the later value silently wins.
- `exec` now skips, with a warning, legacy env names that are not
  valid variable names, instead of injecting malformed entries into
  the child environment.
- `reveal` rejects `--json` combined with `--format sh|fish` instead
  of silently ignoring it, and warns when a value is not valid UTF-8
  and JSON output cannot carry it byte for byte.
- The `set` value prompt no longer reports its errors as passphrase
  errors.
- `exec` and `reveal` now share one batch decrypt path with a single
  expiry rule, so the two verbs cannot drift apart.

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
  longer linger in free pages or WAL frames. The vault holds a single
  connection, so the checkpoint always truncates the log rather than
  being blocked by another pooled connection.
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
- `rekey` now surfaces a real error if it cannot clear a stale staged
  identity, instead of swallowing it and failing later with a
  confusing "already exists" from the identity write.
- `rekey` can no longer lock the vault. The post-commit WAL checkpoint
  in `purge` and `rekey` is now best effort, so a checkpoint failure
  after a committed rekey no longer looks like a rekey failure and no
  longer makes the caller discard the new identity. Discarding it
  would have left the vault re-encrypted to a key that was just
  deleted. The unscrubbed WAL frames are reclaimed by the next
  checkpoint.

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

[2.0.0]: https://github.com/samuel-stidham/safetybox/releases/tag/v2.0.0
[1.2.0]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.2.0
[1.1.0]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.1.0
[1.0.1]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.0.1
[1.0.0]: https://github.com/samuel-stidham/safetybox/releases/tag/v1.0.0
