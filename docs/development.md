# Development

How to build, test, and release safetybox.

## Building

`make help` lists every target. The daily loop is three commands.

```sh
make dev       # build bin/safetybox with a -dev version suffix
make lint      # gofumpt, gci, golangci-lint, all fixers on
make test      # fast tests, for the local loop
make test-race # tests under the race detector, needs cgo, what CI runs
make vuln      # govulncheck against the dependency tree
```

`make dev` builds into `bin/` and tags the version with `-dev` so a
test build never masquerades as an installed one. `make build` is
the clean build CI uses. `make install` is the official install into
`$GOPATH/bin`. Everything builds with `CGO_ENABLED=0`, and the
version comes from git describe through ldflags. A build without
ldflags, like a plain `go install`, falls back to the module version
in the build info. Every path reports the v-prefixed tag.

## Testing

Tests run against real SQLite databases in `t.TempDir()` and real
age keys generated per test. There are no mocks. The cmd package
carries an end-to-end suite that drives the CLI in process through
init, set, rotation, disable, revoke, exec, rekey, passwd, delete,
purge, and revive. Because the suite exercises real age scrypt on
every identity load, it is not instant, and the race detector makes it
several times slower again. So `make test` runs without the detector
for the local loop, and `make test-race` adds it. `make test-race`
forces `CGO_ENABLED=1`, because the detector needs cgo, even though the
shipped binary is built with cgo disabled. CI runs `make test-race`.

The no-echo passphrase prompt is tested against a real pseudo-terminal,
so echo suppression and terminal restore are verified rather than
assumed. That test uses the `creack/pty` helper and runs on Linux and
macOS.

Two conventions are non-negotiable. Every envelope test includes a
corrupt-one-byte case asserting decryption fails. Test fixtures use
obviously fake material like `fake-test-passphrase-not-real`, never
anything that could pass for a real credential.

Coverage targets exist as `make cover`, `make cover-func`, and
`make cover-html`.

## Linting

The golangci-lint config enables nearly every linter. Findings get
fixed, not suppressed. The narrow exceptions and their reasons live
in the [linting policy](linting.md). Import grouping is stdlib, then
safetybox, then third-party, enforced by gci with custom order.

## Dependencies

This is a secrets tool, so every module in go.sum is audit surface.
The dependency list is deliberately short: age, modernc sqlite,
cobra, memguard, testify, and the x/crypto, x/term, and x/sys
families. x/sys backs the no-echo prompt's terminal control. One
test-only dependency, `creack/pty`, allocates a pseudo-terminal for
the prompt's terminal test and never reaches the shipped binary.
Justify any addition in the PR description. A `vendor/` directory may
exist locally for offline builds. It stays untracked, and CI resolves
modules from `go.sum`.

## Commits and CI

Commits follow the conventional commit format and are GPG-signed.
CI runs build, lint with a `git diff --exit-code` guard, tests under
the race detector, a govulncheck scan, and a gitleaks history scan on
every push and pull request.

## Releases

Releases are automatic. Every push to main that passes all gates is
inspected for conventional commits. A feat commit bumps the minor
version, a fix commit bumps the patch, and a breaking change bumps
the major. The new tag triggers GoReleaser in the same workflow run,
which builds static binaries for Linux and macOS on amd64 and arm64,
generates checksums, and publishes the GitHub release. The release
notes come from the `CHANGELOG.md` section for the tag, which CI
extracts and passes to GoReleaser, so the generated commit-list
changelog is disabled. A manually pushed `v*` tag releases the same
way.
