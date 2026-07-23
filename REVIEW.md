# Code review policy for safetybox

Guidance for automated code review of this repository. safetybox is a
single-user, CLI-first secrets manager in Go. Values are sealed in age
envelopes. Metadata lives in SQLite. Keys are held with memguard.
Versioning is append-only. The full model is in `docs/security.md` and
`docs/architecture.md`.

Threat model. This is a local, single-user tool with no network
surface. An attacker with the identity file, the passphrase, and the
vault has everything, and local machine access is treated as a
compromise. Calibrate findings to that model rather than to a
server-side one.

## Non-negotiable security invariants

Flag any change that weakens one of these. These are enforced by code
and tests, so a violation is a bug, not a style note.

- Plaintext lives only in `secret.Value` in `internal/secret`, and
  leaves it only through `Expose`. Never add another exit. Never move
  the type into a shared package. `fmt`, JSON, and `slog` must render
  `[REDACTED]`.
- Plaintext never reaches disk, a log, an error, or a command
  argument. Values arrive from stdin or a no-echo prompt. Passphrases
  arrive from a prompt or `--passphrase-file`, never from argv or the
  environment.
- Every reader that touches secret material wipes the buffers it
  outgrows through `secret.ReadAllWiping`. A decrypted value is
  `Destroy`ed as soon as it is used.
- Every envelope binds to its row. The plaintext is prefixed with
  `api/v1/<name>/<version>`, and `envelope.Open` verifies it. Never
  bypass the address check.
- Read verbs compare the vault's stored recipient to the loaded
  identity and refuse on a mismatch before decrypting anything.
- `rekey` and `passwd` hold the identity lock for their whole run. The
  staged-key handling and the ambiguous-commit retention must not
  regress. A crash must never destroy the only key that reads the
  vault.
- SQLite queries are always parameterized. `secure_delete`, WAL
  journaling, the single connection, and `_txlock=immediate` stay in
  place.

## Documented decisions, do not relitigate

- Secret names, timestamps, and env variable names are plaintext
  columns by design for the MVP. Report a downstream consequence, not
  the decision. The deferred fix is the roadmap's authenticated-
  contents item, which changes the on-disk format.
- Reads are unbounded on purpose. A size cap was judged unnecessary
  for a single-user CLI. Flag a newly unbounded resource only when it
  is a regression.

## Dependencies

Every module in `go.sum` is audit surface. Flag any new module added
to `go.mod` at High, and call it out explicitly in the summary with
what it is and whether it reaches the shipped binary. Test-only
dependencies still count.

## Build and lint constraints

- The shipped binary builds with `CGO_ENABLED=0` and pure-Go SQLite.
  The CI race build uses `CGO_ENABLED=1`. Flag code that behaves
  differently between the two, or a path only the race build runs.
- No inline `nolint`. Lint exclusions live in `.golangci.yml` with a
  justification in `docs/linting.md`. Flag a new inline suppression or
  an exclusion with no matching justification.

## Severity calibration

- Critical. A plaintext secret reaching disk, a log, an error, or
  argv. A decrypt path returning forged or wrong plaintext as valid.
  Loss of the only key. SQL injection. The `secret.Value` redaction
  boundary broken.
- High. A security guard or refusal dropped. Wiping or `Destroy`
  removed from a secret path. The recipient or address check bypassed.
  An identity-lifecycle crash window reopened. A new module
  dependency.
- Medium. A wiping gap on an error path. A doc claim that overstates a
  security property. A newly unbounded resource.
- Low. A misleading error message. A missing test for changed
  behavior. An unjustified lint exclusion.
- Info. Naming, comment accuracy, and style.

## Files to skip

Skip `vendor/`, which is generated from `go.mod`. Do not skip `go.mod`
or `go.sum`, since dependency changes are in scope. Review the docs
against the code they describe. A wrong security claim in `docs/` is a
real finding.

## Verification expectations

Verify a finding against the code before posting it, not against the
diff alone. Read the caller and the callee. For a claimed leak, trace
the plaintext from input to disposal. Prefer a concrete trigger. Do
not post a finding you could not substantiate.

## Summary style

Lead with the verdict. Group findings by severity, most severe first.
Cite file and line. State each finding as what is wrong, why it
matters for this tool, and how to trigger it. Keep prose plain, with
no em dashes and no semicolons.

## Sub-agent usage

- Use 0 sub-agents for a docs-only, CHANGELOG-only, formatting-only,
  or `go.sum` lockfile-only change, or a single-file typo.
- Use 1 sub-agent for a focused change under 300 changed lines that
  touches one risky area. The risky areas are the secret lifecycle,
  identity or rekey, envelope crypto, the vault and SQLite layer, and
  a new dependency.
- Use 3 sub-agents for a change that spans the command surface, the
  vault data layer, and crypto or identity. Split the work this way.
  1. Secret lifecycle and crypto. Trace plaintext and check the
     envelope and recipient handling.
  2. Vault and SQLite correctness. Check queries, transactions, and
     the append-only invariants.
  3. Tests and docs. Check coverage of the changed behavior and doc
     accuracy against the code.
- Use the full 6 sub-agents for a large or security-sensitive change,
  an on-disk format change, or one over 800 changed lines. Split by
  independent area: secret lifecycle, identity and rekey, envelope
  crypto, vault and SQLite, the cmd surface and process handling, and
  tests and docs.

Each sub-agent stays read-only, posts no comments, and returns a path,
line, severity, rationale, and confidence. The main reviewer verifies
every finding before posting it.
