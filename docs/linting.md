# Linting policy

safetybox runs golangci-lint with almost every linter enabled. The
rule is simple. Findings get fixed, not suppressed. When a linter is
wrong for a whole class of files, the exclusion lives in
`.golangci.yml` and gets a justification here. Inline `nolint`
comments are a last resort and each one must carry its reason in the
code.

## Linters excluded for test files

These exclusions apply to `_test.go` files only. Production code
answers to every linter.

**dogsled.** Tests often check only the error from a multi-return
call. Blank identifiers in that position are the clearest way to say
so. Production code should restructure the API instead, which is what
`vault.Resolved` did.

**dupl.** Table-driven tests repeat structure on purpose. Deduping
them into abstractions makes failures harder to read.

**errorlint.** Tests compare and unwrap errors through testify
helpers, which handle wrapping themselves.

**funlen.** A test that walks a full lifecycle reads best as one
story. Splitting it to satisfy a line count scatters the narrative
and forces shared state between functions.

**goconst.** Repeating a literal like a fake path or verb name keeps
each test self-contained. Hoisting test literals into constants adds
a lookup for zero safety.

**mnd.** Magic numbers in tests are assertions. Version 3, mode
0o600, and port-like values are the expected values themselves. A
named constant would just restate the assertion.

**prealloc.** Slice preallocation is a micro-optimization. Test
fixtures gain nothing from it and the hint costs clarity.

**unparam.** Test helpers keep parameters that currently receive one
value so the next test can vary them. Removing the parameter today
and re-adding it tomorrow is churn.

**varnamelen.** Short names like `tt` and `tx` are idiomatic inside
tests and their scope is a few lines.

**gosec, rules G301, G302, and G304 only.** G304 flags file paths
built from variables, and every test builds paths from `t.TempDir()`,
which the test itself controls. G301 and G302 flag loose directory and
file permissions, and the permission tests deliberately create 0755
directories and 0644 files to prove the ssh-style checks refuse them,
so the finding is the point of the test. All other gosec rules still
apply to tests, including G101, which keeps real-looking credentials
out of fixtures.

## Inline suppressions in production code

There is exactly one, and this list must stay short.

**cmd/exec.go, gosec G204.** G204 guards against untrusted input
reaching a subprocess. The exec verb exists to run the user's own
command line with secrets in the environment. The input is the
operator's own argv, so no sanitization could keep the verb useful.

## Inline suppressions in test code

**cmd/review_fixes_internal_test.go, gosec G204.** The shell
round-trip test sources the reveal verb's own emitted assignments in a
real `sh` and `fish` to prove the quoting is injection-safe. Spawning
the shell is the test, so the finding cannot be designed away.
G204 stays inline rather than excluded for all test files, because a
future test that spawns a subprocess with genuinely tainted input
should still be flagged.

## Adding an exclusion

Fix the finding first. If the linter is genuinely wrong for a whole
file class, add the exclusion to `.golangci.yml` and write its
justification in this file in the same change. An exclusion without
a justification entry here should fail review.
