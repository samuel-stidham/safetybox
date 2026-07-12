# Command reference

Every verb, its flags, and its output. Global flags are covered in
the [configuration guide](configuration.md). Output is JSON on
stdout, pretty by default and compact with `--json`. Warnings and
prompts go to stderr.

Verbs that decrypt need your identity passphrase: get, reveal, exec,
passwd, and rekey. Verbs that only write or read metadata never ask
for it: set, show, list, stale, disable, delete, and purge. That
asymmetry is the point of storing the public recipient in the vault.

## init

```sh
safetybox init
```

Generates an X25519 identity, encrypts it with a passphrase, writes
it 0600 inside a 0700 directory, and creates the vault with the
recipient stored in it. Finishes with a seal and open self-test.
Refuses to overwrite an existing identity or vault. Prints the
recipient and a backup warning to stderr.

## set

```sh
printf 'value' | safetybox set <name> [--env-name NAME] [--expires WHEN] [--revoke-previous]
```

Appends a new enabled version. The value comes from stdin, or from a
no-echo prompt when stdin is a terminal. One trailing newline is
trimmed so `echo value | safetybox set` stores what was typed.
Values never come from arguments.

Names are hierarchical. Segments of letters, digits, dots,
underscores, and dashes, joined by single slashes. `api/stripe/live`
is valid. Leading slashes, trailing slashes, and spaces are not.

`--env-name` records the environment variable exec will use.
`--expires` takes RFC3339 or YYYY-MM-DD, where a bare date means
midnight UTC. Both attributes stick until a later set changes them.
`--revoke-previous` disables all older enabled versions in the same
transaction. Without it, prior versions stay enabled so rotation has
an overlap window.

Setting a soft-deleted secret revives it. Version numbers are
monotonic and never reused, even across delete and revive.

```json
{"name":"api/stripe/live","version":2,"state":"enabled","envName":"STRIPE_KEY","revokedPrevious":0}
```

## get

```sh
safetybox get <name>
```

Decrypts the newest enabled version, verifies its address binding,
and prints metadata. The value field always reads `[REDACTED]`. Use
get in scripts that need to know a secret resolves without ever
printing it. Expired secrets warn on stderr and still resolve.

```json
{"name":"api/stripe/live","version":2,"state":"enabled","envName":"STRIPE_KEY","createdAt":"2026-07-12T17:35:17Z","updatedAt":"2026-07-12T17:36:46Z","expired":false,"value":"[REDACTED]"}
```

## reveal

```sh
safetybox reveal <name>
safetybox reveal <name> --json | jq -r .value
safetybox reveal <name> <name>...
safetybox reveal --env --format fish | source
safetybox reveal --prefix projects/myapp --format sh
```

The single verb that prints plaintext. Everything else redacts.

One name prints one JSON object, unchanged from earlier releases.

```json
{"name":"api/stripe/live","envName":"STRIPE_KEY","version":2,"expired":false,"value":"sk_live_example"}
```

Several names, `--env`, or `--prefix` select a batch. The whole batch
decrypts with one passphrase read and one identity unlock, which is
the point. `--env` selects every secret that has an env name.
`--prefix` selects every secret under a name prefix. The two filters
compose, and filters cannot be mixed with explicit names. Batch JSON
output is an array. An explicit name that does not resolve fails the
whole batch. A filter that matches nothing prints an empty array.

`--format sh` and `--format fish` emit assignment lines ready to
source into a shell session, using the env name recorded by set.

```sh
export STRIPE_KEY='sk_live_example'
```

```fish
set -gx STRIPE_KEY 'sk_live_example'
```

Values are single-quoted for the target shell, so embedded quotes,
command substitutions, and newlines stay inert text. A selected
secret with no env name, or with an env name that is not a valid
shell identifier, is skipped with a warning on stderr and never
silently dropped. Load your global secrets in one line:

```fish
safetybox reveal --env --format fish --passphrase-file FILE | source
```

And a project's secrets in a `.envrc`:

```sh
eval "$(safetybox reveal --prefix projects/myapp --format sh --passphrase-file FILE)"
```

## show

```sh
safetybox show <name>
```

Metadata only. Existence, timestamps, expiry state, and the full
version history with states. It never prints the value or its
length, and it needs no identity. show includes soft-deleted secrets
so you can see tombstones.

```json
{"name":"api/stripe/live","envName":"STRIPE_KEY","createdAt":"2026-07-12T17:35:17Z","updatedAt":"2026-07-12T17:36:46Z","expired":false,"versions":[{"version":1,"state":"disabled","createdAt":"2026-07-12T17:35:17Z"},{"version":2,"state":"enabled","createdAt":"2026-07-12T17:36:46Z"}]}
```

## list

```sh
safetybox list [prefix]
```

Lists every non-deleted secret, or only those under a name prefix.
Names are plaintext columns in the current format, so list needs no
identity. Output is a JSON array of metadata summaries with the
latest version number.

## stale

```sh
safetybox stale
```

Lists non-deleted secrets whose expiry has passed. Expiry is a
staleness flag, never a deletion trigger. Stale secrets keep
resolving, with a warning, until you rotate or delete them.

## disable

```sh
safetybox disable <name> <version>
```

Takes one version out of resolution without touching its envelope.
get and reveal fall back to the newest remaining enabled version.
Disabling a destroyed version fails. Disabling twice is a no-op.

## delete

```sh
safetybox delete <name>
```

Soft delete. The secret leaves list, get, and exec, but every
version and envelope stays intact. show still displays it with a
deletedAt timestamp. set revives it. purge destroys it.

## purge

```sh
safetybox purge <name> --yes
```

Erases every envelope of the secret and marks all versions
destroyed, inside one transaction. Rows and history remain, the
values are gone forever. Refuses to run without `--yes`. purge
implies delete.

```json
{"name":"legacy/token","destroyedVersions":1,"result":"purged"}
```

## exec

```sh
safetybox exec -- <command> [args...]
```

Resolves every non-deleted secret that has an env name, decrypts its
newest enabled version, and runs the command with those variables
added to the environment. Everything after `--` belongs to the
child. stdin, stdout, and stderr pass through, and the child's exit
code is propagated. Expired secrets warn on stderr and still
resolve.

## passwd

```sh
safetybox passwd [--new-passphrase-file FILE]
```

Changes the identity passphrase. It decrypts the identity with the
current passphrase and re-encrypts it with the new one, swapped into
place atomically. The key itself does not change, so the vault needs
nothing. The current passphrase comes from the prompt or the global
`--passphrase-file`.

## rekey

```sh
safetybox rekey
```

Full key rotation. rekey generates a new identity, re-encrypts every
non-destroyed version to it, and stores the new recipient. All vault
writes happen inside one transaction and the recipient updates last,
so a failure at any point leaves the old vault fully intact.

The new identity is staged beside the old one before the vault
transaction starts. After the transaction commits, the old identity
moves to a `.bak` sibling and the new one takes its place. Keep the
`.bak` until you have verified a reveal, then back up the new file
and delete the old one. The passphrase stays the same. Use passwd to
change it.

```json
{"recipient":"age1...","rekeyedVersions":4,"backupIdentity":"~/.config/safetybox/identity.age.bak"}
```

## version

```sh
safetybox --version
```

Prints the version stamped at build time from git describe.
