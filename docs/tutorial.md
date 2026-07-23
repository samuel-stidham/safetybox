# Tutorial

This is a hands-on walkthrough. It starts at install and runs every
command safetybox has, in the order you would meet them. Follow it top
to bottom and you will have created a vault, stored and rotated
secrets, injected them into a program, and rotated your keys. Every
value shown here is fake. Use your own.

If you want the terse version of any command, the
[command reference](commands.md) has it. This page is the guided tour.

## 1. Install

You need Go 1.26 or later to build from source.

```sh
go install github.com/samuel-stidham/safetybox/v3@latest
```

That puts `safetybox` in `$GOPATH/bin`, which is `~/go/bin` by default.
Make sure that directory is on your `PATH`. Prebuilt binaries for Linux
and macOS also ship with each GitHub release, so you can download one
instead of building.

Confirm the install and read the version.

```sh
safetybox --version
```

## 2. Create your identity and vault

One command sets up everything.

```sh
safetybox init
```

`init` generates an X25519 keypair. The private half is your identity.
It is encrypted with a passphrase you type at a no-echo prompt and
written to `~/.config/safetybox/identity.age`. The public half is the
recipient. It is stored in the vault at
`~/.local/share/safetybox/vault.db`. `init` finishes with a self-test
that seals and opens a throwaway value through the full stack, then
prints your recipient.

Pick a strong passphrase. It is the only thing protecting your identity
file if that file is ever stolen.

## 3. Understand the two files

safetybox keeps two files, and the difference matters.

The vault holds your public recipient and the sealed secrets. Anyone
who reads it sees ciphertext plus plaintext metadata, meaning names,
env names, and timestamps. They cannot decrypt a single value. Writing
a new secret needs only the vault, because sealing uses the public
recipient.

The identity file holds your private key, encrypted under your
passphrase. Reading a secret needs it. So does rotating your keys.
Without it, every secret in the vault is lost forever, and the
passphrase alone cannot recover them.

This split is deliberate. A machine that only produces secrets can
carry the vault and never hold the private key.

## 4. Back up the identity file now

Do this before you store anything real. Copy the identity file
somewhere safe and offline.

```sh
cp ~/.config/safetybox/identity.age /path/to/backup/identity.age
```

If you lose it, the vault becomes unreadable noise. There is no reset.

## 5. Store your first secret

Values come from stdin or a no-echo prompt, never from arguments.
Arguments leak into shell history and process lists.

```sh
printf 'sk_live_example' | safetybox set api/stripe/live --env-name STRIPE_KEY
```

`set` appends a new enabled version. The `--env-name` records the
environment variable that `exec` and `reveal --format` will use later.
An env name must be a valid shell identifier, so letters, digits, and
underscores, not starting with a digit.

Names are hierarchical. Segments of letters, digits, dots, underscores,
and dashes join with single slashes, like `api/stripe/live`. Build a
tree that prefix queries can walk later.

If stdin is a terminal, `set` prompts instead of reading a pipe.

```sh
safetybox set api/stripe/test
Value for api/stripe/test:
```

## 6. Read the metadata with get

`get` proves a secret resolves without ever printing it.

```sh
safetybox get api/stripe/live
```

It asks for your passphrase, decrypts the newest enabled version,
verifies the envelope is bound to the right row, and prints metadata.
The value field always reads `[REDACTED]`. Use `get` in scripts that
need to confirm a secret is present and decryptable.

## 7. Inspect history with show

`show` needs no identity and decrypts nothing. It prints existence,
timestamps, expiry state, and the full version history.

```sh
safetybox show api/stripe/live
```

`show` includes soft-deleted secrets, so you can see tombstones that
`list` and `get` hide.

## 8. List what you have

```sh
safetybox list
safetybox list api/
```

`list` prints a JSON array of every non-deleted secret, or only those
under a name prefix. The prefix selects whole segments, exactly and
case-sensitively. `api/` selects `api/stripe/live` and `api/stripe/test`
but never a sibling like `api-legacy`. Names are plaintext columns, so
`list` needs no identity.

## 9. Reveal the plaintext

`reveal` is the single verb that prints plaintext. Everything else
redacts. You ask for it on purpose.

```sh
safetybox reveal api/stripe/live
```

One name prints one JSON object with the value in it. Pipe it through
`jq` when you want the raw string.

```sh
safetybox reveal api/stripe/live --json | jq -r .value
```

A value that is not valid UTF-8 cannot ride inside JSON byte for byte.
safetybox base64-encodes it, marks it with an `encoding` field set to
`base64`, and warns on stderr. Decode it yourself, or use `exec`, which
passes the exact bytes.

### Reveal a batch

Several names, `--env`, or `--prefix` select a set. The whole set
decrypts with a single passphrase read, which is the point.

```sh
safetybox reveal api/stripe/live api/stripe/test
safetybox reveal --env
safetybox reveal --prefix api/stripe
```

`--env` selects every secret that has an env name. `--prefix` selects a
name and everything under it as whole segments. Filters and explicit
names cannot be mixed. A filter that matches nothing prints an empty
array, and it never touches your identity.

### Reveal as shell assignments

`--format sh` and `--format fish` emit assignment lines you can source.
They use the env name that `set` recorded.

```sh
safetybox reveal --env --format sh
export STRIPE_KEY='sk_live_example'
```

Values are single-quoted for the target shell, so quotes, command
substitutions, and newlines stay inert text. Load your global secrets
in one line.

```fish
safetybox reveal --env --format fish --passphrase-file FILE | source
```

Or a project's secrets in a `.envrc`.

```sh
eval "$(safetybox reveal --prefix api/stripe --format sh --passphrase-file FILE)"
```

## 10. Inject secrets into a command with exec

`exec` runs a program with your env-named secrets in its environment.

```sh
safetybox exec -- ./deploy.sh
```

It resolves every non-deleted secret that has an env name, decrypts the
newest enabled version, and runs the command with those variables
added. Everything after `--` belongs to the child. Its stdin, stdout,
stderr, and exit code all pass through.

A child killed by a signal reports 128 plus the signal number, the way
a shell does. A secret whose value holds a NUL byte cannot become an
environment variable, so `exec` skips it with a warning that names it
and runs the command with the rest.

## 11. Set an expiry and find stale secrets

An expiry marks a secret stale. It never deletes anything.

```sh
printf 'sk_live_example' | safetybox set api/stripe/live --expires 2027-01-01
```

`--expires` takes RFC3339 or a bare `YYYY-MM-DD`, where a date means
midnight UTC. List the secrets whose expiry has passed.

```sh
safetybox stale
```

Stale secrets keep resolving, with a warning, until you rotate or
delete them. To remove an expiry you set earlier, pass an empty value.

```sh
printf 'sk_live_example' | safetybox set api/stripe/live --expires ''
```

An empty `--env-name` clears the env name the same way.

## 12. Rotate a secret

Rotation is a plain `set`. It appends a new version.

```sh
printf 'sk_live_newer' | safetybox set api/stripe/live
```

The old version stays enabled, so consumers keep working during the
rollout. That overlap is by design. Version numbers are monotonic and
never reused, even across delete and revive.

## 13. Disable an old version

When the rollout is done, take the old version out of resolution.

```sh
safetybox disable api/stripe/live 1
```

`disable` removes one version from resolution without touching its
envelope. `get` and `reveal` fall back to the newest remaining enabled
version. You can also revoke every older version in one step on the next
set.

```sh
printf 'sk_live_newest' | safetybox set api/stripe/live --revoke-previous
```

## 14. Soft-delete and revive

`delete` is reversible. The secret leaves `list`, `get`, and `exec`,
but every version and envelope stays intact.

```sh
safetybox delete api/stripe/test
```

`show` still displays it with a `deletedAt` timestamp. A later `set`
revives it, and the version numbers pick up where they left off.

```sh
printf 'sk_live_revived' | safetybox set api/stripe/test
```

## 15. Purge for good

`purge` is irreversible. It erases every envelope and marks all versions
destroyed. It requires `--yes`.

```sh
safetybox purge api/stripe/test --yes
```

The values are gone forever. The row and its history remain, so the
secret name stays readable in the vault after purge. If a name itself is
sensitive, purge does not remove it. After the commit, purge scrubs the
write-ahead log so the erased bytes do not linger.

## 16. Change your passphrase

`passwd` re-encrypts the identity under a new passphrase. The key itself
does not change, so the vault is untouched.

```sh
safetybox passwd
```

It prompts for the current passphrase, then the new one twice. For
automation, pass `--new-passphrase-file`.

## 17. Rotate your keys with rekey

`rekey` is a full key rotation. It generates a new identity, re-encrypts
every non-destroyed version to it, and stores the new recipient.

```sh
safetybox rekey
```

Every vault write happens in one transaction and the recipient updates
last, so a failure before the commit leaves the old vault fully
intact. In the rare case where the commit itself errors, rekey keeps
both key files and tells you to test which one opens the vault. The
old identity moves to a `.bak` sibling and the new one takes its place.
Keep the `.bak` until you have verified a `reveal`, then back up the new
file and delete the old one. The passphrase stays the same. Use `passwd`
to change it.

## 18. Move your vault to another machine

Copy both files. The vault alone cannot decrypt anything.

```sh
scp ~/.local/share/safetybox/vault.db newhost:~/.local/share/safetybox/
scp ~/.config/safetybox/identity.age newhost:~/.config/safetybox/
```

On the new machine, `reveal` and `get` will prompt for the same
passphrase you set at `init`. If you copy only the vault, you can still
write new secrets and read metadata, but every read of a value fails.

Two safety notes come up here. safetybox warns on stderr if the vault
file, its directory, or its write-ahead siblings become group- or
world-accessible, which a careless copy can cause. And if the vault's
stored recipient does not match your identity, every read refuses with a
clear error rather than a confusing decryption failure. That guards
against a tampered vault and against pointing the wrong identity at it.

## 19. Upgrade an older vault with migrate

If you came to 3.0 from safetybox 1.x or 2.x, your vault is in the old
on-disk format and 3.0 refuses to open it until you migrate. The 3.0
format seals each secret's env name and expiry into its envelope, so a
later edit to those columns is caught on read.

```sh
safetybox migrate
```

migrate prompts for your passphrase, re-seals every secret into the new
format in one transaction, and bumps the format version. Your names,
values, and versions are unchanged. Back up the vault file first. Stop
anything else that touches the vault, especially a script still on the
old binary, or a racing write can strand an unreadable version. Run
it once. A vault already at the current format, like the one you just
created, reports that and does nothing.

For automation, the passphrase can come from `--passphrase-file`,
including a process substitution.

```sh
safetybox migrate --passphrase-file (secret-get safetybox-passphrase | psub)
```

## 20. Where to go next

You have now run every command safetybox has. For the precise contract
of each verb, read the [command reference](commands.md). To understand
what safetybox protects and what it does not, read the
[security model](security.md). For paths, precedence, and the global
flags, read the [configuration guide](configuration.md).
