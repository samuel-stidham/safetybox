# Getting started

This guide takes you from nothing to a working vault with one secret
in it.

## Install

Build from source with Go 1.26 or later.

```sh
git clone https://github.com/samuel-stidham/safetybox.git
cd safetybox
make install
```

`make install` puts the binary in `$GOPATH/bin`, which is `~/go/bin`
by default. For a throwaway build in the repo, use `make dev` and run
`bin/safetybox` instead. Prebuilt binaries for Linux and macOS ship
with each GitHub release.

## Create your identity and vault

```sh
safetybox init
```

init generates an X25519 keypair. The private half is your identity.
It is encrypted with a passphrase you type at a no-echo prompt and
written to `~/.config/safetybox/identity.age`. The public half is the
recipient. It is stored in the vault at
`~/.local/share/safetybox/vault.db` so writes never need your
passphrase. init finishes with a self-test that seals and opens a
throwaway value through the full stack.

## Back up the identity file

Do this now, not later. Without the identity file, every secret in
the vault is unrecoverable. The passphrase alone cannot recover them.
Copy `~/.config/safetybox/identity.age` somewhere safe and offline.

## Store your first secret

Values come from stdin or a no-echo prompt, never from arguments.
Arguments leak into shell history and process lists.

```sh
printf 'sk_live_example' | safetybox set api/stripe/live --env-name STRIPE_KEY
```

Names are hierarchical. Use slashes to build a tree that prefix
queries can walk, like `api/stripe/live` and `api/stripe/test`.

## Read it back

```sh
safetybox get api/stripe/live      # metadata, value shows [REDACTED]
safetybox reveal api/stripe/live   # metadata plus the plaintext
safetybox show api/stripe/live     # metadata only, no identity needed
```

get and reveal ask for your passphrase, decrypt the newest enabled
version, and verify the envelope is bound to the right row. reveal is
the only verb in safetybox that prints plaintext.

## Use it in a command

```sh
safetybox exec -- ./deploy.sh
```

exec resolves every secret that has an env name and runs the command
with those variables injected. The example above runs `deploy.sh`
with `STRIPE_KEY` set.

## Rotate it

```sh
printf 'sk_live_newer' | safetybox set api/stripe/live
```

Updates append a new version. The old version stays enabled so
consumers keep working during the rollout. When the rollout is done,
disable the old version or pass `--revoke-previous` on the next set.

## Move it to another machine

To read your secrets on another machine, copy both files. The vault
alone cannot decrypt anything.

```sh
scp ~/.local/share/safetybox/vault.db newhost:~/.local/share/safetybox/
scp ~/.config/safetybox/identity.age newhost:~/.config/safetybox/
```

On the new machine, get and reveal prompt for the same passphrase you
set at init. If you copy only the vault, you can still write new
secrets and read metadata, but every attempt to read a value fails,
because the private key never left the identity file.

## Where to go next

The [tutorial](tutorial.md) walks through every command in order, from
install to key rotation. The [command reference](commands.md) covers
every verb and flag. The [security model](security.md) explains what
safetybox protects and how. The [configuration guide](configuration.md)
covers paths and environment variables.
