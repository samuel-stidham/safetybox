# safetybox documentation

Start here. The pages below go from first run to internals, roughly in
the order you would need them.

## Learn it

- [Getting started](getting-started.md) takes you from install to your
  first rotated secret in a few minutes.
- [Tutorial](tutorial.md) is the full guided tour. It runs every command
  in order, from install through key rotation, and covers moving a vault
  between machines.

## Use it

- [Command reference](commands.md) is the precise contract of every verb,
  flag, and output shape.
- [Configuration](configuration.md) covers the vault and identity paths,
  their precedence, and the global flags.

## Understand it

- [Security model](security.md) explains the layers, the invariants, and
  what safetybox does not defend against.
- [Architecture](architecture.md) explains the packages, the data model,
  and the address binding.

## Work on it

- [Development](development.md) covers building, testing, and the release
  pipeline.
- [Linting policy](linting.md) records every linter exception and its
  reason.
- [Roadmap](roadmap.md) is closed and kept as a record of the earlier
  review items. From 3.0.0 on, bugs and security findings are tracked
  as [GitHub issues](https://github.com/samuel-stidham/safetybox/issues).
