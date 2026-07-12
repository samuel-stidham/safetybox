// Safetybox is a single-user, CLI-first secrets manager for *nix.
//
// It keeps named, versioned secrets in a SQLite vault. Every value is
// sealed in an age envelope before it touches disk. The vault stores
// only the public recipient, so writing a secret needs no key
// material. Reading one needs the passphrase-protected identity file.
// There is no server, no GUI, and no unencrypted storage.
//
// # Verbs
//
//	init     create the identity and vault
//	set      store a new version of a secret
//	get      fetch and verify a secret, value redacted
//	exec     run a command with env-named secrets injected
//	reveal   print plaintext values, batches, or shell assignments
//	show     print metadata and version history, never the value
//	list     secrets, optionally under a name prefix
//	stale    list secrets past their expiry
//	disable  take one version out of resolution
//	delete   soft-delete a secret, keeping every envelope
//	purge    destroy a secret's envelopes forever
//	passwd   change the identity passphrase
//	rekey    rotate to a fresh identity and re-encrypt the vault
//
// Output is JSON on stdout, with warnings and prompts on stderr.
// reveal is the single verb that prints plaintext. Everything else
// redacts.
//
// # Security model
//
// Plaintext lives in one Go type and leaves it through one method.
// Every envelope is bound to its vault row, so moved or swapped
// ciphertext fails decryption. Passphrases come from a no-echo
// prompt or --passphrase-file, never from argv or the environment.
//
// Full documentation, including the command reference and the
// security model, lives at https://github.com/samuel-stidham/safetybox.
package main
