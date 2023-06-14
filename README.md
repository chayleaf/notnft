# Not Nft

This is a partly-typed version of nftables's JSON format for Nix (it
checks JSON structure and expression contexts; it doesn't check the
types themselves). It uses nixpkgs's option system, which means it can
integrate with Nix very well. A dsl is provided to more easily write
JSON nftables, but you can alternatively simply directly follow the
official schema if you're more comfortable with that.

nftables' documentation is *really* poor, so to the extent possible I
collected some internal documentation in [NOTES.md](./NOTES.md). The
most important thing is not to rely on the official documentation for
~~anything~~ obscure bits (it's fine for the common use cases, but in
general you really can't trust it). I'll try to push some documentation
changes upstream.

- Q: How can I quickly test it?
- A: Clone this repo and edit/run `./sample.nix`
- Q: Why?
- A: I'm working on a fresh NixOS router config, and wanted to nixify
  the nftables syntax. Since this project uses nixpkgs's module system,
  I can easily add options that directly map to nftables concepts.
- Q: Is this limited in any way?
- A: I fully support the current JSON specification, but the nftables
  DSL has a different feature set compared to the JSON API (some
  features are only present in the former, some only in the latter). I
  might add a compiler to .nft files some day.
- Q: Why the name?
- A: I already created [notlua](https://github.com/chayleaf/notlua), so
  this is the next project in that "series".
- Q: Does this have any relation to Non-Fungible Tokens?
- A: As the name implies, no.
