# Not Nft

This is a typed version of nftables's JSON format for Nix. It uses
nixpkgs's option system, which means it can integrate with Nix very
well. Type-safe wrappers for each type are provided, but you can
alternatively simply directly follow the official schema if you're more
comfortable with that.

- Q: Why?
- A: I'm working on a fresh NixOS router config, and wanted to nixify
  the nftables syntax. Since this project uses nixpkgs's module system,
  I can easily add options that directly map to nftables concepts.
- Q: Is this limited in any way?
- A: I fully support the current JSON specification, but the nftables
  DSL has a different feature set compared to the JSON API (some
  features are only preset in the former, some only in the latter, at
  least according to the spec). I might add a compiler to .nft files
  some day.
- Q: Why the name?
- A: I already created [notlua](https://github.com/chayleaf/notlua), so
  this is the next project in that "series".
- Q: Does this have any relation to Non-Fungible Tokens?
- A: As the name implies, no.
