{
  description = "A Nix DSL that compiles to Nftables";

  outputs = { self, nixpkgs }: {
    checks.x86_64-linux.default = let pkgs = nixpkgs.legacyPackages.x86_64-linux; in pkgs.callPackage ./checks.nix {
      flake = (pkgs.callPackage ./. { }).config.notnft;
    };
  };
}
