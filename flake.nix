{
  description = "A Nix DSL that compiles to Nftables JSON";

  outputs = { self, nixpkgs }:
    let
      forEachSystem = func: nixpkgs.lib.genAttrs [ "aarch64-linux" "aarch64-darwin" "x86_64-darwin" "x86_64-linux" ] (system: {
        inherit system;
        result = func { inherit system; pkgs = import nixpkgs { inherit system; }; };
      });
    in
    {
      nixosModules.default = ./.;
      # this isn't an officially supported third-party flake output
      # homeManagerModules.default = ./.;
      lib = forEachSystem ({ pkgs, ... }: (import ./. { inherit pkgs; inherit (pkgs) lib; }).config.notlua);
      checks.x86_64-linux.default = let pkgs = nixpkgs.legacyPackages.x86_64-linux; in pkgs.callPackage ./checks.nix {
        flake = (pkgs.callPackage ./. { }).config.notnft;
      };
    };
}
