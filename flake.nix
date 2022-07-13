{
  description = "wharfix";

  inputs = {
    cargo2nix.url = "github:cargo2nix/cargo2nix";
    cargo2nix.inputs.nixpkgs.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
  };

  outputs = { self, cargo2nix, nixpkgs }:
  let
    pname = "wharfix";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlay cargo2nix.overlays.default ];
    };
    lib = nixpkgs.lib;

    outputPackages = {
      "${pname}" = ["default"];
      "${pname}-mysql" = ["mysql"];
    };
  in {
    packages.${system} = lib.mapAttrs (n: _: pkgs.${n}) outputPackages;
    defaultPackage.${system} = pkgs.${pname};

    overlay = final: prev:
    let
      cratePackage = name: features:
        (final.rustBuilder.makePackageSet {
          rustVersion = final.rustc.version;
          packageFun = import ./Cargo.nix;
          rootFeatures = map (f: "${pname}/${f}") features;
        }).workspace.${pname} {};
    in
      lib.mapAttrs cratePackage outputPackages;

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        cargo
        cargo2nix.packages.${system}.cargo2nix
        nix
        openssl.dev
        pkgconfig
        rustc
        rustfmt
        zlib.dev
      ];
    };
  };
}
