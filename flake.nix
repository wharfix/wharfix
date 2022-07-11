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
    cratePackage = _features: 
    let
      features = lib.naturalSort _features;
      name = if features == ["default"] then pname else "${pname}-${lib.concatStringsSep "-" features}";
    in
    {
      "${name}" = (pkgs.rustBuilder.makePackageSet {
        rustVersion = pkgs.rustc.version;
        packageFun = import ./Cargo.nix;
        rootFeatures = map (f: "${pname}/${f}") features;
      }).workspace.${pname} {};
    };
    outputFeatureSets = [
      ["default"]
      ["mysql"]
    ];
    outputPackages = lib.foldr (a: b: a // b) {} (map cratePackage outputFeatureSets);
  in {
    packages.${system} = outputPackages;
    defaultPackage.${system} = outputPackages.wharfix;

    overlay = final: prev: outputPackages;

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
