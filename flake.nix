{
  description = "wharfix";

  inputs = {
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, crane, nixpkgs}:
  let
    pname = "wharfix";
    system = "x86_64-linux";
    crane-overlay = final: prev: {
      # crane's lib is not exposed as an overlay in its flake (should be added
      # upstream ideally) so this interface might be brittle, but avoids
      # accidentally passing a detached nixpkgs from its flake (or its follows)
      # on to consumers.
      craneLib = crane.mkLib prev;
    };
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlay crane-overlay ];
    };
    lib = nixpkgs.lib;

    outputPackages = {
      "${pname}" = [];
      "${pname}-mysql" = ["mysql"];
    };
  in {
    packages.${system} = lib.mapAttrs (n: _: pkgs.${n}) outputPackages;
    defaultPackage.${system} = pkgs.${pname};
    overlay = final: prev:
    let
      cratePackage = name: features:
        (final.craneLib.buildPackage {
          src = with final; lib.cleanSourceWith {
            src = ./.;
            filter = let
              # Default cleaner nukes everything but rust/cargo relevant files,
              # and we need this in the source tree to embed it.
              drvnix = path: _type: builtins.match ".*/drv.nix" path != null;
            in
              path: type: craneLib.filterCargoSources path type || drvnix path type;
          };
          nativeBuildInputs = with final; [
            pkg-config
          ];
          buildInputs = with final; [
            openssl
          ];
          cargoExtraArgs = final.lib.concatMapStringsSep " " (f: "--features=${f}") features;
        });
    in
      lib.mapAttrs cratePackage outputPackages;

    apps."x86_64-linux" = {
      oom-test =
        let
          inherit pkgs;
          inherit nixpkgs;
          wharfix = self.packages.default;
        in
          (import ./tests/oom-test.nix { inherit self; inherit pkgs; inherit nixpkgs; }).default;
    };

    devShell.${system} = with pkgs; mkShell {
      inputsFrom = [ self.defaultPackage.${system} ];
      nativeBuildInputs = [
        nix
        rustfmt
        just
        cargo
        rustc
      ];
    };

    checks."x86_64-linux" = {
      default = self.apps."x86_64-linux".oom-test;
    };
  };
}
