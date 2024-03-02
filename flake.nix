{
  description = "wharfix";

  inputs = {
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    utils.url = "github:numtide/flake-utils";
    wharfixNonStreaming.url = "github:wharfix/wharfix/1f71fcafbc9caed5fa5d38f01598aaadb6176e08";
  };

  outputs = { self, crane, nixpkgs, utils, wharfixNonStreaming }:
  let
    pname = "wharfix";
    crane-overlay = final: prev: {
      # crane's lib is not exposed as an overlay in its flake (should be added
      # upstream ideally) so this interface might be brittle, but avoids
      # accidentally passing a detached nixpkgs from its flake (or its follows)
      # on to consumers.
      craneLib = crane.mkLib prev;
    };
    lib = nixpkgs.lib;

    outputPackages = {
      "${pname}" = [];
      "${pname}-mysql" = ["mysql"];
    };
  in utils.lib.eachDefaultSystem (system:
  let
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlay.${system} crane-overlay ];
    };
  in {
    packages = lib.mapAttrs (n: _: pkgs.${n}) outputPackages;
    defaultPackage = pkgs.${pname};
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

    devShell = with pkgs; mkShell {
      inputsFrom = [ self.defaultPackage.${system} ];
      nativeBuildInputs = [
        cargo
        rustc
        nix
        rustfmt
        just
      ];
    };

    checks = {
      oom-positive = pkgs.callPackage ./tests/oom.nix {};
      oom-negative = pkgs.callPackage ./tests/oom.nix {
        expectedResult = "fail";
        wharfix = wharfixNonStreaming.defaultPackage.x86_64-linux;
      };
      ref = pkgs.callPackage ./tests/ref.nix {};
      arguments = pkgs.callPackage ./tests/arguments.nix {};
    };
  });
}
