{
  description = "wharfix";

  inputs = {
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
  };

  outputs = { self, crane, nixpkgs }:
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
            (libssh2.overrideAttrs (oa: {
              # OK, hear me out... I know this is super heavy-handed, and it
              # will hurt if someone tries to actually do signalling while
              # libgit2 (the user of libssh2) is blocked on this poll, but it
              # also has a timeout, so we'll probably survive a bit of delay.
              # The entire shenanigans are precipitated (I think...) by
              # async-process using SIGCHLD to deal with reaping etc. of
              # children, causing EINTR to crop up all the way down here. I
              # will work on a minimal reproducer and figure out a better
              # solution with upstream.
              postPatch = ''
                sed -i 's/rc < 0/rc < 0 \&\& errno != EINTR/' src/session.c
              '';
            }))
          ];
          # system dep controlled via both this env var AND a pkgconfig result.
          # Silently ignores the other if either one isn't there and uses a
          # vendored version. Stahp.
          # https://github.com/alexcrichton/ssh2-rs/issues/173
          LIBSSH2_SYS_USE_PKG_CONFIG = true;
          cargoExtraArgs = final.lib.concatMapStringsSep " " (f: "--features=${f}") features;
        });
    in
      lib.mapAttrs cratePackage outputPackages;

    devShell.${system} = with pkgs; mkShell {
      LIBSSH2_SYS_USE_PKG_CONFIG = true;
      inputsFrom = [ self.defaultPackage.${system} ];
      nativeBuildInputs = [
        cargo
        rustc
        nix
        rustfmt
      ];
    };
  };
}
