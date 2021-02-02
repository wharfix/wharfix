let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs {};
  crate2nix = pkgs.callPackage (import sources.crate2nix) {};
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    pkgconfig
    openssl.dev
    zlib.dev
    cargo
    rustc
    crate2nix
    nix
    niv
  ];
}
