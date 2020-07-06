{ pkgs ? (import <nixpkgs> {}) }:
  pkgs.mkShell {
    buildInputs = with pkgs; [
      gcc
      pkgconfig
      openssl.dev
      zlib.dev
      cargo
      rustc
    ];
  }
