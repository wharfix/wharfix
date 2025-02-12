{
  pkgs ? (import <nixpkgs> { }),
  ...
}:
{
  new-cow = {
    name = "new-cow";
    config.EntryPoint = [ "${pkgs.cowsay}/bin/cowsay new" ];
  };
  kubernetes =
    let
      pinnedSrc = pkgs.fetchurl {
        url = "https://github.com/kubernetes/kubernetes/archive/refs/tags/v1.29.2.tar.gz";
        hash = "sha256-2iYfPYLhtTTbxYW9+WGx650HNQH6Ds9AYxfpUjjQhns=";
      };
    in
    {
      name = "kubernetes";
      contents = [
        (pkgs.runCommandNoCC "kubernetes-src-dir" { nativeBuildInputs = [ pkgs.gzip ]; } ''
          mkdir -p $out/etc
          # uncompress, to get a larger layer
          gunzip -c ${pinnedSrc} > $out/etc/src.tar
        '')
      ];
    };
  nyancat = {
    name = "nyancat";
    config.EntryPoint = [ "${pkgs.nyancat}/bin/nyancat" ];
  };
  inherit pkgs;
}
