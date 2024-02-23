{ pkgs ? (import <nixpkgs> {}), ... }: {
  new-cow = {
    name = "new-cow";
    config.EntryPoint = [ "${pkgs.cowsay}/bin/cowsay new" ];
  };
  inherit pkgs;
}
