{
  pkgs ? (import <nixpkgs> { }),
  ...
}:
{
  old-cow = {
    name = "old-cow";
    config.EntryPoint = [ "${pkgs.cowsay}/bin/cowsay old" ];
  };
  inherit pkgs;
}
