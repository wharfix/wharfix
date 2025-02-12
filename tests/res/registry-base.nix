{ pkgs, lib, ... }:
with lib;
let
  indexContent =
    file:
    attrValues (
      filterAttrs (name: _: name != "pkgs") (
        import ../../drv.nix {
          indexFile = import file { inherit pkgs; };
        }
      )
    );
in
{
  # add prebuilt container image servables to the test vm nix stores
  # - to avoid building them during the test run, which would be slow and require internet access
  system.extraDependencies = indexContent ./old-index.nix ++ indexContent ./new-index.nix;
}
