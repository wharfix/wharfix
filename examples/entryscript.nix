{ pkgs }: {
  name = "entryscript";
  config.EntryPoint = [(pkgs.writeShellScript "entry.sh" ''
    echo Hello, Entrypoint reached, sleeping ...
    ${pkgs.coreutils}/bin/sleep 5
  '')];
}
