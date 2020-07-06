{ pkgs }: {
  name = "sl";
  config.EntryPoint = [ "${pkgs.sl}/bin/sl" ];
}
