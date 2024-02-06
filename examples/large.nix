{ pkgs }: 
let 
  fakepkg = pkgs.runCommand "fakepkg" {} ''
    mkdir -p $out/share;
    dd if=/dev/urandom of=$out/share/myfile bs=1M count=4000
  '';
in
  {
    name = "large";
    config.EntryPoint = [ "${pkgs.sl}/bin/sl" ];
  }

