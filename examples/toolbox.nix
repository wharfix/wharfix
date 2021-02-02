{ pkgs }: {
  name = "toolbox";
  contents = with pkgs; [
    bashInteractive
    curl
    dnsutils
    gawk
    gnugrep
    htop
    procps
  ];
}
