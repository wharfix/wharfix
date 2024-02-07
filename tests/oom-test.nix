{
  self,
  nixpkgs ? builtins.fetchTarball "https://github.com/nixOS/nixpkgs/archive/22.05.tar.gz",
  pkgs ? import nixpkgs {},
} : rec {
  examplesRepo = pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
    pname = "examples";
    version = "0";

    src = pkgs.fetchFromGitHub {
      owner = "wharfix";
      repo = "examples";
      rev = "c09ebe2355b69f919f0dd2197d3d4c609fb6fb33";
      hash = "sha256-sKvmqbMvJeLv0vo7kgVBdqSuKsOFdUXsbizlrVwxjlA=";
    };


    dontConfigure = true;
    dontBuild = true;

    installPhase = ''
      runHook preInstall

      mkdir -p $out/
      cp $src $out/repo -r

      runHook postInstall
    '';
  });
  type = "app";
  default = program;
  program = pkgs.nixosTest {
    name = "docker-registry-2";
    meta = with pkgs.lib.maintainers; {
      maintainers = [ globin ironpinguin ];
    };

    nodes = {
      registry = { config, ... }: {
        virtualisation.memorySize = 4096; # 2 G
        virtualisation.diskSize = 100240; # 10 G
        virtualisation.writableStoreUseTmpfs = false;

        environment.etc.nixpkgs.source = builtins.fetchTarball {
          url = "https://github.com/NixOS/nixpkgs/archive/71d7a4c037dc4f3e98d5c4a81b941933cf5bf675.tar.gz";
          sha256 = "sha256:0mz1mrygnpwv87dd0sac32q3m8902ppn9zrkn4wrryljwvvpf60s";
        };
        environment.systemPackages = with pkgs; [
          git
          (pkgs.writeShellScriptBin "make-repo" ''
            # ${pkgs.coreutils}/bin/cp ${self} /etc/repo -r;
            ${pkgs.coreutils}/bin/cp ${examplesRepo}/repo /etc/repo -r;
            cd /etc/repo;
            ${pkgs.git}/bin/git init;
            ${pkgs.git}/bin/git config user.email "example@example.com";
            ${pkgs.git}/bin/git config user.name "test";
            ${pkgs.git}/bin/git remote add origin file:///etc/repo;
            ${pkgs.git}/bin/git add .
            ${pkgs.git}/bin/git commit -m "test";
          '')
          (pkgs.writeShellScriptBin "run-wharfix" ''
            cd /etc/repo/;
            ${pkgs.wharfix}/bin/wharfix --repo file:///etc/repo --port 8080;
          '')
        ];
        systemd.services.wharfix = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          path = [ pkgs.nix ];
          serviceConfig = {
            Environment = "RUST_BACKTRACE=1";
            ExecStartPre = ''/run/current-system/sw/bin/make-repo'';
            ExecStart = ''/run/current-system/sw/bin/run-wharfix'';
          };
        };

        networking.firewall.allowedTCPPorts = [ 8080 ];
      };

      client1 = { ... }: {
        virtualisation.diskSize = 40240; # 10 G
        environment.systemPackages = with pkgs; [
          git
        ];
        virtualisation.docker.enable = true;
        virtualisation.docker.extraOptions = "--insecure-registry registry:8080";
      };
    };

    testScript = ''
          client1.start()
          client1.wait_for_unit("docker.service")

          registry.start()
          registry.wait_for_open_port(8080)
          registry.wait_for_unit("wharfix.service")

          client1.succeed("docker pull registry:8080/hugepkg:master")
          # client1.succeed("docker run -it registry:8080/sl:master")
        '';
  };
}
