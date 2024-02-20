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
  default = { program = program; type = "app"; };
  program = pkgs.nixosTest {
    name = "oom-test";

    nodes = {
      registry = { config, ... }: {
        virtualisation.memorySize = 4096;
        virtualisation.diskSize = 100240;
        virtualisation.writableStoreUseTmpfs = false;

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
            ${pkgs.wharfix}/bin/wharfix --repo file:///etc/repo --port 8080 --address 0.0.0.0 --index-file-path default.nix --blob-cache-dir /root/ --add-nix-gcroots --target /tmp/wharfix;
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
        virtualisation.diskSize = 40240;
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

          client1.succeed("docker pull registry:8080/nyancat:master")
        '';
  };
}
