{
  self,
  nixpkgs ? builtins.fetchTarball "https://github.com/nixOS/nixpkgs/archive/22.05.tar.gz",
  pkgs ? import nixpkgs {},
} : rec {
  repo = pkgs.runCommandNoCC "repo" { nativeBuildInputs = [pkgs.git]; } ''
    mkdir -p $out
    pushd $out
    git init
    cp ${./res/new-index.nix} $out/default.nix
    git add .
    git config user.email "example@example.com";
    git config user.name "test";
    git commit -m "Initial commit"
  '';
  type = "app";
  default = program;
  program = pkgs.nixosTest {
    name = "oom-test";

    nodes = {
      registry = { config, ... }: {
        virtualisation.memorySize = 4096;
        virtualisation.diskSize = 100240;
        virtualisation.writableStoreUseTmpfs = false;

        # this defaults to 2 in the test framework,
        # but we just want the test to fail on oom,
        # not the vms in reboot loops
        boot.kernel.sysctl."vm.panic_on_oom" = 0;

        environment.systemPackages = with pkgs; [
          git
        ];
        systemd.services.wharfix = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          path = [ pkgs.nix ];
          environment.NIX_PATH = "nixpkgs=${pkgs.path}";
          serviceConfig = {
            Slice = "wharfix.slice";
            MemoryAccounting = true;
            MemoryMax = "256M";
            Environment = "RUST_BACKTRACE=1";
            ExecStart = ''${pkgs.wharfix}/bin/wharfix --repo ${repo} --port 8080'';
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
          start_all()

          client1.wait_for_unit("docker.service")
          registry.wait_for_open_port(8080)
          registry.wait_for_unit("wharfix.service")

          client1.succeed("docker pull registry:8080/kubernetes:master")
        '';
  };
}
