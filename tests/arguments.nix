{
  git,
  nix,
  nixosTest,
  runCommandNoCC,
  wharfix,
  indexFileName ? "not-default.nix"
}:
let
  addr = "0.0.0.0";
  port = 5000;
  image = "nyancat";
  blob-cache-dir = "/root";
  target = "/tmp/new-target";
  repo = runCommandNoCC "repo" { nativeBuildInputs = [git]; } ''
    mkdir -p $out
    pushd $out
    git init
    cp ${./res/new-index.nix} $out/${indexFileName}
    git add .
    git config user.email "example@example.com";
    git config user.name "test";
    git commit -m "Initial commit"
  '';
in
nixosTest {
    name = "arguments";

    nodes = {
      registry = { pkgs, ... }: {

        imports = [
          ./res/registry-base.nix
        ];

        # this defaults to 2 in the test framework,
        # but we just want the test to fail on oom,
        # not the vms in reboot loops
        boot.kernel.sysctl."vm.panic_on_oom" = 0;

        environment.systemPackages = [
          git
        ];
        systemd.services.wharfix = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          path = [ nix ];
          environment.NIX_PATH = "nixpkgs=${pkgs.path}";
          serviceConfig = {
            Slice = "wharfix.slice";
            MemoryAccounting = true;
            MemoryMax = "256M";
            Environment = "RUST_BACKTRACE=1";
            ExecStart = ''
              ${wharfix}/bin/wharfix \
                --repo ${repo} \
                --address ${addr} \
                --port ${builtins.toString port} \
                --blob-cache-dir ${blob-cache-dir} \
                --target ${target} \
                --index-file-path ${indexFileName} \
                --add-nix-gcroots
              '';
          };
        };
        systemd.services.wharfix-path = {
          after = [ "network.target" ];
          path = [ nix ];
          environment.NIX_PATH = "nixpkgs=${pkgs.path}";
          serviceConfig = {
            Slice = "wharfix.slice";
            MemoryAccounting = true;
            MemoryMax = "256M";
            Environment = "RUST_BACKTRACE=1";
            ExecStart = ''
              ${wharfix}/bin/wharfix \
                --path ${repo} \
                --address ${addr} \
                --port ${builtins.toString port} \
                --blob-cache-dir ${blob-cache-dir} \
                --target ${target} \
                --index-file-path ${indexFileName} \
                --add-nix-gcroots
              '';
          };
        };

        networking.firewall.allowedTCPPorts = [ port ];
      };

      client = { ... }: {
        virtualisation.docker.enable = true;
        virtualisation.docker.extraOptions = "--insecure-registry registry:${builtins.toString port}";
      };

    };

    testScript = ''
      start_all()

      registry.wait_for_open_port(${builtins.toString port})
      registry.wait_for_unit("wharfix.service")
      client.wait_for_unit("docker.service")

      client.succeed("docker pull registry:${builtins.toString port}/${image}:master")

      # Test --blob-cache-dir
      registry.succeed("stat ${blob-cache-dir}")

      # Test --target
      registry.succeed("stat ${target}")

      # Test --add-nix-gcroots
      registry.succeed("unlink ${blob-cache-dir}/ma/manifest.json")
      registry.fail("unlink ${blob-cache-dir}/ma/manifest.json")

      registry.succeed("systemctl stop wharfix")

      registry.fail("wharfix")
      registry.fail("wharfix --index-file-path really-does-not-exist-${indexFileName} --port ${builtins.toString port}")
      registry.fail("wharfix --index-file-path ${indexFileName} --address 256.256.256.256 --port ${builtins.toString port}")
      registry.fail("wharfix --index-file-path ${indexFileName} --address ${addr} --repo not-a-repository --port ${builtins.toString port}")
      registry.fail("wharfix --index-file-path ${indexFileName} --address ${addr} --repo ${repo} --port not-a-valid-port")
      registry.fail("wharfix --index-file-path ${indexFileName} --address ${addr} --repo ${repo} --port 65536")
      registry.fail("wharfix --index-file-path ${indexFileName} --address ${addr} --repo ${repo} --port ${builtins.toString port} --blob-cache-dir /tmp/does-not-exist")

      # Test --path
      registry.succeed("systemctl start wharfix-path")
      registry.wait_for_unit("wharfix-path.service")
      client.succeed("docker pull registry:${builtins.toString port}/${image}:master")
    '';
}
