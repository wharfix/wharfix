{
  git,
  nix,
  nixosTest,
  wharfix,
  writeShellScriptBin,
}:
let
  port = 8080;
  repoPath = "/var/repo";

  pullImageSucceed = pullImage "succeed";
  pullImageFail = pullImage "fail";

  pullImage =
    action: name: tag:
    ''client.${action}("docker pull registry:${toString port}/${name}:${tag}")'';
in
nixosTest {
  name = "ref-test";

  nodes = {
    registry =
      { pkgs, ... }:
      {

        imports = [
          ./res/registry-base.nix
        ];

        environment.systemPackages = [
          git
        ];

        systemd.services.repo-setup = {
          before = [ "wharfix.service" ];
          requiredBy = [ "wharfix.service" ];
          path = [ git ];
          serviceConfig.Type = "oneshot";
          script = ''
            mkdir ${repoPath}
            pushd ${repoPath}
            git init
            git add .
            git config user.email "example@example.com";
            git config user.name "test";
            cp ${./res/old-index.nix} default.nix
            cp ${./res/new-index.nix} new-index.nix
            git add .
            git commit -m "Initial commit"
          '';
        };

        systemd.services.wharfix = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          path = [
            git
            nix
          ];
          environment.NIX_PATH = "nixpkgs=${pkgs.path}";
          serviceConfig = {
            ExecStart = ''
              ${wharfix}/bin/wharfix \
                          --port ${toString port} \
                          --repo ${repoPath}'';
          };
        };

        networking.firewall.allowedTCPPorts = [ port ];
      };

    client =
      { ... }:
      {
        environment.systemPackages = [
          (writeShellScriptBin "pull-tag-from-file" ''
            set -euo pipefail
            IMAGE="$1"
            TAG="$(cat $2)"
            docker pull registry:${toString port}/$IMAGE:$TAG
          '')
        ];

        virtualisation.docker.enable = true;
        virtualisation.docker.extraOptions = "--insecure-registry registry:${toString port}";
      };
  };

  testScript = ''
    start_all()

    client.wait_for_unit("docker.service")
    registry.wait_for_unit("wharfix.service")
    registry.wait_for_open_port(${toString port})

    ${pullImageSucceed "old-cow" "master"}
    ${pullImageFail "new-cow" "master"}

    registry.succeed("pushd ${repoPath} && git mv -f new-index.nix default.nix && git commit -am enabled-new-index")
    ${pullImageFail "old-cow" "master"}
    ${pullImageSucceed "new-cow" "master"}

    registry.succeed("pushd ${repoPath} && git rev-parse master > /tmp/shared/new.rev")
    registry.succeed("pushd ${repoPath} && git rev-parse master~1 > /tmp/shared/old.rev")
    client.wait_for_file("/tmp/shared/old.rev")
    client.wait_for_file("/tmp/shared/new.rev")

    client.succeed("/run/current-system/sw/bin/pull-tag-from-file old-cow /tmp/shared/old.rev")
    client.succeed("/run/current-system/sw/bin/pull-tag-from-file new-cow /tmp/shared/new.rev")
    client.fail("/run/current-system/sw/bin/pull-tag-from-file new-cow /tmp/shared/old.rev")
    client.fail("/run/current-system/sw/bin/pull-tag-from-file old-cow /tmp/shared/new.rev")
  '';
}
