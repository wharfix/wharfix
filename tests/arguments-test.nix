# Arguments tests
#
# This is where we attempt to tests all the various functionality of wharfix,
# that a *normal* enterprise user is expected to encounter. This also includes
# trying to test most of the arguments we support.
#
# Some tests of more specific, fragile features, like streaming of blob layers
# should be put in their own test files, where more specific memory restrictions
# might e.g. be added. This exists only for the general case.
#
# This tests is expected to be run outside of the sandbox for now, due to the
# architecture of wharfix, packaging all dependencies so we don't have to reach
# for the network is non-trivial.
#
# Usage:
#
# To run this test from the wharfix root dir, use:
#
# ```
# nix build -L --impure --option sandbox false ./#apps.x86_64-linux.arguments-test.program
# ```
#
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

  ## gpg --faked-system-time='20230301T010000!' --quick-generate-key snakeoil ed25519 sign
  signingPrivateKey = ''
    -----BEGIN PGP PRIVATE KEY BLOCK-----

    lFgEY/6jkBYJKwYBBAHaRw8BAQdADXiZRV8RJUyC9g0LH04wLMaJL9WTc+szbMi7
    5fw4yP8AAQCl8EwGfzSLm/P6fCBfA3I9znFb3MEHGCCJhJ6VtKYyRw7ktAhzbmFr
    ZW9pbIiUBBMWCgA8FiEE+wUM6VW/NLtAdSixTWQt6LZ4x50FAmP+o5ACGwMFCQPC
    ZwAECwkIBwQVCgkIBRYCAwEAAh4FAheAAAoJEE1kLei2eMedFTgBAKQs1oGFZrCI
    TZP42hmBTKxGAI1wg7VSdDEWTZxut/2JAQDGgo2sa4VHMfj0aqYGxrIwfP2B7JHO
    GCqGCRf9O/hzBA==
    =9Uy3
    -----END PGP PRIVATE KEY BLOCK-----
  '';
  signingPrivateKeyId = "4D642DE8B678C79D";

  # This is just to make `nix flake` commands happy that this is indeed a valid
  # `app` output.
  type = "app";
  default = { program = program; type = "app"; };

  program = pkgs.nixosTest {
    name = "arguments-test";
    nodes = {
      # This is the git forge, forgejo. We use it, for amongst many reasons, to
      # test if we can pull from a remote repository that's a "real forge", and
      # so we can try to do SSH auth with wharfix.
      forgejo = { config, pkgs, ... }: {
        virtualisation.memorySize = 2047;
        services.forgejo = {
          enable = true;
          database.type = "sqlite3";
          settings.service.DISABLE_REGISTRATION = true;
          settings."repository.signing".SIGNING_KEY = signingPrivateKeyId;
          settings.actions.ENABLED = true;
        };
        environment.systemPackages = [ config.services.forgejo.package pkgs.gnupg pkgs.jq pkgs.file ];
        services.openssh.enable = true;

        specialisation.runner = {
          inheritParentConfig = true;
          configuration.services.gitea-actions-runner.instances."test" = {
            enable = true;
            name = "ci";
            url = "http://localhost:3000";
            labels = [
              # don't require docker/podman
              "native:host"
            ];
            tokenFile = "/var/lib/forgejo/runner_token";
          };
        };
        specialisation.dump = {
          inheritParentConfig = true;
          configuration.services.forgejo.dump = {
            enable = true;
            type = "tar.zst";
            file = "dump.tar.zst";
          };
        };
      };

      # This is the wharfix registry.
      wharfix = { config, ... }: {
        virtualisation.memorySize = 4096;
        virtualisation.diskSize = 100240;
        virtualisation.writableStoreUseTmpfs = false;

        environment.systemPackages = with pkgs; [
          git
          wharfix
          (pkgs.writeShellScriptBin "run-wharfix" ''
            ${pkgs.wharfix}/bin/wharfix \
              --repo $1 \
              --port 8080 \
              --address 0.0.0.0 \
              --index-file-path default.nix \
              --blob-cache-dir /root/ \
              --add-nix-gcroots \
              --ssh-private-key $HOME/.ssh/privk \
              --target /tmp/wharfix;
          '')
        ];
        # systemd.services.wharfix = {
        #   wantedBy = [ "multi-user.target" ];
        #   after = [ "network.target" ];
        #   path = [ pkgs.nix ];
        #   serviceConfig = {
        #     Environment = "RUST_BACKTRACE=1";
        #     ExecStartPre = ''/run/current-system/sw/bin/make-repo'';
        #     ExecStart = ''/run/current-system/sw/bin/run-wharfix'';
        #   };
        # };

        networking.firewall.allowedTCPPorts = [ 8080 ];
      };

      # This client is the one that's gonna pull down the image from wharfix.
      client1 = { config, pkgs, ... }: {
        environment.systemPackages = [ pkgs.git ];
        virtualisation.docker.enable = true;
        virtualisation.docker.extraOptions = "--insecure-registry wharfix:8080";
      };

      # This machines sole job is to create the repo for wharfix to use as a
      # remote.
      repo_maker = { config, pkgs, ... }: {
        environment.systemPackages = with pkgs; [
          git
        ];
        virtualisation.docker.enable = true;
        virtualisation.docker.extraOptions = "--insecure-registry wharfix:8080";
      };
    };

    testScript = {nodes, ...}:
      let
        inherit (import ./ssh-keys.nix pkgs) snakeOilPrivateKey snakeOilPublicKey;
        serverSystem = nodes.server.system.build.toplevel;
        dumpFile = with nodes.server.specialisation.dump.configuration.services.forgejo.dump; "${backupDir}/${file}";
      in
        ''
          start_all()

          GIT_SSH_COMMAND = "ssh -i $HOME/.ssh/privk -o StrictHostKeyChecking=no"
          REPO = "forgejo@forgejo:test/examples"
          PRIVK = "${snakeOilPrivateKey}"

          forgejo.wait_for_unit("forgejo.service")
          forgejo.wait_for_open_port(3000)
          forgejo.wait_for_open_port(22)
          forgejo.succeed("curl --fail http://localhost:3000/")

          forgejo.succeed(
              "su -l forgejo -c 'gpg --homedir /var/lib/forgejo/data/home/.gnupg "
              + "--import ${toString (pkgs.writeText "forgejo.key" signingPrivateKey)}'"
          )

          assert "BEGIN PGP PUBLIC KEY BLOCK" in forgejo.succeed("curl http://localhost:3000/api/v1/signing-key.gpg")

          forgejo.succeed(
              "curl --fail http://localhost:3000/user/sign_up | grep 'Registration is disabled. "
              + "Please contact your site administrator.'"
          )
          forgejo.succeed(
              "su -l forgejo -c 'GITEA_WORK_DIR=/var/lib/forgejo gitea admin user create "
              + "--username test --password totallysafe --email test@localhost'"
          )

          api_token = forgejo.succeed(
              "curl --fail -X POST http://test:totallysafe@localhost:3000/api/v1/users/test/tokens "
              + "-H 'Accept: application/json' -H 'Content-Type: application/json' -d "
              + "'{\"name\":\"token\",\"scopes\":[\"all\"]}' | jq '.sha1' | xargs echo -n"
          )

          forgejo.succeed(
              "curl --fail -X POST http://localhost:3000/api/v1/user/repos "
              + "-H 'Accept: application/json' -H 'Content-Type: application/json' "
              + f"-H 'Authorization: token {api_token}'"
              + ' -d \'{"auto_init":false, "description":"string", "license":"mit", "name":"examples", "private":false}\'''
          )

          forgejo.succeed(
              "curl --fail -X POST http://localhost:3000/api/v1/user/keys "
              + "-H 'Accept: application/json' -H 'Content-Type: application/json' "
              + f"-H 'Authorization: token {api_token}'"
              + ' -d \'{"key":"${snakeOilPublicKey}","read_only":true,"title":"SSH"}\'''
          )

          client1.wait_for_unit("docker.service")

          repo_maker.wait_for_unit("network.target")

          client1.succeed("mkdir -p $HOME/.ssh")
          client1.succeed(f"cat {PRIVK} > $HOME/.ssh/privk")
          client1.succeed("chmod 0400 $HOME/.ssh/privk")
          client1.succeed("git config --global user.email test@localhost")
          client1.succeed("git config --global user.name test")

          repo_maker.succeed("mkdir -p $HOME/.ssh")
          repo_maker.succeed(f"cat {PRIVK} > $HOME/.ssh/privk")
          repo_maker.succeed("chmod 0400 $HOME/.ssh/privk")

          repo_maker.succeed("git config --global user.email test@localhost")
          repo_maker.succeed("git config --global user.name test")

          repo_maker.succeed("git clone https://github.com/wharfix/examples.git /tmp/examples")
          repo_maker.succeed(f"git -C /tmp/examples remote set-url origin {REPO}")

          repo_maker.succeed(
            f"GIT_SSH_COMMAND='{GIT_SSH_COMMAND}' git -C /tmp/examples push origin master"
          )

          wharfix.wait_for_unit("network.target")

          wharfix.succeed("mkdir -p $HOME/.ssh")
          wharfix.succeed(f"cat {PRIVK} > $HOME/.ssh/privk")
          wharfix.succeed("chmod 0400 $HOME/.ssh/privk")
          wharfix.succeed("git config --global user.email test@localhost")
          wharfix.succeed("git config --global user.name test")

          wharfix.execute(
            "wharfix"
            + " --repo {REPO}"
            + " --port 8080"
            + " --address 0.0.0.0"
            + " --index-file-path default.nix"
            + " --blob-cache-dir /root/"
            + " --add-nix-gcroots"
            + " --ssh-private-key $HOME/.ssh/privk"
            + " --target /tmp/wharfix"
            + ""
          )
          # wharfix.wait_for_open_port(8080)

          # wharfix.wait_for_unit("wharfix.service")

          client1.succeed("docker pull wharfix:8080/sl:master")
        '';
  };
}
