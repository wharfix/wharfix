alias i := integration-tests
alias d := debug-vm-tests

non-nix-integration-tests:
    # #!/usr/bin/env fish
    docker rmi localhost:8080/sl:master --force || true
    cargo build; cargo run -- --repo https://github.com/wharfix/examples.git --port 8080 &
    sleep 5
    -docker run -it localhost:8080/sl:master
    pkill wharfix
    @echo "if you saw a train then wharfix is working as expected :)"

integration-tests:
    nix flake check -L --impure --option sandbox false

debug-vm-tests:
    nix build .#checks.x86_64-linux.default.driverInteractive
    ./result/bin/nixos-test-driver --interactive
