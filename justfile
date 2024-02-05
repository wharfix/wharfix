alias i := integration-tests

integration-tests:
    # #!/usr/bin/env fish
    docker rmi localhost:8080/sl:master --force || true
    cargo build; cargo run -- --repo https://github.com/wharfix/examples.git --port 8080 &
    sleep 5
    -docker run -it localhost:8080/sl:master
    pkill wharfix
    @echo "if you saw a train then wharfix is working as expected :)"

