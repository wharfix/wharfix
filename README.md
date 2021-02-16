# wharfix

Minimal stateless+readonly docker registry based on nix expressions.

Heavily inspired by https://github.com/google/nixery.

## Requirements

You'll need to have Nix installed, see: https://nixos.org/download.html

## Quick start

Checkout this repo and run: `nix-shell --run 'cargo run -- --repo https://github.com/wharfix/examples.git --port 8080'`

This will start a registry serving at localhost port 8080, serving expressions stored in the root of `./examples`.

Images are named after their filenames (without .nix extension).
The image tag is currently ignored.

Try out: `docker run -it localhost:8080/sl:master`
