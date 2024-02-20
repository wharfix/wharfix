# wharfix

Minimal stateless+readonly docker registry based on nix expressions.

Heavily inspired by https://github.com/google/nixery.

## Requirements

You'll need to have Nix installed, see: https://nixos.org/download.html

## Quick start

Checkout this repo and run: `nix develop`.

When in the dev-shell, run: `cargo run -- --repo https://github.com/wharfix/examples.git --port 8080`

This will start a registry serving at localhost port 8080, serving expressions stored in the root of `./examples`.

Images are named after their filenames (without .nix extension).
The image tag is currently ignored.

Try out: `docker run -it localhost:8080/sl:master`

## Integration Testing

If in the Nix devshell, running `just i` will test whether docker is able to pull from wharfix.

## Usage

Wharfix requires that you specify an input from one of:
+ `--path <path>`: Path to directory of static docker image specs.
+ `--repo <repo>`: URL to git repository.
+ `--derivation-output <derivationoutput>`: Output which servable derivations
  need to produce to be valid.

By default, wharfix will start on `0.0.0.0`, port `8088`, but you can specify
another address/port with `--address <address>`, `--port <port>`.

For help, use `-h` or `--help`. For version, `-V` or `--version`.

##### Index File

Wharfix expect a index file, written in nix, to tell wharfix about the images to
serve via the docker registry. By default, it looks for a `default.nix` in the
root directory of the input (repo, path, derivation-output). You can change this
by setting the `--index-file-path <indexfilepath>` option.

<!-- Clarify this -->
`--index-file-is-buildable` can be used to set if the provided index-file is a
valid nix entrypoint by itself (i.e. don't use internal drv-wrapper).

##### Authenticating over SSH

To access ssh authentication based repositories, specify a ssh private key with `--ssh-private-key <sshprivatekey>`.

##### Substituters

To use substituters for internal wharfix calls to `nix-build`, use the `--substituters <substituters>` option to specify a comma-separated list of nix substituters.

##### Blobcache

Wharfix by default stores the docker layer blobs to a directory in `/tmp`. To specify where to store the docker layer blobs, set `--blob-cache-dir <blobcachedir>`.

By default, wharfix does not add nix gcroots to the blobcachedir. You can make it do so by adding the `--add-nix-gcroots` flag.

##### Specify checkout target dir

By default, wharfix will checkout repos to `/tmp/wharfix`. To change this, specify `--target <target>`, where `<target>` is a directory.
