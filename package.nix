{ stdenv, lib, gcc, rustPlatform, openssl, pkgconfig }:

rustPlatform.buildRustPackage {
  pname = "wharfix";
  version = "dev";
  src = builtins.filterSource
    (path: type: baseNameOf path != "result" || baseNameOf path != ".git" || baseNameOf path != "target")
    ./.;

  cargoSha256 = "1gii94qgi1sz1zjxqk2igiri9hrcyygm16ambzd66nis40r3fd51";

  nativeBuildInputs = [ gcc pkgconfig ];
  buildInputs = [ openssl.dev ];
  OPENSSL_LIB_DIR = openssl.dev;

  meta = with stdenv.lib; {
    description = "Minimal stateless+readonly docker registry based on nix expressions";
    homepage = https://github.com/johanot/wharfix;
    license = licenses.mit;
  };
}
