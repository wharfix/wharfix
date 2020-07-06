{ specFile }:
let
  pkgs = import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/581937d380aca9a3455687999f1bf14729278356.tar.gz";
    sha256 = "0q7mj91qf84mnffvqxbfkfq5d0z66q151c9869y0f1sq74zbddvm";
  }) {};
  spec = import specFile { inherit pkgs; };
in
pkgs.runCommand "${spec.name}-servable" { buildInputs = [pkgs.jq]; } ''
  mkdir -p $out/raw $out/blobs
  pushd $out/raw
  ${pkgs.dockerTools.streamLayeredImage spec} | tar -xf -
  popd

  CONF="$(cat $out/raw/manifest.json | jq -r '.[].Config')"
  CONFSIZE="$(wc -c $out/raw/$CONF | awk '{ print $1 }')"
  CONFSUM="$(sha256sum $out/raw/$CONF | awk '{ print $1 }')"
  cp $out/raw/$CONF $out
  ln -s "$out/$CONF" "$out/blobs/$CONFSUM.json"

  MANIFESTJSON='{ "schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"'
  MANIFESTJSON="$MANIFESTJSON, "'"config": { "mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:'"$CONFSUM"'", "size": '"$CONFSIZE"' }, "layers": [] }'

  for L in $(cat $out/raw/manifest.json |jq -r '.[].Layers[]'); do
    OUTNAME="$(dirname $L)"
    OUTFILE="$out/raw/$OUTNAME.tar"
    cp "$out/raw/$L" $OUTFILE
    OUTSIZE="$(wc -c $OUTFILE | awk '{ print $1 }')"
    ln -s "$OUTFILE" "$out/blobs/$OUTNAME.tar"
    MANIFESTJSON=$(echo "$MANIFESTJSON" | jq '.layers += [{ "mediaType": "application/vnd.docker.image.rootfs.diff.tar", "digest": "sha256:'"$OUTNAME"'", "size": '"$OUTSIZE"' }]')
  done
  echo "$MANIFESTJSON" >$out/manifest.json
''
