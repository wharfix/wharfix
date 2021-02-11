{ indexFile }:
let
  _index = import indexFile;
  index = if builtins.isFunction _index then _index {} else _index;
  pkgs = index.pkgs or (import <nixpkgs> {});
  drv = spec: pkgs.runCommand "${spec.name}-servable" { buildInputs = [pkgs.jq]; } ''
    mkdir -p $out/raw $out/blobs
    pushd $out/raw
    ${pkgs.dockerTools.streamLayeredImage spec} | tar -xf -
    popd

    CONF="$(cat $out/raw/manifest.json | jq -r '.[].Config')"
    cat "$out/raw/$CONF" | jq -SMc >$out/$CONF
    CONFSIZE="$(wc -c "$out/$CONF" | awk '{ print $1 }')"
    CONFSUM="$(sha256sum "$out/$CONF" | awk '{ print $1 }')"
    ln -s "$out/$CONF" "$out/blobs/$CONFSUM.configjson"

    MANIFESTJSON='{ "schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"'
    MANIFESTJSON="$MANIFESTJSON, "'"config": { "mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:'"$CONFSUM"'", "size": '"$CONFSIZE"' }, "layers": [] }'

    for L in $(cat $out/raw/manifest.json |jq -r '.[].Layers[]'); do
      OUTNAME="$(dirname $L)"
      OUTSIZE="$(wc -c $out/raw/$L | awk '{ print $1 }')"
      ln -s "$out/raw/$L" "$out/blobs/$OUTNAME.difftar"
      MANIFESTJSON=$(echo "$MANIFESTJSON" | jq '.layers += [{ "mediaType": "application/vnd.docker.image.rootfs.diff.tar", "digest": "sha256:'"$OUTNAME"'", "size": '"$OUTSIZE"' }]')
    done
    echo "$MANIFESTJSON" | jq -SMc >$out/manifest.json

    # add detached digest of finished manifest (for introspection)
    MANIFESTSUM=$(sha256sum "$out/manifest.json" | awk '{ print $1 }')
    echo $MANIFESTSUM >$out/manifest.json.sha256
    ln -s "$out/manifest.json" "$out/blobs/$MANIFESTSUM.manifestjson"
 '';
in
  pkgs.lib.mapAttrs (_: v: drv v) index
