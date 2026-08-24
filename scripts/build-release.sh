#!/bin/sh
set -eu

output=${AEGIS_DIST_DIR:-dist}
mkdir -p "$output"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  suffix=""
  if [ "$os" = windows ]; then suffix=".exe"; fi
  name="aegis_${os}_${arch}${suffix}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w" -o "$output/$name" ./cmd/aegis
done

(cd "$output" && shasum -a 256 aegis_*) > "$output/checksums.txt"
