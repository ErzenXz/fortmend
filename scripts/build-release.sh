#!/bin/sh
set -eu

output=${FORTMEND_DIST_DIR:-dist}
mkdir -p "$output"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  suffix=""
  if [ "$os" = windows ]; then suffix=".exe"; fi
  name="fortmend-${os}-${arch}${suffix}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w" -o "$output/$name" ./cmd/fortmend
done

cp packaging/linux/install.sh "$output/install.sh"
cp packaging/linux/fortmend-protect.service "$output/fortmend-protect.service"
cp packaging/linux/linux.example.json "$output/linux.example.json"
(cd "$output" && shasum -a 256 fortmend-* install.sh linux.example.json) > "$output/SHA256SUMS"
