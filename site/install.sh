#!/bin/sh
set -eu

repository="ErzenXz/aegis"
release_base="https://github.com/$repository/releases/latest/download"

case "$(uname -s)" in
  Linux) platform="linux" ;;
  Darwin) platform="darwin" ;;
  *) echo "Aegis supports this installer on Linux and macOS. On Windows, use install.ps1." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) architecture="amd64" ;;
  arm64|aarch64) architecture="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="aegis_${platform}_${architecture}"
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/aegis-install.XXXXXX")
cleanup() { rm -f "$temporary_directory/$asset" "$temporary_directory/checksums.txt"; rmdir "$temporary_directory" 2>/dev/null || true; }
trap cleanup EXIT HUP INT TERM

echo "Downloading Aegis for $platform/$architecture..."
curl -fsSL "$release_base/$asset" -o "$temporary_directory/$asset"
curl -fsSL "$release_base/checksums.txt" -o "$temporary_directory/checksums.txt"

expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$temporary_directory/checksums.txt")
if [ -z "$expected" ]; then
  echo "Release checksum for $asset is missing." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$temporary_directory/$asset" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$temporary_directory/$asset" | awk '{print $1}')
fi
if [ "$actual" != "$expected" ]; then
  echo "Aegis download checksum did not match." >&2
  exit 1
fi

install_directory=${AEGIS_INSTALL_DIR:-/usr/local/bin}
if [ ! -d "$install_directory" ] || [ ! -w "$install_directory" ]; then
  install_directory="$HOME/.local/bin"
  mkdir -p "$install_directory"
fi
install -m 0755 "$temporary_directory/$asset" "$install_directory/aegis"

echo "Installed Aegis at $install_directory/aegis"
case ":$PATH:" in
  *":$install_directory:"*) ;;
  *) echo "Add $install_directory to PATH to run aegis directly." ;;
esac

if [ "$#" -gt 0 ]; then
  exec "$install_directory/aegis" onboard "$@"
fi
if { : </dev/tty; } 2>/dev/null; then
  exec "$install_directory/aegis" onboard "$@" </dev/tty
fi
echo "Run: $install_directory/aegis onboard"
