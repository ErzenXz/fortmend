#!/bin/sh
# Fortmend v0.2.0-preview.1 bootstrap. Run inside the VM you want to protect.
# Release files are SHA-256 checked; Codex has separately pinned upstream hashes.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
release=v0.2.0-preview.1
base="https://github.com/ErzenXz/fortmend/releases/download/$release"
codex_version=rust-v0.163.0
no_start=false
retain_legacy_state=false
policy=
fail() { echo "Fortmend install: $*" >&2; exit 1; }
usage() { echo 'Usage: sudo sh install.sh [--no-start] [--retain-legacy-state] [--policy /path/to/reviewed.json]' >&2; exit 2; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --retain-legacy-state) retain_legacy_state=true; shift ;;
        --no-start) no_start=true; shift ;;
        --policy) [ "$#" -ge 2 ] || usage; policy=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ "$(uname -s)" = Linux ] || fail 'run inside an Ubuntu/Debian VM (not on your Mac)'
[ "$(id -u)" = 0 ] || fail 'run with sudo'
case "$(uname -m)" in
    x86_64|amd64) arch=amd64; codex_target=x86_64-unknown-linux-musl; codex_hash=beb339e8ecd9ba057a6bb2dc81ad8ca474812edfbf0fc5056ca818797648dde4 ;;
    aarch64|arm64) arch=arm64; codex_target=aarch64-unknown-linux-musl; codex_hash=a7261e65f4a96d8f4ca65a069c6cf2dc2c33defc341e48078acefda9461fffe4 ;;
    *) fail 'supported architectures: amd64 and arm64' ;;
esac
[ -f /etc/os-release ] || fail 'missing /etc/os-release'
distro=$(sed -n 's/^ID=//p' /etc/os-release | tr -d "\"'")
case "$distro" in ubuntu|debian) ;; *) fail 'only Ubuntu and Debian are supported' ;; esac
[ -d /run/systemd/system ] || fail 'systemd must be running; containers are not supported'
[ ! -e /etc/aegis/linux.json ] && [ ! -e /etc/systemd/system/aegis-protect.service ] || fail 'legacy Aegis installation detected; see https://github.com/ErzenXz/fortmend/blob/main/docs/LINUX.md#moving-from-aegis'
if [ -e /var/lib/aegis ]; then
    [ "$retain_legacy_state" = true ] && [ -f /etc/fortmend/linux.json ] || fail 'legacy Aegis state detected; migrate policy first, then explicitly pass --retain-legacy-state (see docs/LINUX.md#moving-from-aegis)'
fi
if [ "$retain_legacy_state" = true ]; then
    [ -f /etc/fortmend/linux.json ] || fail '--retain-legacy-state requires an existing /etc/fortmend/linux.json'
fi
[ -z "$policy" ] || [ -f "$policy" ] || fail '--policy must name an existing JSON file'
# Reject replaceable ancestors before privileged writes. No caller-supplied PATH,
# download mirror, temporary directory or installation prefix is accepted.
secure_ancestors() {
    path=$1
    while :; do
        [ ! -L "$path" ] || fail "symlinked installation path: $path"
        if [ -e "$path" ]; then
            [ -d "$path" ] || fail "installation ancestor is not a directory: $path"
            [ "$(stat -c %u -- "$path")" = 0 ] || fail "installation ancestor must be root owned: $path"
            mode=$(stat -c %a -- "$path")
            [ "$((0$mode & 0022))" = 0 ] || fail "installation ancestor is writable by another user: $path"
        fi
        [ "$path" != / ] || break
        path=$(dirname -- "$path")
    done
}
for directory in /usr/local/bin /usr/local/lib/fortmend /etc/fortmend /var/lib/fortmend /etc/systemd/system; do
    secure_ancestors "$directory"
done
command -v curl >/dev/null 2>&1 || fail 'curl is required; run sudo apt-get update && sudo apt-get install -y curl ca-certificates first'
temporary_directory=$(mktemp -d /tmp/fortmend-install.XXXXXXXX)
service_stopped=false
completed=false
codex_tmp=
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$temporary_directory"
    [ -z "$codex_tmp" ] || rm -f -- "$codex_tmp"
    if [ "$completed" != true ] && [ "$service_stopped" = true ]; then
        echo 'Fortmend remains stopped because installation did not complete. Resolve the error, then rerun this installer.' >&2
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
fetch() { curl --proto '=https' --tlsv1.2 -fSL --retry 3 --connect-timeout 15 --max-time 600 "$1" -o "$2"; }
verify_release() {
    name=$1
    expected=$(awk -v name="$name" '$2 == name { count++; hash=$1 } END { if (count == 1) print hash }' "$temporary_directory/SHA256SUMS")
    [ "${#expected}" = 64 ] || fail "missing or duplicate checksum for $name"
    case "$expected" in *[!0-9a-f]*) fail "invalid checksum for $name" ;; esac
    actual=$(sha256sum "$temporary_directory/$name" | cut -d ' ' -f 1)
    [ "$actual" = "$expected" ] || fail "checksum mismatch: $name"
}
echo "Installing Fortmend $release for $distro/$arch."
echo 'Full-control AI can repair files and execute commands as root. Keep a tested VM backup.'
fetch "$base/SHA256SUMS" "$temporary_directory/SHA256SUMS"
for asset in "fortmend-linux-$arch" install.sh fortmend-protect.service linux.example.json; do
    fetch "$base/$asset" "$temporary_directory/$asset"
    verify_release "$asset"
done
# Bootstrap only required distro packages through authenticated APT. This does
# not perform a release upgrade or broad apt upgrade.
apt-get -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false update
DEBIAN_FRONTEND=noninteractive apt-get -o APT::Get::AllowUnauthenticated=false install -y --no-install-recommends ca-certificates unattended-upgrades jq
# Preserve an administrator's existing policy. For a fresh install, only make
# currently active web/SSH services required health checks.
if [ -f /etc/fortmend/linux.json ]; then
    policy=/etc/fortmend/linux.json
elif [ -z "$policy" ]; then
    services='[]'
    for unit in ssh.service sshd.service nginx.service apache2.service; do
        if systemctl is-active --quiet "$unit"; then
            services=$(printf '%s' "$services" | jq --arg unit "$unit" '. + [$unit]')
        fi
    done
    jq --argjson services "$services" '.healthServices = $services' "$temporary_directory/linux.example.json" > "$temporary_directory/policy.json"
    policy="$temporary_directory/policy.json"
fi
# Codex is installed in its own directory; an existing personal/global Codex
# installation is untouched. Extract only the exact expected file, never paths.
fetch "https://github.com/openai/codex/releases/download/$codex_version/codex-$codex_target.tar.gz" "$temporary_directory/codex.tar.gz"
actual=$(sha256sum "$temporary_directory/codex.tar.gz" | cut -d ' ' -f 1)
[ "$actual" = "$codex_hash" ] || fail 'Codex checksum mismatch'
tar -xOf "$temporary_directory/codex.tar.gz" "codex-$codex_target" > "$temporary_directory/codex"
[ -s "$temporary_directory/codex" ] || fail 'Codex archive contains no executable'
chmod 0755 "$temporary_directory/fortmend-linux-$arch"
# Stop only after every download passed its integrity check. Existing policy,
# state, credentials and evidence are retained. No service starts on failure.
if systemctl is-active --quiet fortmend-protect.service; then
    systemctl stop fortmend-protect.service
    service_stopped=true
fi
install -d -o root -g root -m 0755 /usr/local/lib/fortmend
codex_tmp=$(mktemp /usr/local/lib/fortmend/.codex.XXXXXXXX)
install -o root -g root -m 0755 "$temporary_directory/codex" "$codex_tmp"
mv -f -- "$codex_tmp" /usr/local/lib/fortmend/codex
codex_tmp=
if [ "$retain_legacy_state" = true ]; then
    sh "$temporary_directory/install.sh" --binary "$temporary_directory/fortmend-linux-$arch" --policy "$policy" --retain-legacy-state
else
    sh "$temporary_directory/install.sh" --binary "$temporary_directory/fortmend-linux-$arch" --policy "$policy"
fi
if [ "$no_start" = true ]; then
    completed=true
    echo 'Installed. Protection has not been started.'
    echo 'Review: sudoedit /etc/fortmend/linux.json'
    echo 'Sign in: sudo fortmend ai login --binary /usr/local/lib/fortmend/codex'
    echo 'Start: sudo systemctl enable --now fortmend-protect.service'
    exit 0
fi
if [ "$(jq -r '.ai.enabled' /etc/fortmend/linux.json)" = true ]; then
    state=$(jq -er '.stateDir | if . == null or . == "" then "/var/lib/fortmend/protection" else . end' /etc/fortmend/linux.json)
    codex_binary=$(jq -er '.ai.binary | if . == null or . == "" then "/usr/local/lib/fortmend/codex" else . end' /etc/fortmend/linux.json)
    if ! /usr/local/bin/fortmend ai status --state-dir "$state" --binary "$codex_binary" | jq -e '.account.type == "chatgpt"' >/dev/null; then
        # The script itself may arrive over stdin. Device login must read the
        # controlling terminal, never consume the remainder of this script.
        if ! { : </dev/tty; } 2>/dev/null; then
            fail 'no terminal for ChatGPT sign-in. Rerun with --no-start, then sign in and start manually (see docs/LINUX.md).'
        fi
        /usr/local/bin/fortmend ai login --state-dir "$state" --binary "$codex_binary" </dev/tty || fail 'ChatGPT sign-in did not complete; protection has not been started'
        /usr/local/bin/fortmend ai status --state-dir "$state" --binary "$codex_binary" | jq -e '.account.type == "chatgpt"' >/dev/null || fail 'ChatGPT authentication was not confirmed; protection has not been started'
    fi
fi
systemctl enable --now fortmend-protect.service
systemctl is-active --quiet fortmend-protect.service || fail 'service did not become active; inspect journalctl -u fortmend-protect.service'
completed=true
echo 'Fortmend is protecting this VM.'
echo 'Policy: /etc/fortmend/linux.json — set webRoots to your application folders.'
echo 'Activity: sudo journalctl -u fortmend-protect.service -f'
