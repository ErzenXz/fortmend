#!/bin/sh
# Offline installation only. Review the policy and authenticate before starting.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
usage() {
    echo 'Usage: sudo install.sh --binary /path/to/fortmend --policy /path/to/linux.json [--replace-policy] [--retain-legacy-state]' >&2
    exit 2
}
fail() { echo "Fortmend install: $*" >&2; exit 1; }
binary=
policy=
replace=false
retain_legacy_state=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --retain-legacy-state) retain_legacy_state=true; shift ;;
        --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2 ;;
        --policy) [ "$#" -ge 2 ] || usage; policy=$2; shift 2 ;;
        --replace-policy) replace=true; shift ;;
        *) usage ;;
    esac
done
[ "$(uname -s)" = Linux ] || fail 'Ubuntu/Debian Linux is required'
[ "$(id -u)" = 0 ] || fail 'run as root'
[ ! -e /etc/aegis/linux.json ] && [ ! -e /etc/systemd/system/aegis-protect.service ] || fail 'legacy Aegis installation detected; see docs/LINUX.md#moving-from-aegis before installing'
if [ -e /var/lib/aegis ]; then
    [ "$retain_legacy_state" = true ] && [ -f /etc/fortmend/linux.json ] || fail 'legacy Aegis state detected; migrate policy first, then explicitly pass --retain-legacy-state (see docs/LINUX.md#moving-from-aegis)'
fi
if [ "$retain_legacy_state" = true ]; then
    [ -f /etc/fortmend/linux.json ] || fail '--retain-legacy-state requires an existing /etc/fortmend/linux.json'
fi
[ -n "$binary" ] && [ -f "$binary" ] && [ -x "$binary" ] || fail 'provide an executable local --binary'
[ -n "$policy" ] && [ -f "$policy" ] || fail 'provide a local --policy JSON file'
# Parse the ID without sourcing an executable shell file.
distro=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | tr -d "'")
case "$distro" in ubuntu|debian) ;; *) fail 'only Ubuntu/Debian are supported' ;; esac
for tool in unattended-upgrade journalctl dpkg apt-get systemctl install stat mktemp; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing dependency: $tool (provision it separately)"
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$script_dir/fortmend-protect.service" ] || fail 'keep fortmend-protect.service alongside install.sh'
# Reject replaceable ancestors before writing privileged executables or policy.
secure_ancestors() {
    path=$1
    while :; do
        [ ! -L "$path" ] || fail "symlinked installation path: $path"
        if [ -e "$path" ]; then
            [ -d "$path" ] || fail "installation ancestor is not a directory: $path"
            [ "$(stat -c %u -- "$path")" = 0 ] || fail "installation ancestor must be root owned: $path"
            mode=$(stat -c %a -- "$path")
            [ "$((0$mode & 0022))" = 0 ] || fail "installation ancestor is group/world writable: $path"
        fi
        [ "$path" != / ] || break
        path=$(dirname -- "$path")
    done
}
for directory in /usr/local/bin /etc/fortmend /var/lib/fortmend/protection /etc/systemd/system; do
    secure_ancestors "$directory"
done
install -d -o root -g root -m 0755 /usr/local/bin
install -d -o root -g root -m 0700 /etc/fortmend /var/lib/fortmend /var/lib/fortmend/protection
[ ! -L /etc/fortmend/linux.json ] || fail 'policy destination must not be a symlink'
if [ -e /etc/fortmend/linux.json ]; then
    [ -f /etc/fortmend/linux.json ] || fail 'existing policy is not a regular file'
    [ "$(stat -c %u /etc/fortmend/linux.json)" = 0 ] || fail 'existing policy must be root owned'
    mode=$(stat -c %a /etc/fortmend/linux.json)
    [ "$((0$mode & 0027))" = 0 ] || fail 'existing policy must be private and not group writable (0640 or stricter)'
fi
binary_tmp=$(mktemp /usr/local/bin/.fortmend.XXXXXXXX)
policy_tmp=
service_tmp=
cleanup() {
    [ -z "$binary_tmp" ] || rm -f -- "$binary_tmp"
    [ -z "$policy_tmp" ] || rm -f -- "$policy_tmp"
    [ -z "$service_tmp" ] || rm -f -- "$service_tmp"
}
trap cleanup EXIT HUP INT TERM
install -o root -g root -m 0755 -- "$binary" "$binary_tmp"
# Rename replaces an old executable atomically, including a symlink itself.
mv -f -- "$binary_tmp" /usr/local/bin/fortmend
binary_tmp=
if [ ! -e /etc/fortmend/linux.json ] || [ "$replace" = true ]; then
    policy_tmp=$(mktemp /etc/fortmend/.linux.XXXXXXXX)
    install -o root -g root -m 0640 -- "$policy" "$policy_tmp"
    # Parse with the installed CLI before replacing the active policy. Status has
    # no update, scan, quarantine or AI execution side effects.
    /usr/local/bin/fortmend protect --config "$policy_tmp" --status >/dev/null
    mv -f -- "$policy_tmp" /etc/fortmend/linux.json
    policy_tmp=
else
    echo 'Preserving existing /etc/fortmend/linux.json (use --replace-policy to replace it).'
    /usr/local/bin/fortmend protect --config /etc/fortmend/linux.json --status >/dev/null
fi
service_tmp=$(mktemp /etc/systemd/system/.fortmend-protect.XXXXXXXX)
install -o root -g root -m 0644 "$script_dir/fortmend-protect.service" "$service_tmp"
mv -f -- "$service_tmp" /etc/systemd/system/fortmend-protect.service
service_tmp=
systemctl daemon-reload
echo 'Installed Fortmend. The service has not been enabled or started.'
echo 'Review /etc/fortmend/linux.json. If AI is enabled, run sudo fortmend ai login with the matching --binary and --state-dir from that policy.'
echo 'Then start protection: sudo systemctl enable --now fortmend-protect.service'
