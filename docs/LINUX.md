# Autonomous Ubuntu/Debian VM protection

Fortmend runs as a root service inside one Ubuntu or Debian VM. It combines distro security updates, vendor CVE matching against installed dpkg packages, live SSH/journald monitoring, PHP webshell indicators in configured webroots, and cron/systemd persistence changes. An optional Codex app-server connection uses your ChatGPT account to investigate and repair the VM and its applications.

The supplied example explicitly enables **full-control AI**. In this mode the AI can execute host commands and modify application and system files as root without asking for each change. Review the policy before starting the service. Native package updates and PHP quarantine are separately controlled by `securityUpdates` and `autoQuarantine`. `ai.enabled: false` disables AI; `ai.mode: "investigate"` keeps AI investigations read-only.

Full-control AI is instructed to preserve evidence and recoverable application backups, make scoped repairs, and test them. These instructions guide the model; they are not a permission sandbox. Run this on a VM for which you have recovery access and a tested backup or snapshot. Fortmend does not create hypervisor snapshots, implement guaranteed package rollback, or establish that a host has no remaining vulnerabilities or compromise. Docker deployment is not shipped.

## One-command setup

Run inside an Ubuntu 24.04 or Debian 12 VM with systemd, sudo, and curl:

```sh
curl -fsSL https://fortmend.vercel.app/install.sh | sudo sh
```

The bootstrap pins Fortmend `v0.2.0-preview.1`, downloads the matching amd64 or
arm64 binary and policy/service installer from that GitHub release, and checks
every file against its release `SHA256SUMS`. This verifies download integrity;
the manifest and binaries share the GitHub release's trust boundary. It installs
required packages through APT without a broad package upgrade. No compiler,
Node.js, or npm installation is needed.

It also installs OpenAI's standalone Codex `rust-v0.163.0` into
`/usr/local/lib/fortmend/codex`. The architecture-specific SHA-256 hashes are
pinned in the bootstrap from the official OpenAI release metadata. Your existing
Codex installation and personal profile are untouched. See the
[official Codex CLI documentation](https://learn.chatgpt.com/docs/cli).

The installer displays a ChatGPT device-login link. Complete sign-in yourself
using an account with Codex access; the service starts only after authentication
is confirmed. It uses `/dev/tty` for login when the script is piped through stdin.
AI cannot sign in on your behalf. A failed or cancelled installation never
enables a new service; an existing running service stopped for an upgrade stays
stopped on failure so you can resolve the error and rerun the installer.

The initial policy enables security-only updates, PHP quarantine, and
full-control AI, and disables automatic reboot. It requires only the active
SSH/nginx/Apache units detected at install time. Set `webRoots` to your actual
application directories; the default is `/var/www/html`. Add other required
services, such as `php8.3-fpm.service`, to `healthServices`. Only list installed,
running units. A missing or inactive required unit blocks updates. Existing
content establishes the initial monitor baseline, not proof of a clean host.

```sh
sudoedit /etc/fortmend/linux.json
sudo systemctl restart fortmend-protect.service
sudo systemctl status fortmend-protect.service --no-pager
sudo journalctl -u fortmend-protect.service -f
```

To download and inspect the bootstrap, install without sign-in/start, or provide
a reviewed local policy:

```sh
curl -fsSL https://fortmend.vercel.app/install.sh -o /tmp/fortmend-install.sh
less /tmp/fortmend-install.sh
sudo sh /tmp/fortmend-install.sh --no-start
# Optional on a fresh installation:
# sudo sh /tmp/fortmend-install.sh --no-start --policy /path/to/reviewed-linux.json
```

An existing `/etc/fortmend/linux.json` is always preserved by the bootstrap, along
with state and managed sign-in. Repeat the command to install the version pinned
in the current bootstrap. It does not enable automatic Fortmend binary or Codex
version upgrades. Security package updates continue according to policy.

## Sign in and start manually

After `--no-start`, use the `stateDir` and `ai.binary` values from your policy.
With the default policy:

```sh
sudo fortmend ai login --binary /usr/local/lib/fortmend/codex
sudo fortmend ai status --binary /usr/local/lib/fortmend/codex
sudo systemctl enable --now fortmend-protect.service
```

`ai login` starts the official local `codex app-server`, displays its managed
ChatGPT device authorization URL/code, and waits for completion. Codex owns
credential persistence and refresh; Fortmend does not extract or copy ChatGPT
credentials. See the [app-server authentication protocol](https://learn.chatgpt.com/docs/app-server).

The dedicated profile is `/var/lib/fortmend/protection/codex`, derived from
`stateDir`. It must **not contain `config.toml`**: Fortmend controls app-server
settings and refuses inherited configuration, MCP servers, provider routing,
hooks, or plugins. Do not copy your personal Codex profile into it. For a custom
state directory, add `--state-dir /absolute/state` and the matching
`--binary /absolute/codex`. Treat the entire profile as sensitive root-owned data.

## Install an existing binary offline

Download the Linux release binary and `SHA256SUMS` on a trusted machine, verify
the checksum, and copy it to the VM with `packaging/linux/install.sh`,
`fortmend-protect.service`, and a reviewed JSON policy. Keep the installer and
service file together. Alternatively build from source with Go 1.25 or newer:

```sh
go build -trimpath -o /tmp/fortmend ./cmd/fortmend
```

Provision `unattended-upgrades`, `journalctl`, `dpkg`, `apt-get`, `systemctl`, and
the official Codex CLI separately. Set the policy's `ai.binary` to the trusted
root-owned Codex executable. Then:

```sh
sudo sh packaging/linux/install.sh \
  --binary /path/to/linux/fortmend \
  --policy /path/to/reviewed-linux.json
```

The offline installer downloads nothing, checks Ubuntu/Debian and root
privileges, refuses symlinked or replaceable privileged installation paths,
installs `/usr/local/bin/fortmend` atomically, and validates policy using the
installed CLI. `/etc/fortmend` and `/var/lib/fortmend/protection` are root-owned
mode `0700`; the policy is root-owned `0640`. Existing policy is retained unless
`--replace-policy` is explicit. Stop the service before an offline upgrade.

Offline installation reloads systemd and does not enable or start protection.
Review policy, sign in when AI is enabled, and start it with the manual commands
above. The service intentionally has root write access to the host.

For a single real cycle with the daemon stopped, run
`sudo fortmend protect --config /etc/fortmend/linux.json --once`. This performs
real updates, quarantine, and AI work according to policy.
`sudo fortmend protect --config /etc/fortmend/linux.json --status` only reads
local policy/receipt state and can run while the daemon is active.

## Moving from Aegis

The bootstrap refuses legacy Aegis installations by default. Migration preserves
`/var/lib/aegis` **in place**: quarantine receipts, evidence, and queued events
can contain absolute paths. Moving that directory would break those references.
Your existing `stateDir`, managed ChatGPT authentication, evidence, and receipts
must remain unchanged.

Use a VM backup before migration. Stop and disable the old service, and ensure
Fortmend has not already been installed. Preserve the original unit and policy,
and move only the configuration directory:

```sh
sudo systemctl disable --now aegis-protect.service
sudo sh -eu <<'MIGRATE'
test ! -e /etc/fortmend
test ! -e /etc/systemd/system/fortmend-protect.service
test -d /etc/aegis
test -d /var/lib/aegis
test ! -L /etc/aegis
test ! -L /var/lib/aegis
test ! -e /var/lib/fortmend-migration-backup
install -d -o root -g root -m 0700 /var/lib/fortmend-migration-backup
cp -p /etc/aegis/linux.json /var/lib/fortmend-migration-backup/linux.json
if test -e /etc/systemd/system/aegis-protect.service; then
  mv /etc/systemd/system/aegis-protect.service /var/lib/fortmend-migration-backup/aegis-protect.service
fi
mv /etc/aegis /etc/fortmend
systemctl daemon-reload
MIGRATE
sudoedit /etc/fortmend/linux.json
```

In that existing policy set `schemaVersion` to `fortmend.linux/v1`, and set
`ai.binary` to `/usr/local/lib/fortmend/codex`. **Keep `stateDir` unchanged**, normally
`/var/lib/aegis/protection`. Keep your actual webroots, required services, AI mode,
and update settings. Custom state directories also stay in their original
locations. If you use optional hub enrollment, review its paths and the hub's
migration requirements separately.

Run the bootstrap with the explicit legacy-state opt-in:

```sh
curl -fsSL https://fortmend.vercel.app/install.sh | sudo sh -s -- --retain-legacy-state
```

`--retain-legacy-state` permits `/var/lib/aegis` only when an existing
`/etc/fortmend/linux.json` is present. It still refuses the old Aegis policy or
protection unit. The offline installer accepts the same flag. Pass it again on
future installs while legacy state is retained. Both installers preserve and
validate the existing policy. Verify service logs and retained evidence after
migration. The legacy CLI may remain on disk, but must not run its old daemon.

## What runs and what is verified

The default monitor interval is five seconds. It reads bounded journal batches and scoped files, detecting SSH failures/suspicious authentication evidence, strong PHP execution indicators, and changes to systemd/cron persistence. Quarantine is limited to eligible high-confidence PHP indicators inside the configured webroots, with evidence preserved outside served roots. Review suspicious findings and quarantine receipts; detection is heuristic and does not cover every attack, web stack, file type, or entry point.

Every assessment cycle, by default hourly, inventories installed packages and compares them with official Ubuntu/Debian vulnerability data. Feeds are cached for up to six hours, so this is periodic advisory refresh rather than an instantaneous disclosure feed. Distro package versions include vendor backports. Ubuntu uses Canonical CVE OVAL metadata and Debian uses the official Debian security tracker. Advisory predicates that cannot be resolved safely are reported as `vulnerability.unknown`; `complete_with_unknowns` is a valid assessment result and does not mean those cases are fixed. Ubuntu OVAL kernel predicates that require unsupported running-kernel/variable evaluation produce `vulnerability.coverage_unknown` per installed kernel source; kernel vulnerability resolution is not asserted from package inventory alone. Application dependencies installed outside dpkg, such as Composer packages or manually installed PHP builds, are not covered by the deterministic CVE scanner. Full-control AI can inspect and repair those applications, subject to model access and actual verification evidence.

The native updater checks dpkg audit and configured service health, refreshes authenticated APT repositories, plans an exact security-origin `unattended-upgrade` dry run, then applies only if `securityUpdates` is true. Its private APT policy ignores existing global unattended-upgrade origins; ordinary release upgrades and broad `apt upgrade` are not part of this mechanism. Explicit source settings that bypass authentication or validity checks are rejected. Existing distro unattended-upgrade timers are not modified by installation; contention with another package transaction causes an update error rather than bypassing locks.

After application, dpkg audit and required units must pass again. A later CVE assessment records remaining vulnerable packages instead of treating command completion as vulnerability eradication. Reboot requirements are emitted separately. `automaticReboot` defaults to false; enabling it permits a reboot scheduled one minute after successful health checks. Fortmend does not prove that an already compromised VM is clean merely by patching it.

Full-control AI runs periodic VM audits and investigations of qualifying high/critical findings. AI work is serialized with package assessment/update operations. Incident kinds use separate bounded batches so a large CVE set cannot crowd out a new webshell. Following a completed investigation, Fortmend reruns package assessment, checks every retained original finding and configured host health, and records verification evidence. Known unresolved findings receive a cooldown; transient failures retry. Residual findings and application-level uncertainty still matter. Auth, network, missing tools, unavailable feeds, journal access problems, and failed repairs are recorded as degraded coverage or errors. A model's narrative alone is not proof of a successful fix.

## State, failures, and recovery

Operational output is available through `journalctl -u fortmend-protect.service`. Local state lives under the configured `stateDir`:

- `history.jsonl` and `history.jsonl.previous` contain up to 16 MiB each, for at most 32 MiB of local event history. Export evidence you need before it rotates; system journal retention is managed independently by the OS.
- `events.jsonl` is the bounded delivery queue; local history continues without an optional hub connection.
- `monitor/` holds journal cursors and file baselines; `vulnerability/` holds vendor advisory cache.
- `patching/receipt.json` records attempted package application and its result. `investigations.json` tracks pending/completed AI work.
- `response-outbox.json` stages a containment result until it enters the event queue. Protected quarantine receipts also replay after a crash and are acknowledged only after durable delivery; event delivery can repeat after a crash.
- `codex/` contains the dedicated managed authentication profile. Quarantine receipts and recoverable content also live outside served webroots under state.

Failed or interrupted package application blocks further automatic patch attempts until an administrator investigates and acknowledges it. Acknowledgement is not repair and does not roll packages back. Inspect the receipt, dpkg/unattended-upgrade logs, and application health, repair package/service state through your normal recovery procedure, then:

```sh
sudo systemctl stop fortmend-protect.service
sudo fortmend protect --config /etc/fortmend/linux.json --acknowledge-update-failure
sudo systemctl start fortmend-protect.service
```

The next cycle repeats preflight and post-update checks. Keep hypervisor console/recovery access available. Package rollback is not guaranteed; VM snapshot/backup orchestration is a platform integration left for future work.

## Disposable VM integration test

`internal/patching/linux_integration_test.go` is skipped by default. It intentionally applies security updates and requires root, `FORTMEND_PATCHING_INTEGRATION=1`, and `/etc/fortmend-disposable-integration` containing exactly `fortmend-disposable-security-update-test`. Use only an explicitly disposable Ubuntu/Debian VM with `unattended-upgrades` and `ssh.service` provisioned. Never create that marker on a production host.

The test exercises the production runner and distro policy: dry-run, real application, durable completion receipt, dpkg audit, and SSH health. It was verified on a disposable Debian 12 ARM64 VM with 12 actual security package upgrades, including OpenSSL, Expat, Python, and kernel packages; the required reboot was reported without rebooting. The same production-runner test also passed on Ubuntu 24.04 ARM64 with security-only effective origins and clean SSH/dpkg health; its image had no eligible security upgrades remaining, so application was a verified no-op.
