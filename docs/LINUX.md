# Autonomous Ubuntu/Debian VM protection

Aegis runs as a root service inside one Ubuntu or Debian VM. It combines distro security updates, vendor CVE matching against installed dpkg packages, live SSH/journald monitoring, PHP webshell indicators in configured webroots, and cron/systemd persistence changes. An optional Codex app-server connection uses your ChatGPT account to investigate and repair the VM and its applications.

The supplied example explicitly enables **full-control AI**. In this mode the AI can execute host commands and modify application and system files as root without asking for each change. Review the policy before starting the service. Native package updates and PHP quarantine are separately controlled by `securityUpdates` and `autoQuarantine`. `ai.enabled: false` disables AI; `ai.mode: "investigate"` keeps AI investigations read-only.

Full-control AI is instructed to preserve evidence and recoverable application backups, make scoped repairs, and test them. These instructions guide the model; they are not a permission sandbox. Run this on a VM for which you have recovery access and a tested backup or snapshot. Aegis does not create hypervisor snapshots, implement guaranteed package rollback, or establish that a host has no remaining vulnerabilities or compromise. Docker deployment is not shipped.

## Install an existing binary offline

Build this working revision on the target VM with Go 1.25 or newer, or
cross-compile it for the VM architecture. The published preview installer still
points to the older release; build from this repository to use `protect`.

```sh
go build -trimpath -o /tmp/aegis ./cmd/aegis
```

Provision a matching Linux architecture `aegis` binary, this repository's `packaging/linux/install.sh` and `aegis-protect.service`, and a reviewed JSON policy. Keep the installer and service file together. The installer downloads nothing and installs no dependencies. It requires `unattended-upgrade`, `journalctl`, `dpkg`, `apt-get`, and `systemctl` already available. Provision missing distribution dependencies through your normal authenticated package workflow; the relevant package for `unattended-upgrade` is `unattended-upgrades`.

Copy `packaging/linux/linux.example.json` to a local policy file and edit it. Set an optional stable `deviceId` or leave it empty to use the hostname. Set `webRoots` to your actual application directories and `healthServices` to required literal systemd service units such as `ssh.service`, `nginx.service`, and `php8.3-fpm.service`. A missing or inactive required unit blocks updates. Existing content establishes the monitor's initial baseline; it is not proof that the baseline is clean.

```sh
sudo ./packaging/linux/install.sh \
  --binary /path/to/linux/aegis \
  --policy /path/to/reviewed-linux.json
```

The installer verifies Ubuntu/Debian and root privileges, refuses symlinked or replaceable privileged installation paths, installs `/usr/local/bin/aegis` atomically, and parses the policy with the installed CLI. `/etc/aegis` and `/var/lib/aegis/protection` are root-owned mode `0700`; the installed policy is root-owned `0640`. An existing policy is preserved unless you explicitly pass `--replace-policy`. For upgrades, stop `aegis-protect.service` first so its process lock does not conflict with policy validation, run the installer, and start the service again.

Installation reloads systemd but **does not enable or start protection**. The service intentionally has root write access to the host because security updates and full-control repairs require it. It uses a fixed executable path, controlled PATH, private umask, process-group termination, and a 120-second graceful stop timeout.

## Provision Codex and sign in

Install the official Codex CLI separately from a trusted OpenAI distribution, matching the VM architecture. The policy defaults to `/usr/local/bin/codex`; use an absolute `ai.binary` path if your installation differs. Aegis does not download or bundle the CLI. See the [official Codex CLI documentation](https://learn.chatgpt.com/docs/cli) and [Codex app-server authentication protocol](https://learn.chatgpt.com/docs/app-server).

```sh
sudo aegis ai login
sudo aegis ai status
```

`ai login` starts the official local `codex app-server`, displays its managed ChatGPT device authorization URL/code, and waits for completion. Complete this sign-in yourself. Codex owns credential persistence and refresh; Aegis does not extract or copy ChatGPT credentials. Availability depends on your account and the installed CLI's supported authentication flow.

The dedicated profile is `/var/lib/aegis/protection/codex` by default, derived from `stateDir`. It must **not contain `config.toml`**: Aegis controls the app-server settings and refuses inherited configuration, MCP servers, provider routing, hooks, or plugins. Do not copy your personal Codex profile into it. With a custom state directory use `sudo aegis ai login --state-dir /absolute/state` and the matching `--binary /absolute/codex` when needed. Treat the entire profile as sensitive root-owned data; do not commit it or print its credential files.

After reviewing the installed policy and completing sign-in when AI is enabled:

```sh
sudo systemctl enable --now aegis-protect.service
sudo systemctl status aegis-protect.service
sudo journalctl -u aegis-protect.service -f
```

For an isolated first run, keep the daemon stopped and use `sudo aegis protect --config /etc/aegis/linux.json --once`. This performs real updates, quarantine, and AI work according to the policy; it is not a dry run. `sudo aegis protect --config /etc/aegis/linux.json --status` reads local policy/receipt state without running protection and can be used while the daemon is active.

## What runs and what is verified

The default monitor interval is five seconds. It reads bounded journal batches and scoped files, detecting SSH failures/suspicious authentication evidence, strong PHP execution indicators, and changes to systemd/cron persistence. Quarantine is limited to eligible high-confidence PHP indicators inside the configured webroots, with evidence preserved outside served roots. Review suspicious findings and quarantine receipts; detection is heuristic and does not cover every attack, web stack, file type, or entry point.

Every assessment cycle, by default hourly, inventories installed packages and compares them with official Ubuntu/Debian vulnerability data. Feeds are cached for up to six hours, so this is periodic advisory refresh rather than an instantaneous disclosure feed. Distro package versions include vendor backports. Ubuntu uses Canonical CVE OVAL metadata and Debian uses the official Debian security tracker. Advisory predicates that cannot be resolved safely are reported as `vulnerability.unknown`; `complete_with_unknowns` is a valid assessment result and does not mean those cases are fixed. Ubuntu OVAL kernel predicates that require unsupported running-kernel/variable evaluation produce `vulnerability.coverage_unknown` per installed kernel source; kernel vulnerability resolution is not asserted from package inventory alone. Application dependencies installed outside dpkg, such as Composer packages or manually installed PHP builds, are not covered by the deterministic CVE scanner. Full-control AI can inspect and repair those applications, subject to model access and actual verification evidence.

The native updater checks dpkg audit and configured service health, refreshes authenticated APT repositories, plans an exact security-origin `unattended-upgrade` dry run, then applies only if `securityUpdates` is true. Its private APT policy ignores existing global unattended-upgrade origins; ordinary release upgrades and broad `apt upgrade` are not part of this mechanism. Explicit source settings that bypass authentication or validity checks are rejected. Existing distro unattended-upgrade timers are not modified by installation; contention with another package transaction causes an update error rather than bypassing locks.

After application, dpkg audit and required units must pass again. A later CVE assessment records remaining vulnerable packages instead of treating command completion as vulnerability eradication. Reboot requirements are emitted separately. `automaticReboot` defaults to false; enabling it permits a reboot scheduled one minute after successful health checks. Aegis does not prove that an already compromised VM is clean merely by patching it.

Full-control AI runs periodic VM audits and investigations of qualifying high/critical findings. AI work is serialized with package assessment/update operations. Incident kinds use separate bounded batches so a large CVE set cannot crowd out a new webshell. Following a completed investigation, Aegis reruns package assessment, checks every retained original finding and configured host health, and records verification evidence. Known unresolved findings receive a cooldown; transient failures retry. Residual findings and application-level uncertainty still matter. Auth, network, missing tools, unavailable feeds, journal access problems, and failed repairs are recorded as degraded coverage or errors. A model's narrative alone is not proof of a successful fix.

## State, failures, and recovery

Operational output is available through `journalctl -u aegis-protect.service`. Local state lives under the configured `stateDir`:

- `history.jsonl` and `history.jsonl.previous` contain up to 16 MiB each, for at most 32 MiB of local event history. Export evidence you need before it rotates; system journal retention is managed independently by the OS.
- `events.jsonl` is the bounded delivery queue; local history continues without an optional hub connection.
- `monitor/` holds journal cursors and file baselines; `vulnerability/` holds vendor advisory cache.
- `patching/receipt.json` records attempted package application and its result. `investigations.json` tracks pending/completed AI work.
- `response-outbox.json` stages a containment result until it enters the event queue. Protected quarantine receipts also replay after a crash and are acknowledged only after durable delivery; event delivery can repeat after a crash.
- `codex/` contains the dedicated managed authentication profile. Quarantine receipts and recoverable content also live outside served webroots under state.

Failed or interrupted package application blocks further automatic patch attempts until an administrator investigates and acknowledges it. Acknowledgement is not repair and does not roll packages back. Inspect the receipt, dpkg/unattended-upgrade logs, and application health, repair package/service state through your normal recovery procedure, then:

```sh
sudo systemctl stop aegis-protect.service
sudo aegis protect --config /etc/aegis/linux.json --acknowledge-update-failure
sudo systemctl start aegis-protect.service
```

The next cycle repeats preflight and post-update checks. Keep hypervisor console/recovery access available. Package rollback is not guaranteed; VM snapshot/backup orchestration is a platform integration left for future work.

## Disposable VM integration test

`internal/patching/linux_integration_test.go` is skipped by default. It intentionally applies security updates and requires root, `AEGIS_PATCHING_INTEGRATION=1`, and `/etc/aegis-disposable-integration` containing exactly `aegis-disposable-security-update-test`. Use only an explicitly disposable Ubuntu/Debian VM with `unattended-upgrades` and `ssh.service` provisioned. Never create that marker on a production host.

The test exercises the production runner and distro policy: dry-run, real application, durable completion receipt, dpkg audit, and SSH health. It was verified on a disposable Debian 12 ARM64 VM with 12 actual security package upgrades, including OpenSSL, Expat, Python, and kernel packages; the required reboot was reported without rebooting. The same production-runner test also passed on Ubuntu 24.04 ARM64 with security-only effective origins and clean SSH/dpkg health; its image had no eligible security upgrades remaining, so application was a verified no-op.
