<div align="center">
  <img src="site/aegis-mark.svg" width="80" alt="Fortmend shield">

# Fortmend

**An autonomous security engineer for your Linux server.**

Find risks. Apply fixes. Check the results.

[![CI](https://github.com/ErzenXz/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/ErzenXz/aegis/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-315d52.svg)](LICENSE)
[![Developer preview](https://img.shields.io/badge/status-developer%20preview-b9523b.svg)](docs/IMPLEMENTATION.md)

</div>

Fortmend runs inside your VM. It checks installed software for vulnerabilities,
monitors attacks, applies security updates, and uses Codex with your ChatGPT
account to investigate and repair problems.

**Current target:** Ubuntu 24.04 and Debian 12 VMs running systemd.
Fortmend is the new product name; the repository, command, and service still use
`aegis`.

## Quick start

Run these steps **inside the VM you want to protect**, using an account with sudo.

### 1. Prepare the VM

Install [Go 1.25 or newer](https://go.dev/doc/install) and the
[official Codex CLI](https://learn.chatgpt.com/docs/cli).
Use the standalone Linux Codex binary at `/usr/local/bin/codex`, owned by root
and not writable by other users. See [Codex setup details](docs/LINUX.md#provision-codex-and-sign-in).

```sh
sudo apt-get update
sudo apt-get install -y git make ca-certificates unattended-upgrades
```

### 2. Install Fortmend

```sh
git clone https://github.com/ErzenXz/aegis.git
cd aegis
make build
sudo sh packaging/linux/install.sh \
  --binary ./bin/aegis \
  --policy packaging/linux/linux.example.json
```

Edit the policy to match your applications:

```sh
sudoedit /etc/aegis/linux.json
```

Set `webRoots` to your application folders and `healthServices` to the services
that must stay healthy. The example uses `/var/www/html` and `ssh.service`.
Only list services installed and running on this VM.

The example enables automatic security updates, PHP quarantine, and
**full-control AI**. Automatic reboots are off.

> Full-control AI can execute commands and change system and application files
> as root. Start with a backed-up VM and review the policy before enabling it.

### 3. Sign in and start

```sh
sudo aegis ai login
sudo systemctl enable --now aegis-protect.service
sudo systemctl status aegis-protect.service --no-pager
```

Open the device-login URL shown in your terminal and complete ChatGPT sign-in.
Then start the service with the next command.

Watch activity:

```sh
sudo journalctl -u aegis-protect.service -f
```

The service keeps running after you close the terminal.

## What it does

- **Checks vulnerabilities:** matches installed package versions against official
  Ubuntu and Debian advisories, including vendor backports.
- **Monitors attacks:** watches SSH authentication, systemd/cron changes, and
  suspicious PHP files in your configured webroots.
- **Applies repairs:** installs security updates, preserves quarantined evidence,
  and lets Codex inspect and repair the VM and its applications.
- **Verifies results:** checks package state, configured services, and original
  findings. Reports unresolved problems explicitly.

It works locally without a hub. Fleet management and container packaging are
future work.

## Details

- [Configuration, authentication, and recovery](docs/LINUX.md)
- [Tests and real VM verification](docs/TESTING.md)
- [Implementation status and limitations](docs/IMPLEMENTATION.md)

This is a developer preview. Detection has coverage limits, and a successful
repair does not establish that the entire VM is uncompromised.

## Development

```sh
go test -race ./...
go vet ./...
```

## License

[AGPL-3.0](LICENSE). The vendored fx code retains its Apache-2.0 license;
see [third-party notices](THIRD_PARTY_NOTICES.md).
