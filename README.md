<div align="center">
  <img src="site/fortmend-mark.svg" width="80" alt="Fortmend shield">

# Fortmend

**An autonomous security engineer for your Linux server.**

Find risks. Apply fixes. Check the results.

[![CI](https://github.com/ErzenXz/fortmend/actions/workflows/ci.yml/badge.svg)](https://github.com/ErzenXz/fortmend/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-315d52.svg)](LICENSE)
[![Developer preview](https://img.shields.io/badge/status-developer%20preview-b9523b.svg)](docs/IMPLEMENTATION.md)

</div>

Fortmend runs inside your VM. It checks installed software for vulnerabilities,
monitors attacks, applies security updates, and uses Codex with your ChatGPT
account to investigate and repair problems.

**Current target:** Ubuntu 24.04 and Debian 12 VMs running systemd.

## Install

Run this **inside the VM you want to protect**:

```sh
curl -fsSL https://fortmend.vercel.app/install.sh | sudo sh
```

Open the ChatGPT sign-in link shown in the terminal. Finish signing in, and
Fortmend starts automatically and keeps running after you disconnect.
No Go, Node.js, API key, or source build is needed.

The installer checks release downloads, installs the official pinned Codex CLI
and distro dependencies, and sets up `fortmend-protect.service`. It enables
security updates, PHP quarantine, and **full-control AI**. Automatic reboots
are off. Run it again to reinstall the pinned release; your policy, sign-in, and
evidence are preserved.

> Full-control AI can run commands and change system and application files as
> root. Use a backed-up VM with recovery access. ChatGPT sign-in requires an
> account with Codex access.

Point Fortmend at your applications:

```sh
sudoedit /etc/fortmend/linux.json
sudo systemctl restart fortmend-protect.service
```

Set `webRoots` to your application folders (default: `/var/www/html`).
`healthServices` contains the active SSH/nginx/Apache units detected during
installation; add other services that must stay healthy.

Watch activity:

```sh
sudo journalctl -u fortmend-protect.service -f
```

Prefer to review before starting, need an offline install, or already run Aegis?
See the [setup and migration guide](docs/LINUX.md).

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

## More

- [Setup, configuration, and recovery](docs/LINUX.md)
- [Tests and real VM verification](docs/TESTING.md)
- [Implementation status and limitations](docs/IMPLEMENTATION.md)

This is a developer preview. Detection has coverage limits, and a successful
repair does not establish that the entire VM is uncompromised.

## Development

```sh
go test -race ./...
go vet ./...
python3 scripts/test-install.py
```

## License

[AGPL-3.0](LICENSE). The vendored fx code retains its Apache-2.0 license;
see [third-party notices](THIRD_PARTY_NOTICES.md).
