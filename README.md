<div align="center">
  <img src="site/aegis-mark.svg" width="88" alt="Aegis shield">

# Aegis

**Endpoint defense that keeps its judgment separate from its authority.**

[![CI](https://github.com/ErzenXz/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/ErzenXz/aegis/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-315d52.svg)](LICENSE)
[![Status: developer preview](https://img.shields.io/badge/status-developer%20preview-b9523b.svg)](docs/IMPLEMENTATION.md)

[Homepage](https://aegis.erzen.dev/) · [Implementation status](docs/IMPLEMENTATION.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)
</div>

---

Aegis is a self-hosted, cross-platform endpoint-defense developer preview for
solo administrators. A deterministic endpoint agent collects and classifies
security events offline. A tightly constrained, vendored
[`fx`](https://github.com/vercel-labs/fx) planner can investigate those events
through seven typed security tools when a model provider is available.

> [!WARNING]
> Aegis is not production-ready antivirus or a replacement for a maintained
> EDR. The current preview does not install kernel sensors, enable autonomous
> host repair, or make a machine impossible to compromise. Privileged response
> remains locked until each action has a tested recovery adapter.

## What works now

- One Go binary for macOS, Linux, and Windows: `hub`, `agent`, `enroll`,
  `scan`, `status`, `doctor`, and `provider` commands.
- A self-hosted HTTPS hub with a local CA, device-owned CSRs, single-use
  enrollment, certificate-bound event identity, SQLite storage, retention
  metadata, tamper-evident audit chaining, SSE updates, and an embedded incident
  timeline.
- A bounded durable endpoint queue that keeps collecting while the hub is
  unavailable and replays events in order.
- Host/capability snapshots plus opt-in osquery, Trivy, and YARA adapters.
- Deterministic signature, vulnerability, persistence, authentication, and
  ransomware-burst findings.
- A recovery-gated response executor that requires deterministic evidence,
  confidence `>= 0.95`, 24 hours of observation, healthy telemetry, verified
  rollback, idempotency, and post-action health checks.
- fx v0.0.5 vendored at commit
  `df7e6245e1992758d4060c97477ceafa27770551`, with an `fx acp --aegis`
  profile that disables native fx tools and accepts only ACP-provided MCP tools.
- A seven-tool security MCP surface: `get_case`, `search_events`,
  `collect_evidence`, `get_host_state`, `simulate_response`,
  `request_response`, and `verify_response`.
- Ed25519 update-manifest signing and tamper verification primitives.

## Build and test

Install the latest preview and start guided onboarding:

```sh
curl -fsSL https://aegis.erzen.dev/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://aegis.erzen.dev/install.ps1 | iex
```

Requirements: Go 1.25. Zig 0.16 is needed only for the vendored fx planner.

```sh
make test
make build
make fx-build       # Linux/macOS planner
```

Run a local preview scan:

```sh
./bin/aegis scan --device-id my-machine
./bin/aegis scan --device-id my-machine --osquery
./bin/aegis scan --device-id my-machine --trivy-target /
./bin/aegis scan --device-id my-machine \
  --yara-rules /path/to/rules --yara-targets /tmp,/usr/local/bin
```

## Hub and enrollment

Start the hub with certificate names matching the URL devices will use:

```sh
./bin/aegis hub \
  --addr :7443 \
  --data-dir ~/.aegis-hub \
  --tls-hosts localhost,127.0.0.1,aegis.lan
```

The hub prints a one-run enrollment token and the CA path. Securely copy the CA
to the endpoint, then enroll:

```sh
./bin/aegis enroll \
  --hub https://aegis.lan:7443 \
  --token TOKEN_FROM_HUB \
  --ca /path/to/ca.pem \
  --device-id workstation-1

./bin/aegis agent --once
./bin/aegis agent
```

Open `https://aegis.lan:7443/` to view the timeline. The hub CA is private, so
the browser must trust it locally during development. Do not expose this
preview directly to the public internet.

## Provider routes

Build/install `aegis-fx`, or set `AEGIS_FX_PATH` to the patched fx binary.
The wrapper preserves fx's supported authentication routes:

```sh
aegis provider login vercel
aegis provider setup          # AI Gateway API key
aegis provider login codex
aegis provider login grok
aegis provider status
```

Detection and event retention never depend on provider availability. Provider
tokens remain in fx's protected profile storage and are not written to Aegis's
SQLite database.

## Platform status

| Platform | Aegis agent/hub | fx planner | Preview sensors |
| --- | --- | --- | --- |
| Ubuntu 22.04/24.04, Debian 12 | Buildable | Native Zig | Host + osquery/Trivy/YARA adapters |
| macOS 14+ x64/arm64 | Buildable | Native Zig | Host + osquery/Trivy/YARA adapters |
| Windows 11, Server 2022/2025 | Buildable | **Port incomplete** | Host + osquery/Trivy/YARA adapters |

The pinned fx source currently produces 15 Windows errors even for its narrower
N-API build, mostly from POSIX permissions, realpath, poll, and session storage.
Aegis therefore reports the Windows planner as unavailable rather than falling
back to an unsafe shell bridge. The Go protection path and deterministic
detection continue to work. See [the implementation status](docs/IMPLEMENTATION.md).

Deep macOS Endpoint Security monitoring additionally requires Apple's
entitlement, signing, and notarization. The preview does not pretend that
unsigned log polling is equivalent.

## Security model

- Security evidence is untrusted data. It is passed to fx as a separate JSON
  resource and never interpolated into trusted instructions.
- fx has no direct shell, filesystem mutation, web, skill-installation, or
  arbitrary MCP authority in the Aegis profile.
- The reasoner may propose actions; only the deterministic response executor
  can authorize privileged effects.
- Developer-preview response tools return a rejection until a platform adapter
  demonstrates snapshot, health verification, and rollback.
- Raw-file upload is disabled; current evidence consists of bounded normalized
  metadata.

## License

Original Aegis code is licensed under AGPL-3.0. The vendored fx source remains
under Apache-2.0; its license and third-party notices are retained inside
`third_party/fx` and summarized in `THIRD_PARTY_NOTICES.md`.

## Contributing

Start with an issue describing the detector, platform adapter, or recovery
invariant you want to add. Security-sensitive changes should include a failure
test and must preserve the rule that model output cannot directly acquire host
authority.
