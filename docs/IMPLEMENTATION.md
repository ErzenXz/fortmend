# Implementation status

This document separates implemented behavior from the production EDR roadmap.

## Ubuntu/Debian autonomous VM core

`fortmend protect` now implements a separate local Linux control path. It includes
official-vendor installed-source-package CVE checks, security-only APT updates,
live SSH journals with cursor-gap recovery, persistence/PHP file monitoring,
recoverable webshell quarantine, and managed Codex app-server authentication.
An explicit full-control policy grants native root host tools for application
investigation/repair. Fresh assessments and health checks distinguish verified
original findings from unresolved findings; no result asserts a clean host.

See [Linux setup, operational limits and recovery](LINUX.md). This core is
intended for Ubuntu/Debian systemd VMs. Container packaging, fleet coordination,
comprehensive EDR telemetry, hypervisor snapshots and guaranteed package rollback
are not implemented. The legacy cross-platform response MCP remains locked.

## Implemented developer-preview slice

- Versioned event, finding, evidence, case, response, receipt, capability, and
  audit types.
- Deep module interfaces for sensors, deterministic detection, fx reasoning,
  and privileged response.
- Mutual-TLS enrollment and device-bound ingestion.
- Fingerprint-pinned CA bootstrap for one-command remote enrollment.
- DPAPI-sealed device and CA private material on Windows; owner-only files on
  Linux and macOS.
- SQLite event/finding persistence and SHA-256 audit chaining.
- Offline event queue and hub replay.
- Embedded responsive incident timeline.
- YARA, Trivy, and osquery command adapters.
- Recovery gate, confidence gate, deterministic-evidence gate, idempotency,
  health verification, and rollback orchestration.
- Security-only MCP tool surface and fx ACP client.
- Signed update manifest primitives and cross-platform Go build script.

## Deliberately locked or incomplete

- No privileged response adapter is enabled. `request_response` and
  `simulate_response` reject in the preview because rollback has not been
  proven for a real host mutation.
- Linux eBPF/audit telemetry is not implemented. The Linux core polls bounded
  SSH journald records with durable cursors and explicit gap reporting.
- Windows ETW/Event Log/WFP/Defender streaming and DPAPI-backed fx storage are
  not implemented.
- macOS Endpoint Security and Network Extension targets are not implemented;
  production work also depends on Apple entitlement approval.
- Signed feed distribution, Sigma rule compilation, general quarantine across
  platforms, account/key repair, and production agent-binary swapping remain
  roadmap items. Native Linux package updates/reboot policy and PHP quarantine
  are implemented in the Linux core.
- The hub has device authentication and MCP bearer authentication, but the web
  owner-login interface is not implemented. Bind it to a trusted interface only.

## fx verification record

- Upstream: `vercel-labs/fx`
- Version: `v0.0.5`
- Commit: `df7e6245e1992758d4060c97477ceafa27770551`
- Local fork patch: `fx acp --fortmend` disables native tools and preserves only
  ACP-provided MCP access.
- `zig fmt --check src/`: pass.
- `zig build test`: 8,466 pass, 2 skip, 1 upstream ANSI presentation failure.
- `zig build -Dtarget=x86_64-windows`: fails with 32 upstream portability errors.
- `zig build -Dnapi-surface=core -Dtarget=x86_64-windows`: fails with 15
  upstream portability errors.

## Next production milestones

1. Persist enrollment-token consumption and add owner authentication/CSRF
   protection to the web interface.
2. Implement the platform telemetry adapters behind `SensorStream.Start` and
   test them on the certified VM matrix.
3. Add quarantine and network-isolation adapters first; enable each action only
   after failure-injection and rollback tests pass.
4. Complete the Windows headless fx port or upstream an equivalent host-safe
   ACP build; do not substitute unrestricted PowerShell execution.
5. Obtain production signing identities and the Apple Endpoint Security
   entitlement, then add notarized packages and system-extension tests.
6. Implement atomic signed updater staging, retained previous binaries, and
   rollout/rollback orchestration using the existing manifest verifier.
