# Linux core verification

Run the ordinary, non-mutating checks:

```sh
go test -race ./...
go vet ./...
git diff --check
sh -n packaging/linux/install.sh
```

The suite covers offline queue capacity and replay, hub/SQLite findings,
independent collection during hub outages, installed source package versions,
vendor feed errors and freshness, update origin restrictions and failure locks,
webshell/path races and evidence preservation, AI job grouping and restart
recovery, authentication protocol fixtures, and original-finding verification.
Residual affected/unknown findings are unresolved, not verified fixes.

The Linux root CI job compiles test binaries without elevated privileges, then
runs root/path/rename and full-control protocol tests on the ephemeral runner.
The Codex protocol tests use a local fake app-server. They do not make model
requests, extract personal credentials, or modify real applications.

To smoke-test an installed official Codex CLI without login or inference:

```sh
FORTMEND_CODEX_SMOKE=1 go test -v ./internal/codexapp \
  -run '^TestOfficialAppServerAccountSmoke$'
```

This creates a separate temporary profile and checks initialization, an empty
account, effective configuration, and read-only thread creation. A live AI
repair requires the official CLI on the target VM and `sudo fortmend ai login`.

## Actual disposable VM runs

Validated on 2026-10-22 with Ubuntu 24.04 ARM64 and Debian 12 ARM64:

- Debian applied twelve real security updates, including OpenSSL, Expat,
  Python and kernel packages. Native allowed origins contained only the Debian
  security suite. Dpkg audit and SSH health passed; reboot remained pending.
- Ubuntu executed the real apply path with the exact Ubuntu/ESM security-origin
  allowlist. No eligible security updates remained, so no package changes were
  needed. Dpkg audit and SSH health passed.
- Ubuntu's live Canonical feed scan checked 668 binary / 435 source packages in
  approximately ten seconds with one HTTP request; its repeat scan reused the
  advisory cache while refreshing installed versions. Unsupported running-kernel
  and other predicates were reported explicitly as unknown coverage.
- Installed PHP 8.3 source version `8.3.6-0ubuntu0.24.04.13` correctly cleared two
  current vendor CVE fix boundaries. Epoch, tilde and backport comparisons used
  real dpkg, rather than generic semantic versions.
- Debian's installed systemd service performed before/after vendor assessments,
  security updates, live SSH burst/success correlation, PHP fixture detection,
  protected quarantine, original-path absence and evidence hash verification.
  Restart preserved cursor/dedup state. Recreating the same malicious content is
  a distinct occurrence, preventing stale events from targeting a reinfection.
- Linux root fixtures tested full-control app-server parameters, credential and
  executable ownership, unsafe symlink/hardlink refusals, rename race recovery,
  stale journal cursor recovery, and bounded offline-result replay.

These are actual OS/update/monitoring tests. No live ChatGPT model inference was
run on the disposable VMs; model-side work and permission handshakes were tested
through protocol fixtures. Do not interpret a model summary or a successful
package transaction as proof that an entire host is uncompromised.

## Repeating destructive integration tests

Use disposable VMs only. Cross-compile individual test binaries for the VM
architecture, copy them into the VM, and execute there. The real updater test
requires root, `FORTMEND_PATCHING_INTEGRATION=1`, and
`/etc/fortmend-disposable-integration` containing exactly
`fortmend-disposable-security-update-test`. It applies real security updates.

The live journal test requires root, the disposable marker, and
`FORTMEND_MONITOR_INTEGRATION=1`; it writes clearly identified test SSH records to
the journal. The live vendor scanner uses
`FORTMEND_VULNERABILITY_INTEGRATION=1` and contacts official vendor feeds. Ordinary
test runs skip all three opt-in integrations.

Keep VM console/recovery access. Destroy disposable VMs and their test images
after capturing results; do not reuse their intentionally modified state as a
production installation.
