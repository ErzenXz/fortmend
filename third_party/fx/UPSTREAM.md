# Fortmend vendoring record

- Canonical repository: `https://github.com/vercel-labs/fx`
- Upstream tag: `v0.0.5`
- Upstream commit: `df7e6245e1992758d4060c97477ceafa27770551`
- Imported as a git archive, without an embedded `.git` directory.

## Local patch policy

Fortmend carries the smallest reviewed patch set needed for a security-only ACP
profile and platform support. Syncs must start from a signed/tagged upstream
release, review the complete upstream diff, rerun the Fortmend and fx suites, and
record verification results in `docs/IMPLEMENTATION.md`.

Current patch:

- `fx acp --fortmend` sets `allow_native_tools=false` and
  `allow_acp_mcp=true`, ensuring the planner can see only tools supplied by the
  trusted Fortmend ACP client.
