# Third-party notices

## fx

The directory `third_party/fx` contains fx v0.0.5 from
`https://github.com/vercel-labs/fx` at commit
`df7e6245e1992758d4060c97477ceafa27770551`.

fx is licensed under Apache License 2.0. Its unmodified license is retained at
`third_party/fx/LICENSE`, and its upstream third-party attributions are retained
at `third_party/fx/THIRD_PARTY_NOTICES.md`.

Aegis carries a local modification that adds the security-only
`fx acp --aegis` launch profile. Modified files remain clearly identifiable in
the repository history and diff from the pinned upstream commit.

## Go dependencies

The Go module graph is recorded in `go.mod` and `go.sum`. Release packaging
must generate a machine-readable software bill of materials and include each
dependency's license before public distribution.
