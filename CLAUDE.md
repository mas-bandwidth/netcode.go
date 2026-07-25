<!-- HOT:BEGIN -->
**netcode.go is the official Go port of the C netcode reference library**
(mas-bandwidth/netcode, which is normative). Not the C repo, not mas-bandwidth/netcode.rs,
and NOT `wirepair/netcode` (a separate, unaffiliated Go netcode, dormant since 2019,
linked from our README as a community implementation). Module path ends `.go`; the package is `netcode`.

DECISIONS
- Three independent version numbers live here. Do not reconcile them.
  1. Module/tag version: its own line, v1.0.0 -> v1.1.0. It does not track C's numbering.
  2. Exported `VersionFull` "1.3.5": the C version ported FROM, unchanged since the first
     commit (C is now 1.4.0). No recorded decision says whether it should track C. Treat
     as UNRESOLVED, ask before changing it, and do not read it as "behind on C".
  3. `versionInfo` "NETCODE 1.02": the on-the-wire PROTOCOL version. It never moves.
- C 1.4.0's AEAD nonce-reuse fix IS ported: commit 2336bed (C dc21b70), shipped in v1.1.0.
  `VersionFull` saying 1.3.5 does not mean that fix is missing.

INVARIANTS
- Wire compatibility with the C reference is the prime directive. C is normative: where the
  bytes disagree, this port is wrong until the C side is proven wrong.
- Enforced per PR in CI: testdata/*.bin regenerated from C main and byte-compared, plus live
  UDP interop against the built C binaries in both directions.

TRAPS
- CI checks out C main unpinned (wire-compat, spec-sync), so an upstream C commit can redden
  this repo with no change here. Read the C diff first.
- STANDARD.md is a verbatim vendored copy of the C repo's; spec-sync diffs it against C main.
- Plain `go test` SKIPS TestCInterop unless NETCODE_C_BIN_DIR points at a built C checkout.
  Green locally does not mean interop passes.

NEVER
- Never edit testdata/*.bin, regenerate the vectors from Go, or edit STANDARD.md here to make
  a test pass. Fix the port, or fix it upstream in C first.
<!-- HOT:END -->

## Build and test

```
go build ./...
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

Interop against the C reference (skipped without the env var):

```
NETCODE_C_BIN_DIR=$HOME/netcode/build/bin go test -run TestCInterop -v -count=1 .
```

Also run in CI: `gofmt -l .` must be empty, `go mod tidy` must leave `go.mod`/`go.sum`
unchanged, golangci-lint, govulncheck, a short fuzz pass over each `Fuzz*` target, and
`go run ./cmd/soak 500`.
