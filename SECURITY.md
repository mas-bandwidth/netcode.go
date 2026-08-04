# Security Policy

netcode.go implements an encrypted, connection-oriented protocol over UDP. It parses
untrusted data straight off the wire — packets, connect tokens, and the challenge exchange
— and it holds the keys, so we take memory-safety and protocol bugs seriously.

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues or pull requests.**

Report privately through either channel:

- **GitHub private vulnerability reporting** (preferred): on this repository, go to the
  **Security** tab → **Report a vulnerability**. This opens a private advisory visible only
  to the maintainers.
- **Email**: glenn@mas-bandwidth.com.

Please include enough detail to reproduce: the affected version or commit, a description of
the flaw, and — where possible — a proof-of-concept input or a small patch.

We will acknowledge your report, keep you updated on our assessment, and coordinate
disclosure timing with you. We prefer coordinated disclosure and will credit reporters who
wish to be named.

## Scope

In scope — bugs in this repository: the netcode.go implementation itself, including packet
parsing, connect token handling, the challenge exchange, and replay protection.

Especially of interest: memory-safety or panic-inducing issues reachable from a received
packet or connect token, and protocol flaws that let a peer bypass authentication,
encryption, or replay protection.

The protocol itself is specified in `STANDARD.md`. **A flaw in the *specification* — as
opposed to this implementation of it — is in scope and is more valuable to us**, because it
affects every implementation of netcode rather than one. Report those the same way.

## Known issue: AEAD nonce reuse in the global packet sequence (fixed in v1.1.0)

**Advisory: [GHSA-wgmm-f3w5-7c6q](https://github.com/mas-bandwidth/netcode.go/security/advisories/GHSA-wgmm-f3w5-7c6q)** (published 2026-07-26; a CVE has been requested and is pending assignment).

**Affected: v1.0.0 through v1.0.2. Fixed in v1.1.0.**

The server's global packet sequence — used for connection challenge and connection denied
packets — shared a nonce space with per-client packets under the same server-to-client key.
netcode uses the packet sequence as the AEAD nonce, so a repeated `(key, nonce)` pair voids
**both confidentiality and integrity** for the affected packets under ChaCha20-Poly1305: it
leaks the XOR of the two plaintexts, and it can permit recovery of the Poly1305 one-time
key, enabling forgery.

Fixed in **v1.1.0**, which re-seeds the global sequence to 2^63 in both `Start()` and
`Stop()` so the global and per-client nonce spaces stay disjoint.

### If you are using an affected version

Upgrade to v1.1.0 or later:

    go get github.com/mas-bandwidth/netcode.go@latest

### Where affected versions can still be obtained

`go.mod` carries a `retract [v1.0.0, v1.0.2]` directive, so `go get` warns. That is the only
lever available: **the Go module proxy is an immutable cache**, so those versions remain
fetchable forever and cannot be withdrawn by anyone, including us. The retraction and the
advisory above exist precisely because removal is impossible.

### Related

The same defect class affects the C implementation (`netcode` ≤ 1.3.5, fixed in 1.4.0,
[GHSA-3x95-24j9-7448](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-3x95-24j9-7448))
and `yojimbo`, which vendors it (≤ 1.6.3, fixed in 1.7.0,
[GHSA-hqp3-fj6v-hrpc](https://github.com/mas-bandwidth/yojimbo/security/advisories/GHSA-hqp3-fj6v-hrpc)).
`netcode.rs` is **not** affected.

## Supported versions

Security fixes land on the latest release. We do not backport to older release lines.
