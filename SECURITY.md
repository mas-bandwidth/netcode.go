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

## Known issue: AEAD nonce reuse on unfinished handshakes and multi-server connect tokens (fixed in v1.2.0)

**Advisory: [GHSA-8mrq-q9c6-h23v](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-8mrq-q9c6-h23v)** (published 2026-11-19).

**Affected: v1.1.4 and earlier (`NETCODE 1.02`). Fixed in v1.2.0 (`NETCODE 1.03`).**

In `NETCODE 1.02`, packets encrypted directly under the 32-byte `clientToServerKey` and
`serverToClientKey` carried inside a connect token, which allowed two AEAD nonce-reuse
paths within a single connect token's lifetime:

1. **Retried unfinished handshakes.** If a client received a connection challenge and sent
   one or more connection response packets that were lost (or aborted the handshake before a
   client slot was assigned), the server's connect token history entry remained _pending_. If
   the caller reconnected with the same unexpired connect token, the client reset its packet
   sequence to zero and encrypted new connection response packets under the same
   `clientToServerKey` at already-used nonces.
2. **Multi-server connect tokens.** When a connect token listed multiple dedicated servers,
   two freshly started servers shared the connect token's `serverToClientKey` and both
   began their global packet sequence at `2^63` (e.g. a full first server sending a
   connection denied packet at `2^63` and the next server sending a connection challenge
   packet at `2^63`).

Fixed in **v1.2.0** (corresponding to C reference **1.5.0**) by upgrading the wire protocol
to **`NETCODE 1.03`**:

- Per-connection packet keys are derived via `HChaCha20(tokenKey, clientSalt || serverNonce)`
  from a fresh 8-byte client salt per attempt (`connection request`, now 1086 bytes) and a
  fresh 8-byte server nonce per server mapping or full-server denial (`connection denied` and
  `connection challenge` headers, bound into 30-byte AEAD associated data). Connect token root
  keys never encrypt packets directly.
- Pending connect token history entries bind the 8-byte client salt and expire as admissible
  after `timeoutSeconds` from creation; valid `connection disconnect` packets on a half-open
  mapping consume the history entry and remove the mapping.

Thank you to [@magicaldave](https://github.com/magicaldave) ([DreamWeave-MP/dream-net](https://github.com/DreamWeave-MP/dream-net)) for discovering and privately reporting the unfinished-handshake connect-token reuse issue.

### If you are using an affected version

Upgrade to **v1.2.0** or later (`netcode` C **1.5.0** or later; `netcode.rs` and `netcode.cs`
**1.2.0** or later; **yojimbo 1.16.0** or later):

    go get github.com/mas-bandwidth/netcode.go@latest

Because `NETCODE 1.03` changes the wire protocol version string and handshake packet headers,
clients, servers, and token-issuing backends must be upgraded together.

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
