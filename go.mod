module github.com/mas-bandwidth/netcode.go

go 1.26.0

require (
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.49.0
)

// SECURITY: v1.0.0 through v1.1.4 implement NETCODE 1.02 and are affected by
// ChaCha20-Poly1305 AEAD (key, nonce) reuse vulnerabilities:
//   - v1.0.0..v1.0.2: server global packet sequence overlaps per-client nonces
//     across restart (GHSA-wgmm-f3w5-7c6q / GHSA-3x95-24j9-7448, fixed in v1.1.0).
//   - v1.0.0..v1.1.3: reusing an unexpired connect token after disconnect
//     repeats per-session AEAD nonces under the same token keys
//     (GHSA-v29p-3vj4-vg4f, fixed in v1.1.4).
//   - v1.0.0..v1.1.4: retried unfinished handshakes and multi-server connect
//     tokens reuse AEAD nonces under static connect-token keys
//     (GHSA-8mrq-q9c6-h23v, fixed in v1.2.0 / NETCODE 1.03 via per-connection
//     HChaCha20 key derivation).
// Repeating a (key, nonce) pair voids both confidentiality and integrity under
// ChaCha20-Poly1305. Upgrade to v1.2.0 or later.
retract [v1.0.0, v1.1.4]
