module github.com/mas-bandwidth/netcode.go

go 1.25.0

require (
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
)

// SECURITY: v1.0.0 through v1.0.2 reuse an AEAD (key, nonce) pair across a
// server restart. Stop() zeroed the global packet sequence and Start() did not
// re-seed it, so a stopped-and-restarted server re-encrypted global packets
// (challenge, denied) from sequence 0 under the same per-connect-token
// server-to-client key already used for per-client packets starting at 0.
// Repeating a (key, nonce) pair voids both confidentiality and integrity for
// ChaCha20-Poly1305. Fixed in v1.1.0, which re-seeds the global sequence to
// 2^63 in both Start() and Stop() so the global and per-client nonce spaces
// stay disjoint. Upgrade to v1.1.0 or later.
retract [v1.0.0, v1.0.2]
