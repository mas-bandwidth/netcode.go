package netcode

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// The C implementation uses libsodium. The equivalent primitives here are:
//
//	crypto_core_hchacha20                -> chacha20.HChaCha20     (16 byte input)
//	crypto_aead_chacha20poly1305_ietf_*  -> chacha20poly1305.New   (12 byte nonce)
//	crypto_aead_xchacha20poly1305_ietf_* -> chacha20poly1305.NewX  (24 byte nonce)
//
// Both AEADs produce a 16 byte poly1305 MAC appended to the ciphertext.

var errDecryptFailed = errors.New("netcode: failed to decrypt")

// GenerateKey generates a random 32 byte encryption key.
func GenerateKey() []byte {
	key := make([]byte, KeyBytes)
	RandomBytes(key)
	return key
}

func generateNonce() [connectTokenNonceBytes]byte {
	var nonce [connectTokenNonceBytes]byte
	RandomBytes(nonce[:])
	return nonce
}

// RandomBytes fills data with cryptographically secure random bytes.
func RandomBytes(data []byte) {
	if _, err := rand.Read(data); err != nil {
		panic(err) // crypto/rand.Read never fails on supported platforms
	}
}

// encryptAEADBigNonce encrypts message[:messageLength] in place with
// XChaCha20-Poly1305 (24 byte nonce), writing the 16 byte MAC directly after
// the message. The buffer must have room for messageLength+MacBytes.
func encryptAEADBigNonce(message []byte, messageLength int, additional []byte, nonce []byte, key []byte) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	aead.Seal(message[:0], nonce, message[:messageLength], additional)
	return nil
}

// decryptAEADBigNonce decrypts message[:messageLength] in place, where the last
// 16 bytes are the MAC. On success the plaintext occupies message[:messageLength-MacBytes].
func decryptAEADBigNonce(message []byte, messageLength int, additional []byte, nonce []byte, key []byte) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	if _, err := aead.Open(message[:0], nonce, message[:messageLength], additional); err != nil {
		return errDecryptFailed
	}
	return nil
}

// encryptAEAD encrypts message[:messageLength] in place with ChaCha20-Poly1305
// IETF (12 byte nonce), writing the 16 byte MAC directly after the message.
func encryptAEAD(message []byte, messageLength int, additional []byte, nonce []byte, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	aead.Seal(message[:0], nonce, message[:messageLength], additional)
	return nil
}

// decryptAEAD decrypts message[:messageLength] in place, where the last 16
// bytes are the MAC.
func decryptAEAD(message []byte, messageLength int, additional []byte, nonce []byte, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	if _, err := aead.Open(message[:0], nonce, message[:messageLength], additional); err != nil {
		return errDecryptFailed
	}
	return nil
}

// derivePacketKey derives a 32-byte per-connection packet key from a 32-byte
// connect token root key, an 8-byte client salt, and an 8-byte server nonce:
//
//	HChaCha20(tokenKey, clientSalt || serverNonce)
func derivePacketKey(tokenKey [KeyBytes]byte, clientSalt [connectSaltBytes]byte, serverNonce [serverNonceBytes]byte) [KeyBytes]byte {
	var input [connectSaltBytes + serverNonceBytes]byte
	copy(input[:connectSaltBytes], clientSalt[:])
	copy(input[connectSaltBytes:], serverNonce[:])

	derivedSlice, err := chacha20.HChaCha20(tokenKey[:], input[:])
	clear(input[:])
	if err != nil {
		panic(err) // fixed-size 32-byte key and 16-byte input never fail length validation
	}

	var derived [KeyBytes]byte
	copy(derived[:], derivedSlice)
	clear(derivedSlice)
	return derived
}

// packetNonce constructs the 96 bit nonce used for packet and challenge token
// encryption: four zero bytes followed by the sequence number as a 64 bit
// little-endian value.
func packetNonce(sequence uint64) [12]byte {
	var nonce [12]byte
	w := writer{buffer: nonce[:]}
	w.uint32(0)
	w.uint64(sequence)
	return nonce
}
