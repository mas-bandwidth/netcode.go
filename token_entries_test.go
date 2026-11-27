package netcode

import (
	"bytes"
	"testing"
)

func TestConnectTokenEntries(t *testing.T) {
	var entries [maxConnectTokenEntries]connectTokenEntry
	connectTokenEntriesReset(&entries)

	addressA, err := ParseAddress("[::1]:50000")
	check(t, err == nil)
	addressB, err := ParseAddress("[::1]:50001")
	check(t, err == nil)

	currentTimestamp := uint64(1000)
	expireTimestamp := currentTimestamp + 30
	timeoutSeconds := int32(30)

	var mac [MacBytes]byte
	saltA := [connectSaltBytes]byte(bytes.Repeat([]byte{0xAA}, connectSaltBytes))
	saltB := [connectSaltBytes]byte(bytes.Repeat([]byte{0xBB}, connectSaltBytes))

	// a connect token the history has not seen creates a pending entry
	mac[0] = 1

	index := connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 100.0, timeoutSeconds)
	check(t, index >= 0)
	check(t, entries[index].state == connectTokenEntryPending)
	check(t, entries[index].time == 100.0)
	check(t, entries[index].expireTimestamp == expireTimestamp)
	check(t, entries[index].clientSalt == saltA)
	check(t, entries[index].address.Equal(addressA))

	// a pending entry admits a retransmitted connection request from the same address with the
	// same client salt within timeoutSeconds, and the entry time is not refreshed
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 130.0, timeoutSeconds) == index)
	check(t, entries[index].time == 100.0)

	// a pending entry refuses a different client salt without mutating the entry
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltB, expireTimestamp, currentTimestamp, 110.0, timeoutSeconds) == connectTokenEntryRefused)
	check(t, entries[index].clientSalt == saltA)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 120.0, timeoutSeconds) == index)

	// a pending entry refuses every other address
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressB, mac[:], saltA, expireTimestamp, currentTimestamp, 120.0, timeoutSeconds) == connectTokenEntryRefused)

	// once timeoutSeconds have elapsed since creation, a pending entry admits nothing
	// (unless timeoutSeconds <= 0, which disables the timeout)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 130.1, timeoutSeconds) == connectTokenEntryRefused)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 200.0, 0) == index)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 200.0, -1) == index)

	// a consumed entry admits nothing, including the address and salt that used the connect token
	connectTokenEntriesConsume(&entries, index, mac[:])

	check(t, entries[index].state == connectTokenEntryConsumed)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 110.0, timeoutSeconds) == connectTokenEntryRefused)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressB, mac[:], saltA, expireTimestamp, currentTimestamp, 110.0, timeoutSeconds) == connectTokenEntryRefused)

	// a history whose entries all hold unexpired connect tokens refuses a new connect token
	// instead of evicting one
	for i := 1; i < maxConnectTokenEntries; i++ {
		var fillMac [MacBytes]byte
		fillMac[0] = uint8(i + 1)
		fillMac[1] = uint8((i + 1) >> 8)
		idx := connectTokenEntriesFindOrAdd(&entries, &addressA, fillMac[:], saltA, expireTimestamp, currentTimestamp, 400.0, timeoutSeconds)
		check(t, idx >= 0)
	}

	var overflowMac [MacBytes]byte
	overflowMac[0] = 0xFF
	overflowMac[1] = 0xFF

	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, overflowMac[:], saltA, expireTimestamp, currentTimestamp, 500.0, timeoutSeconds) == connectTokenHistoryFull)

	// the consumed entry is still refusing its connect token, and was not evicted by the flood
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], saltA, expireTimestamp, currentTimestamp, 500.0, timeoutSeconds) == connectTokenEntryRefused)

	// entries live until their connect token expires. once they have, the history takes new connect tokens again
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, overflowMac[:], saltA, expireTimestamp, expireTimestamp, 600.0, timeoutSeconds) >= 0)
}

func TestConnectTokenEntriesConsumeOnlyMatchingToken(t *testing.T) {
	var entries [maxConnectTokenEntries]connectTokenEntry
	connectTokenEntriesReset(&entries)

	address, err := ParseAddress("[::1]:50000")
	check(t, err == nil)

	var firstMac, secondMac [MacBytes]byte
	firstMac[0] = 1
	secondMac[0] = 2
	salt := [connectSaltBytes]byte{1, 2, 3, 4, 5, 6, 7, 8}

	firstExpireTimestamp := uint64(1000)
	firstIndex := connectTokenEntriesFindOrAdd(&entries, &address, firstMac[:], salt,
		firstExpireTimestamp, firstExpireTimestamp-1, 100.0, 30)
	check(t, firstIndex >= 0)

	// the first token expires and the second takes over its history slot
	secondExpireTimestamp := firstExpireTimestamp + 100
	secondIndex := connectTokenEntriesFindOrAdd(&entries, &address, secondMac[:], salt,
		secondExpireTimestamp, firstExpireTimestamp, 200.0, 30)
	check(t, secondIndex == firstIndex)
	check(t, entries[secondIndex].state == connectTokenEntryPending)

	// a late response for the first token must leave the second token pending
	connectTokenEntriesConsume(&entries, firstIndex, firstMac[:])
	check(t, entries[secondIndex].state == connectTokenEntryPending)

	// the second token's retried connection request within timeoutSeconds is still admitted
	check(t, connectTokenEntriesFindOrAdd(&entries, &address, secondMac[:], salt,
		secondExpireTimestamp, firstExpireTimestamp, 220.0, 30) == secondIndex)
}

func TestConnectTokenEntriesConsumeBounds(t *testing.T) {
	var entries [maxConnectTokenEntries]connectTokenEntry
	connectTokenEntriesReset(&entries)

	// Out of range indices should not panic
	connectTokenEntriesConsume(&entries, -1, nil)
	connectTokenEntriesConsume(&entries, maxConnectTokenEntries, nil)
	connectTokenEntriesConsume(&entries, 99999, nil)
}
