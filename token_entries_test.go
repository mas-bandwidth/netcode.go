package netcode

import (
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

	var mac [MacBytes]byte

	// a connect token the history has not seen creates a pending entry
	mac[0] = 1

	index := connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], expireTimestamp, currentTimestamp, 100.0)
	check(t, index >= 0)
	check(t, entries[index].state == connectTokenEntryPending)
	check(t, entries[index].time == 100.0)
	check(t, entries[index].expireTimestamp == expireTimestamp)
	check(t, entries[index].address.Equal(addressA))

	// a pending entry admits a retransmitted connection request from the address that created it,
	// and the entry time is not refreshed
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], expireTimestamp, currentTimestamp, 200.0) == index)
	check(t, entries[index].time == 100.0)

	// a pending entry refuses every other address
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressB, mac[:], expireTimestamp, currentTimestamp, 200.0) == connectTokenEntryRefused)

	// a consumed entry admits nothing, including the address that used the connect token
	connectTokenEntriesConsume(&entries, index)

	check(t, entries[index].state == connectTokenEntryConsumed)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], expireTimestamp, currentTimestamp, 300.0) == connectTokenEntryRefused)
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressB, mac[:], expireTimestamp, currentTimestamp, 300.0) == connectTokenEntryRefused)

	// a history whose entries all hold unexpired connect tokens refuses a new connect token
	// instead of evicting one
	for i := 1; i < maxConnectTokenEntries; i++ {
		var fillMac [MacBytes]byte
		fillMac[0] = uint8(i + 1)
		fillMac[1] = uint8((i + 1) >> 8)
		idx := connectTokenEntriesFindOrAdd(&entries, &addressA, fillMac[:], expireTimestamp, currentTimestamp, 400.0)
		check(t, idx >= 0)
	}

	var overflowMac [MacBytes]byte
	overflowMac[0] = 0xFF
	overflowMac[1] = 0xFF

	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, overflowMac[:], expireTimestamp, currentTimestamp, 500.0) == connectTokenHistoryFull)

	// the consumed entry is still refusing its connect token, and was not evicted by the flood
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, mac[:], expireTimestamp, currentTimestamp, 500.0) == connectTokenEntryRefused)

	// entries live until their connect token expires. once they have, the history takes new connect tokens again
	check(t, connectTokenEntriesFindOrAdd(&entries, &addressA, overflowMac[:], expireTimestamp, expireTimestamp, 600.0) >= 0)
}

func TestConnectTokenEntriesConsumeBounds(t *testing.T) {
	var entries [maxConnectTokenEntries]connectTokenEntry
	connectTokenEntriesReset(&entries)

	// Out of range indices should not panic
	connectTokenEntriesConsume(&entries, -1)
	connectTokenEntriesConsume(&entries, maxConnectTokenEntries)
	connectTokenEntriesConsume(&entries, 99999)
}
