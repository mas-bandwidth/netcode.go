package netcode

const maxConnectTokenEntries = MaxClients * 8

// connectTokenEntry records that a connect token (identified by its private
// data MAC) has been used from a particular address, so the same token cannot
// be replayed from a different address.
type connectTokenEntry struct {
	time    float64
	mac     [MacBytes]byte
	address Address
}

func connectTokenEntriesReset(entries *[maxConnectTokenEntries]connectTokenEntry) {
	for i := range entries {
		entries[i].time = -1000.0
		entries[i].mac = [MacBytes]byte{}
		entries[i].address = Address{}
	}
}

func connectTokenEntriesFindOrAdd(entries *[maxConnectTokenEntries]connectTokenEntry, address *Address, mac []byte, time float64) bool {
	// find the matching entry for the token mac and the oldest token entry. constant time worst case. This is intentional!

	matchingTokenIndex := -1
	oldestTokenIndex := -1
	oldestTokenTime := 0.0

	for i := 0; i < maxConnectTokenEntries; i++ {
		if [MacBytes]byte(mac) == entries[i].mac {
			matchingTokenIndex = i
		}

		if oldestTokenIndex == -1 || entries[i].time < oldestTokenTime {
			oldestTokenTime = entries[i].time
			oldestTokenIndex = i
		}
	}

	// if no entry is found with the mac, this is a new connect token. replace the oldest token entry.

	if matchingTokenIndex == -1 {
		entries[oldestTokenIndex].time = time
		entries[oldestTokenIndex].address = *address
		copy(entries[oldestTokenIndex].mac[:], mac)
		return true
	}

	// allow connect tokens we have already seen from the same address

	return entries[matchingTokenIndex].address.Equal(*address)
}
