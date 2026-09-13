package netcode

const maxConnectTokenEntries = MaxClients * 8

const (
	connectTokenEntryFree     = 0
	connectTokenEntryPending  = 1
	connectTokenEntryConsumed = 2

	connectTokenEntryRefused = -1
	connectTokenHistoryFull  = -2
)

// connectTokenEntry records that a connect token (identified by its private
// data MAC) has been seen by the server, tracking its pending or consumed state
// so a token is admitted for at most one connection.
type connectTokenEntry struct {
	state           int
	time            float64
	expireTimestamp uint64
	mac             [MacBytes]byte
	address         Address
}

func connectTokenEntriesReset(entries *[maxConnectTokenEntries]connectTokenEntry) {
	for i := range entries {
		entries[i].state = connectTokenEntryFree
		entries[i].time = -1000.0
		entries[i].expireTimestamp = 0
		entries[i].mac = [MacBytes]byte{}
		entries[i].address = Address{}
	}
}

// connectTokenEntriesFindOrAdd finds or adds an entry for the given connect token MAC.
// Returns the index of the entry that admits this connection request, or one of
// connectTokenEntryRefused and connectTokenHistoryFull.
//
// An entry is created pending the first time a connect token is seen, and becomes consumed
// when the client that presented it is installed in a client slot. A pending entry admits
// a retransmitted connection request from the address that created it, so a handshake that
// loses a packet still completes. A consumed entry admits nothing, whatever the address, so
// the keys inside a connect token encrypt exactly one session.
//
// An entry lives until its connect token expires. A history whose entries all hold unexpired
// connect tokens refuses a new connect token instead of evicting one, because evicting is
// how a flood of connect tokens would reopen a token that has already been used.
func connectTokenEntriesFindOrAdd(entries *[maxConnectTokenEntries]connectTokenEntry,
	address *Address,
	mac []byte,
	expireTimestamp uint64,
	currentTimestamp uint64,
	time float64) int {

	// find the matching entry for the token mac and the first entry free to take a new token.
	// constant time worst case. This is intentional!

	matchingTokenIndex := -1
	freeTokenIndex := -1

	for i := 0; i < maxConnectTokenEntries; i++ {
		if entries[i].state != connectTokenEntryFree && [MacBytes]byte(mac) == entries[i].mac {
			matchingTokenIndex = i
		}

		if freeTokenIndex == -1 &&
			(entries[i].state == connectTokenEntryFree || entries[i].expireTimestamp <= currentTimestamp) {
			freeTokenIndex = i
		}
	}

	// if no entry is found with the mac, this is a new connect token

	if matchingTokenIndex == -1 {
		if freeTokenIndex == -1 {
			return connectTokenHistoryFull
		}

		entries[freeTokenIndex].state = connectTokenEntryPending
		entries[freeTokenIndex].time = time
		entries[freeTokenIndex].expireTimestamp = expireTimestamp
		entries[freeTokenIndex].address = *address
		copy(entries[freeTokenIndex].mac[:], mac)
		return freeTokenIndex
	}

	// a pending entry admits the address that created it, and nothing else. a consumed entry admits nothing.
	// the entry time is set when the entry is created and is never refreshed.

	if entries[matchingTokenIndex].state == connectTokenEntryPending &&
		entries[matchingTokenIndex].address.Equal(*address) {
		return matchingTokenIndex
	}

	return connectTokenEntryRefused
}

func connectTokenEntriesConsume(entries *[maxConnectTokenEntries]connectTokenEntry, index int) {
	if index >= 0 && index < maxConnectTokenEntries {
		entries[index].state = connectTokenEntryConsumed
	}
}
