package netcode

// replayEmpty marks a slot in the replay protection buffer that has not been
// used yet. The sequence 0xFFFFFFFFFFFFFFFF is reserved for this marker and is
// never a valid packet sequence.
const replayEmpty = uint64(0xFFFFFFFFFFFFFFFF)

// replayProtection stops an attacker from recording a valid packet and
// replaying it back at a later time in an attempt to break the protocol.
// It is applied to keep-alive, payload and disconnect packets on both the
// client and the server.
type replayProtection struct {
	mostRecentSequence uint64
	receivedPacket     [replayProtectionBufferSize]uint64
}

func (r *replayProtection) reset() {
	r.mostRecentSequence = 0
	for i := range r.receivedPacket {
		r.receivedPacket[i] = replayEmpty
	}
}

func (r *replayProtection) alreadyReceived(sequence uint64) bool {
	// the empty-slot marker is not a valid sequence number. refuse it on every
	// check so it can never be recorded or advance the most recent sequence.

	if sequence == replayEmpty {
		return true
	}

	// written so it cannot overflow: "sequence + BUFFER_SIZE <= most_recent" wraps for
	// sequence values near the top of the sequence space and falsely rejects them as replays

	if r.mostRecentSequence >= replayProtectionBufferSize &&
		sequence <= r.mostRecentSequence-replayProtectionBufferSize {
		return true
	}

	index := sequence % replayProtectionBufferSize

	if r.receivedPacket[index] == replayEmpty {
		return false
	}

	return r.receivedPacket[index] >= sequence
}

func (r *replayProtection) advanceSequence(sequence uint64) {
	if sequence == replayEmpty {
		return
	}
	if sequence > r.mostRecentSequence {
		r.mostRecentSequence = sequence
	}
	r.receivedPacket[sequence%replayProtectionBufferSize] = sequence
}
