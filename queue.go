package netcode

// packetQueue is a fixed size ring buffer of received payload packets waiting
// to be delivered to the application. When the queue is full, newly received
// packets are dropped.
type packetQueue struct {
	numPackets int
	startIndex int
	packets    [packetQueueSize]*connectionPayload
	sequences  [packetQueueSize]uint64
}

func (q *packetQueue) clear() {
	q.numPackets = 0
	q.startIndex = 0
	q.packets = [packetQueueSize]*connectionPayload{}
	q.sequences = [packetQueueSize]uint64{}
}

func (q *packetQueue) push(packet *connectionPayload, sequence uint64) bool {
	if q.numPackets == packetQueueSize {
		return false
	}
	index := (q.startIndex + q.numPackets) % packetQueueSize
	q.packets[index] = packet
	q.sequences[index] = sequence
	q.numPackets++
	return true
}

func (q *packetQueue) pop() (*connectionPayload, uint64) {
	if q.numPackets == 0 {
		return nil, 0
	}
	packet := q.packets[q.startIndex]
	sequence := q.sequences[q.startIndex]
	q.packets[q.startIndex] = nil
	q.startIndex = (q.startIndex + 1) % packetQueueSize
	q.numPackets--
	return packet, sequence
}
