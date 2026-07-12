package netcode

const (
	simulatorNumPacketEntries         = MaxClients * 256
	simulatorNumPendingReceivePackets = MaxClients * 64
	simulatorRNGSeed                  = 0x9E3779B97F4A7C15
)

type simulatorPacketEntry struct {
	from         Address
	to           Address
	deliveryTime float64
	packetData   []byte
}

// NetworkSimulator simulates latency, jitter, packet loss and duplicate
// packets between clients and servers created with it, entirely in memory.
// It is used by the test suite and is handy for testing your own protocol
// under adverse network conditions.
//
// Set the public fields before sending packets. Zero values simulate a
// perfect network.
type NetworkSimulator struct {
	LatencyMilliseconds    float32
	JitterMilliseconds     float32
	PacketLossPercent      float32
	DuplicatePacketPercent float32

	rngState                 uint64
	time                     float64
	currentIndex             int
	numPendingReceivePackets int
	packetEntries            []simulatorPacketEntry
	pendingReceivePackets    []simulatorPacketEntry
}

// NewNetworkSimulator creates a network simulator.
func NewNetworkSimulator() *NetworkSimulator {
	return &NetworkSimulator{
		rngState:              simulatorRNGSeed,
		packetEntries:         make([]simulatorPacketEntry, simulatorNumPacketEntries),
		pendingReceivePackets: make([]simulatorPacketEntry, simulatorNumPendingReceivePackets),
	}
}

// Reset discards all packets in flight and reseeds the random number generator.
func (sim *NetworkSimulator) Reset() {
	printf(LogLevelDebug, "network simulator reset\n")
	for i := range sim.packetEntries {
		sim.packetEntries[i] = simulatorPacketEntry{}
	}
	for i := 0; i < sim.numPendingReceivePackets; i++ {
		sim.pendingReceivePackets[i] = simulatorPacketEntry{}
	}
	sim.currentIndex = 0
	sim.numPendingReceivePackets = 0
	sim.rngState = simulatorRNGSeed
}

func (sim *NetworkSimulator) randomUint64() uint64 {
	// xorshift64*. self-contained and deterministic: the simulator produces the
	// same loss, jitter and duplication sequence on every run, and shares no
	// state with the application or other simulator instances.
	x := sim.rngState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	sim.rngState = x
	return x * 0x2545F4914F6CDD1D
}

func (sim *NetworkSimulator) randomFloat(a, b float32) float32 {
	random := float32(sim.randomUint64()>>40) / float32(1<<24)
	return a + random*(b-a)
}

func (sim *NetworkSimulator) queuePacket(from, to *Address, packetData []byte, delay float32) {
	entry := &sim.packetEntries[sim.currentIndex]
	entry.from = *from
	entry.to = *to
	entry.packetData = append([]byte(nil), packetData...)
	entry.deliveryTime = sim.time + float64(delay)
	sim.currentIndex = (sim.currentIndex + 1) % simulatorNumPacketEntries
}

// SendPacket queues a packet for delivery from one address to another, subject
// to the simulated latency, jitter, packet loss and duplication.
func (sim *NetworkSimulator) SendPacket(from, to *Address, packetData []byte) {
	if sim.randomFloat(0.0, 100.0) <= sim.PacketLossPercent {
		return
	}

	delay := sim.LatencyMilliseconds / 1000.0

	if sim.JitterMilliseconds > 0.0 {
		delay += sim.randomFloat(-sim.JitterMilliseconds, +sim.JitterMilliseconds) / 1000.0
	}

	sim.queuePacket(from, to, packetData, delay)

	if sim.randomFloat(0.0, 100.0) <= sim.DuplicatePacketPercent {
		sim.queuePacket(from, to, packetData, delay+sim.randomFloat(0, 1.0))
	}
}

// ReceivePackets pops up to maxPackets packets addressed to the given address
// out of the pending receive buffer. It returns the packet payloads and the
// addresses they were sent from.
func (sim *NetworkSimulator) ReceivePackets(to *Address, maxPackets int) (packetData [][]byte, from []Address) {
	for i := 0; i < sim.numPendingReceivePackets; i++ {
		if len(packetData) == maxPackets {
			break
		}

		entry := &sim.pendingReceivePackets[i]

		if entry.packetData == nil {
			continue
		}

		if !entry.to.Equal(*to) {
			continue
		}

		packetData = append(packetData, entry.packetData)
		from = append(from, entry.from)

		entry.packetData = nil
	}

	return packetData, from
}

// Update advances the simulator to the given time, moving any packets whose
// delivery time has passed into the pending receive buffer. Packets that were
// not picked up with ReceivePackets since the last update are discarded.
func (sim *NetworkSimulator) Update(time float64) {
	sim.time = time

	// discard any pending receive packets that are still in the buffer

	for i := 0; i < sim.numPendingReceivePackets; i++ {
		sim.pendingReceivePackets[i].packetData = nil
	}

	sim.numPendingReceivePackets = 0

	// walk across packet entries and move any that are ready to be received into the pending receive buffer

	for i := range sim.packetEntries {
		if sim.packetEntries[i].packetData == nil {
			continue
		}

		if sim.numPendingReceivePackets == simulatorNumPendingReceivePackets {
			break
		}

		if sim.packetEntries[i].deliveryTime <= time {
			sim.pendingReceivePackets[sim.numPendingReceivePackets] = sim.packetEntries[i]
			sim.numPendingReceivePackets++
			sim.packetEntries[i].packetData = nil
		}
	}
}
