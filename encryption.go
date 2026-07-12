package netcode

const maxEncryptionMappings = MaxClients * 4

// encryptionManager maps packet source addresses to the send and receive keys
// from the private connect token, so the server can decrypt packets from
// clients that are mid-handshake or connected. Mappings expire after timeout
// seconds without being touched, or at an absolute expire time while the
// client has not yet established a connection.
type encryptionManager struct {
	numEncryptionMappings int
	timeout               [maxEncryptionMappings]int32
	expireTime            [maxEncryptionMappings]float64
	lastAccessTime        [maxEncryptionMappings]float64
	address               [maxEncryptionMappings]Address
	clientIndex           [maxEncryptionMappings]int
	sendKey               [maxEncryptionMappings][KeyBytes]byte
	receiveKey            [maxEncryptionMappings][KeyBytes]byte
}

func (m *encryptionManager) reset() {
	printf(LogLevelDebug, "reset encryption manager\n")

	m.numEncryptionMappings = 0

	for i := 0; i < maxEncryptionMappings; i++ {
		m.clientIndex[i] = -1
		m.expireTime[i] = -1.0
		m.lastAccessTime[i] = -1000.0
		m.address[i] = Address{}
		m.timeout[i] = 0
		m.sendKey[i] = [KeyBytes]byte{}
		m.receiveKey[i] = [KeyBytes]byte{}
	}
}

func (m *encryptionManager) entryExpired(index int, time float64) bool {
	return (m.timeout[index] > 0 && m.lastAccessTime[index]+float64(m.timeout[index]) < time) ||
		(m.expireTime[index] >= 0.0 && m.expireTime[index] < time)
}

func (m *encryptionManager) addEncryptionMapping(address *Address, sendKey, receiveKey []byte, time, expireTime float64, timeout int32) bool {
	for i := 0; i < m.numEncryptionMappings; i++ {
		if m.address[i].Equal(*address) && !m.entryExpired(i, time) {
			m.timeout[i] = timeout
			m.expireTime[i] = expireTime
			m.lastAccessTime[i] = time
			copy(m.sendKey[i][:], sendKey)
			copy(m.receiveKey[i][:], receiveKey)
			return true
		}
	}

	for i := 0; i < maxEncryptionMappings; i++ {
		if m.address[i].Type == AddressNone ||
			(m.entryExpired(i, time) && m.clientIndex[i] == -1) {
			m.timeout[i] = timeout
			m.address[i] = *address
			m.expireTime[i] = expireTime
			m.lastAccessTime[i] = time
			copy(m.sendKey[i][:], sendKey)
			copy(m.receiveKey[i][:], receiveKey)
			if i+1 > m.numEncryptionMappings {
				m.numEncryptionMappings = i + 1
			}
			return true
		}
	}

	return false
}

func (m *encryptionManager) removeEncryptionMapping(address *Address, time float64) bool {
	for i := 0; i < m.numEncryptionMappings; i++ {
		if m.address[i].Equal(*address) {
			m.expireTime[i] = -1.0
			m.lastAccessTime[i] = -1000.0
			m.address[i] = Address{}
			m.sendKey[i] = [KeyBytes]byte{}
			m.receiveKey[i] = [KeyBytes]byte{}

			if i+1 == m.numEncryptionMappings {
				index := i - 1
				for index >= 0 {
					if !m.entryExpired(index, time) || m.clientIndex[index] != -1 {
						break
					}
					m.address[index].Type = AddressNone
					index--
				}
				m.numEncryptionMappings = index + 1
			}

			return true
		}
	}

	return false
}

func (m *encryptionManager) findEncryptionMapping(address *Address, time float64) int {
	for i := 0; i < m.numEncryptionMappings; i++ {
		if m.address[i].Equal(*address) && !m.entryExpired(i, time) {
			m.lastAccessTime[i] = time
			return i
		}
	}
	return -1
}

func (m *encryptionManager) touch(index int, address *Address, time float64) bool {
	if !m.address[index].Equal(*address) {
		return false
	}
	m.lastAccessTime[index] = time
	return true
}

func (m *encryptionManager) setExpireTime(index int, expireTime float64) {
	m.expireTime[index] = expireTime
}

func (m *encryptionManager) getSendKey(index int) []byte {
	if index == -1 {
		return nil
	}
	return m.sendKey[index][:]
}

func (m *encryptionManager) getReceiveKey(index int) []byte {
	if index == -1 {
		return nil
	}
	return m.receiveKey[index][:]
}

func (m *encryptionManager) getTimeout(index int) int32 {
	if index == -1 {
		return 0
	}
	return m.timeout[index]
}
