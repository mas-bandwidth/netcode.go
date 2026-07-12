package netcode

import "encoding/binary"

// All data on the wire is little-endian. These helpers mirror the read/write
// functions in the C implementation: a cursor over a fixed-size buffer that
// panics past the end, which the callers never do by construction.

type writer struct {
	buffer []byte
	pos    int
}

func (w *writer) uint8(value uint8) {
	w.buffer[w.pos] = value
	w.pos++
}

func (w *writer) uint16(value uint16) {
	binary.LittleEndian.PutUint16(w.buffer[w.pos:], value)
	w.pos += 2
}

func (w *writer) uint32(value uint32) {
	binary.LittleEndian.PutUint32(w.buffer[w.pos:], value)
	w.pos += 4
}

func (w *writer) uint64(value uint64) {
	binary.LittleEndian.PutUint64(w.buffer[w.pos:], value)
	w.pos += 8
}

func (w *writer) bytes(data []byte) {
	copy(w.buffer[w.pos:], data)
	w.pos += len(data)
}

type reader struct {
	buffer []byte
	pos    int
}

func (r *reader) uint8() uint8 {
	value := r.buffer[r.pos]
	r.pos++
	return value
}

func (r *reader) uint16() uint16 {
	value := binary.LittleEndian.Uint16(r.buffer[r.pos:])
	r.pos += 2
	return value
}

func (r *reader) uint32() uint32 {
	value := binary.LittleEndian.Uint32(r.buffer[r.pos:])
	r.pos += 4
	return value
}

func (r *reader) uint64() uint64 {
	value := binary.LittleEndian.Uint64(r.buffer[r.pos:])
	r.pos += 8
	return value
}

func (r *reader) bytes(data []byte) {
	copy(data, r.buffer[r.pos:r.pos+len(data)])
	r.pos += len(data)
}
