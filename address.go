package netcode

import (
	"fmt"
	"net/netip"
	"strings"
)

// Address types.
const (
	AddressNone = 0
	AddressIPv4 = 1
	AddressIPv6 = 2
)

// Address is a network address: an IPv4 or IPv6 address plus a port.
//
// IPv4 addresses are stored as four bytes a.b.c.d in IPv4[0..3]. IPv6 addresses
// are stored as eight 16 bit groups [a:b:c:d:e:f:g:h] in IPv6[0..7], in the
// order they appear in the address string.
type Address struct {
	Type uint8
	IPv4 [4]byte
	IPv6 [8]uint16
	Port uint16
}

func parsePort(s string) (uint16, bool) {
	// the port must be all digits and fit in [0,65535]. anything else is an error,
	// rather than silent truncation.
	if len(s) == 0 {
		return 0, false
	}
	value := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		value = value*10 + int(s[i]-'0')
		if value > 65535 {
			return 0, false
		}
	}
	return uint16(value), true
}

func addressFromNetip(addr netip.Addr, port uint16) Address {
	addr = addr.Unmap()
	if addr.Is4() {
		return Address{Type: AddressIPv4, IPv4: addr.As4(), Port: port}
	}
	var address Address
	address.Type = AddressIPv6
	address.Port = port
	raw := addr.As16()
	for i := 0; i < 8; i++ {
		address.IPv6[i] = uint16(raw[i*2])<<8 | uint16(raw[i*2+1])
	}
	return address
}

func (address *Address) toNetip() netip.AddrPort {
	if address.Type == AddressIPv4 {
		return netip.AddrPortFrom(netip.AddrFrom4(address.IPv4), address.Port)
	}
	var raw [16]byte
	for i := 0; i < 8; i++ {
		raw[i*2] = byte(address.IPv6[i] >> 8)
		raw[i*2+1] = byte(address.IPv6[i])
	}
	return netip.AddrPortFrom(netip.AddrFrom16(raw), address.Port)
}

// ParseAddress parses an address string in one of the following forms:
//
//	"a.b.c.d"          IPv4 address
//	"a.b.c.d:port"     IPv4 address and port
//	"a:b:...:h"        IPv6 address
//	"[a:b:...:h]"      IPv6 address in brackets
//	"[a:b:...:h]:port" IPv6 address and port
//
// If a port is omitted, it is assumed to be zero.
func ParseAddress(addressString string) (Address, error) {
	var address Address

	// first try to parse the string as an IPv6 address:
	// 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
	// 2. otherwise try to parse as a raw IPv6 address

	if len(addressString) > maxAddressStringLength-1 {
		addressString = addressString[:maxAddressStringLength-1]
	}

	s := addressString

	if strings.HasPrefix(s, "[") {
		baseIndex := len(s) - 1
		// note: no need to search past 6 characters as ":65535" is longest possible port value
		for i := 0; i < 6; i++ {
			index := baseIndex - i
			if index < 3 {
				break
			}
			if s[index] == ':' && s[index-1] == ']' {
				port, ok := parsePort(s[index+1:])
				if !ok {
					return Address{}, fmt.Errorf("netcode: invalid port in address %q", addressString)
				}
				address.Port = port
				s = s[:index-1]
				break
			}
		}

		// if a port is omitted, strip the trailing ']' so "[addr]" parses as just the address

		s = strings.TrimSuffix(s, "]")

		s = s[1:]
	}

	if addr, err := netip.ParseAddr(s); err == nil && addr.Is6() {
		// don't unmap 4-in-6 addresses here: "::ffff:a.b.c.d" parses as IPv6,
		// matching inet_pton in the C implementation
		address.Type = AddressIPv6
		raw := addr.As16()
		for i := 0; i < 8; i++ {
			address.IPv6[i] = uint16(raw[i*2])<<8 | uint16(raw[i*2+1])
		}
		return address, nil
	}

	// otherwise it's probably an IPv4 address:
	// 1. look for ":portnum", if found save the portnum and strip it out
	// 2. parse the remaining ipv4 address

	baseIndex := len(s) - 1
	for i := 0; i < 6; i++ {
		index := baseIndex - i
		if index < 0 {
			break
		}
		if s[index] == ':' {
			port, ok := parsePort(s[index+1:])
			if !ok {
				return Address{}, fmt.Errorf("netcode: invalid port in address %q", addressString)
			}
			address.Port = port
			s = s[:index]
			break
		}
	}

	if addr, err := netip.ParseAddr(s); err == nil && addr.Is4() {
		address.Type = AddressIPv4
		address.IPv4 = addr.As4()
		return address, nil
	}

	return Address{}, fmt.Errorf("netcode: failed to parse address %q", addressString)
}

// String returns the address formatted so that it can be parsed back with
// ParseAddress. A zero port is omitted.
func (address Address) String() string {
	switch address.Type {
	case AddressIPv6:
		addrPort := address.toNetip()
		if address.Port == 0 {
			return addrPort.Addr().String()
		}
		return fmt.Sprintf("[%s]:%d", addrPort.Addr().String(), address.Port)
	case AddressIPv4:
		if address.Port != 0 {
			return fmt.Sprintf("%d.%d.%d.%d:%d", address.IPv4[0], address.IPv4[1], address.IPv4[2], address.IPv4[3], address.Port)
		}
		return fmt.Sprintf("%d.%d.%d.%d", address.IPv4[0], address.IPv4[1], address.IPv4[2], address.IPv4[3])
	default:
		return "NONE"
	}
}

// Equal reports whether two addresses have the same type, address and port.
// Addresses of type AddressNone are never equal to anything, including each other.
func (address Address) Equal(other Address) bool {
	if address.Type != other.Type {
		return false
	}
	if address.Port != other.Port {
		return false
	}
	switch address.Type {
	case AddressIPv4:
		return address.IPv4 == other.IPv4
	case AddressIPv6:
		return address.IPv6 == other.IPv6
	default:
		return false
	}
}
