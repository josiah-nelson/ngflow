package main

import (
	"encoding/binary"
	"math"
	"net"
	"net/netip"
)

func clampUint64ToInt(v uint64) int {
	if v > math.MaxInt {
		return math.MaxInt
	}
	return int(v)
}

func netipAddrToIP(addr netip.Addr) net.IP {
	if addr.Is4() {
		ip4 := addr.As4()
		return net.IP(ip4[:])
	}
	ip16 := addr.As16()
	return net.IP(ip16[:])
}

func parseObservationDomainID(payload []byte) (uint32, bool) {
	if len(payload) < 16 {
		return 0, false
	}
	version := binary.BigEndian.Uint16(payload[0:2])
	switch version {
	case 9:
		return binary.BigEndian.Uint32(payload[12:16]), true
	case 10:
		return binary.BigEndian.Uint32(payload[12:16]), true
	default:
		return 0, false
	}
}
