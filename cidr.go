// Copyright (c) 2026 Konstantin Khait

package core

import (
	"bytes"
	"encoding/binary"
	"net"
	"sort"
)

// CIDRSet is an immutable set of IPv4 and IPv6 networks optimised for Contains
// queries via binary search — O(log n) per lookup.
//
// Assumes non-overlapping ranges, which is guaranteed by standard RIR country
// allocation files (each address block belongs to exactly one country).
type CIDRSet struct {
	// IPv4 — stored as sorted uint32 pairs (network address, mask).
	starts4 []uint32
	masks4  []uint32
	// IPv6 — stored as sorted [16]byte pairs (network address, mask).
	starts6 [][16]byte
	masks6  [][16]byte
}

// ParseCIDRs builds a CIDRSet from a slice of CIDR strings.
// Invalid entries are silently skipped.  Both IPv4 and IPv6 prefixes are
// accepted.
func ParseCIDRs(cidrs []string) *CIDRSet {
	type entry4 struct{ start, mask uint32 }
	type entry6 struct{ start, mask [16]byte }

	var entries4 []entry4
	var entries6 []entry6

	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ip4 := n.IP.To4(); ip4 != nil && len(n.Mask) == 4 {
			entries4 = append(entries4, entry4{
				start: binary.BigEndian.Uint32([]byte(ip4)),
				mask:  binary.BigEndian.Uint32([]byte(n.Mask)),
			})
		} else if len(n.IP) == 16 && len(n.Mask) == 16 {
			var s, m [16]byte
			copy(s[:], n.IP)
			copy(m[:], n.Mask)
			entries6 = append(entries6, entry6{start: s, mask: m})
		}
	}

	sort.Slice(entries4, func(i, j int) bool { return entries4[i].start < entries4[j].start })
	sort.Slice(entries6, func(i, j int) bool {
		return bytes.Compare(entries6[i].start[:], entries6[j].start[:]) < 0
	})

	s := &CIDRSet{
		starts4: make([]uint32, len(entries4)),
		masks4:  make([]uint32, len(entries4)),
		starts6: make([][16]byte, len(entries6)),
		masks6:  make([][16]byte, len(entries6)),
	}
	for i, e := range entries4 {
		s.starts4[i] = e.start
		s.masks4[i] = e.mask
	}
	for i, e := range entries6 {
		s.starts6[i] = e.start
		s.masks6[i] = e.mask
	}
	return s
}

// Contains reports whether ip is covered by any network in the set.
func (s *CIDRSet) Contains(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return s.contains4(ip4)
	}
	if len(ip) == 16 {
		return s.contains6(ip)
	}
	return false
}

func (s *CIDRSet) contains4(ip4 net.IP) bool {
	if len(s.starts4) == 0 {
		return false
	}
	addr := binary.BigEndian.Uint32([]byte(ip4))
	lo, hi, idx := 0, len(s.starts4)-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		if s.starts4[mid] <= addr {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if idx < 0 {
		return false
	}
	return addr&s.masks4[idx] == s.starts4[idx]
}

func (s *CIDRSet) contains6(ip net.IP) bool {
	if len(s.starts6) == 0 {
		return false
	}
	var addr [16]byte
	copy(addr[:], ip)
	lo, hi, idx := 0, len(s.starts6)-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		if bytes.Compare(s.starts6[mid][:], addr[:]) <= 0 {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if idx < 0 {
		return false
	}
	for i := 0; i < 16; i++ {
		if addr[i]&s.masks6[idx][i] != s.starts6[idx][i] {
			return false
		}
	}
	return true
}

// Len returns the total number of networks in the set (IPv4 + IPv6).
func (s *CIDRSet) Len() int { return len(s.starts4) + len(s.starts6) }
