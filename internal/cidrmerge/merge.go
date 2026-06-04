package cidrmerge

import (
	"net/netip"
	"sort"
)

type v4Prefix struct {
	net uint32
	len uint8
}

func Merge(list []string, dropCovered bool) []string {
	set := map[v4Prefix]struct{}{}
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		set[toV4(p)] = struct{}{}
	}
	set = aggregate(set)

	items := make([]v4Prefix, 0, len(set))
	for p := range set {
		items = append(items, p)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].len != items[j].len {
			return items[i].len < items[j].len
		}
		if items[i].net != items[j].net {
			return items[i].net < items[j].net
		}
		return false
	})

	outItems := make([]v4Prefix, 0, len(items))
	for _, p := range items {
		if dropCovered {
			covered := false
			for _, k := range outItems {
				if covers(k, p) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
		}
		outItems = append(outItems, p)
	}

	out := make([]string, 0, len(outItems))
	for _, p := range outItems {
		out = append(out, fromV4(p).String())
	}
	sort.Strings(out)
	return unique(out)
}

func aggregate(set map[v4Prefix]struct{}) map[v4Prefix]struct{} {
	for {
		changed := false
		byLen := map[uint8]map[uint32]struct{}{}
		for p := range set {
			if byLen[p.len] == nil {
				byLen[p.len] = map[uint32]struct{}{}
			}
			byLen[p.len][p.net] = struct{}{}
		}

		for plen := 32; plen >= 1; plen-- {
			m := byLen[uint8(plen)]
			if len(m) == 0 {
				continue
			}
			visited := map[uint32]struct{}{}
			for p := range m {
				if _, ok := visited[p]; ok {
					continue
				}
				sibling := p ^ (uint32(1) << (32 - uint(plen)))
				if _, ok := m[sibling]; !ok {
					continue
				}
				parent := p & mask32(uint(plen-1))
				delete(set, v4Prefix{net: p, len: uint8(plen)})
				delete(set, v4Prefix{net: sibling, len: uint8(plen)})
				set[v4Prefix{net: parent, len: uint8(plen-1)}] = struct{}{}
				visited[p] = struct{}{}
				visited[sibling] = struct{}{}
				changed = true
			}
		}

		if !changed {
			return set
		}
	}
}

func toV4(p netip.Prefix) v4Prefix {
	a := p.Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	return v4Prefix{net: n & mask32(uint(p.Bits())), len: uint8(p.Bits())}
}

func fromV4(p v4Prefix) netip.Prefix {
	b := [4]byte{byte(p.net >> 24), byte(p.net >> 16), byte(p.net >> 8), byte(p.net)}
	return netip.PrefixFrom(netip.AddrFrom4(b), int(p.len)).Masked()
}

func covers(parent, child v4Prefix) bool {
	if parent.len > child.len {
		return false
	}
	pm := mask32(uint(parent.len))
	return (parent.net & pm) == (child.net & pm)
}

func mask32(bits uint) uint32 {
	if bits == 0 {
		return 0
	}
	if bits >= 32 {
		return ^uint32(0)
	}
	return ^uint32(0) << (32 - bits)
}

func unique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}