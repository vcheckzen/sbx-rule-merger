package domainmerge

import (
	"sort"
	"strings"
)

type Node struct {
	End bool
	Child map[string]*Node
}

func NewNode() *Node {
	return &Node{Child: map[string]*Node{}}
}

func Insert(root *Node, domain string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	for i := len(parts)-1; i >= 0; i-- {
		if root.End {
			return false
		}
		p := parts[i]
		if p == "" {
			continue
		}
		if root.Child[p] == nil {
			root.Child[p] = NewNode()
		}
		root = root.Child[p]
	}
	root.End = true
	root.Child = nil
	return true
}

func BuildShortestSuffixes(list []string) []string {
	root := NewNode()
	in := append([]string(nil), list...)
	sort.Slice(in, func(i, j int) bool {
		li := labelCount(in[i])
		lj := labelCount(in[j])
		if li != lj {
			return li < lj
		}
		if len(in[i]) != len(in[j]) {
			return len(in[i]) < len(in[j])
		}
		return in[i] < in[j]
	})
	out := make([]string, 0, len(in))
	for _, d := range in {
		if Insert(root, d) {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return unique(out)
}

func labelCount(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, ".") + 1
}

func unique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
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