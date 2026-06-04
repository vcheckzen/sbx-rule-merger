package adguard

import (
	"strings"

	"rule-merger/internal/ruleset"
)

func Parse(data []byte) *ruleset.CollectResult {
	res := &ruleset.CollectResult{}
	lines := strings.Split(string(data), "\n")

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@@") {
			continue
		}
		if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#$#") {
			continue
		}
		if i := strings.IndexByte(line, '$'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if host, ok := parseHostsLine(line); ok {
			res.Domains = append(res.Domains, host)
			continue
		}
		if d, suffix, ok := parseAdblockDomain(line); ok {
			if suffix {
				res.DomainSuffix = append(res.DomainSuffix, d)
			} else {
				res.Domains = append(res.Domains, d)
			}
		}
	}
	return res
}

func parseHostsLine(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", false
	}
	ip := fields[0]
	if ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "::1" {
		return "", false
	}
	host := normalizeHost(fields[1])
	if host == "" {
		return "", false
	}
	return host, true
}

func parseAdblockDomain(line string) (string, bool, bool) {
	if strings.HasPrefix(line, "||") {
		r := strings.TrimPrefix(line, "||")
		r = strings.TrimSuffix(r, "^")
		r = stripPathAndPort(r)
		r = normalizeHost(r)
		return r, true, r != ""
	}
	if strings.HasPrefix(line, "|") {
		r := strings.TrimPrefix(line, "|")
		r = strings.TrimSuffix(r, "^")
		r = stripPathAndPort(r)
		r = normalizeHost(r)
		return r, false, r != ""
	}
	if strings.HasPrefix(line, ".") {
		r := normalizeHost(strings.TrimPrefix(line, "."))
		return r, true, r != ""
	}
	if strings.ContainsAny(line, "*/^") {
		return "", false, false
	}
	r := normalizeHost(line)
	if r == "" {
		return "", false, false
	}
	return r, false, true
}

func normalizeHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.Trim(s, ".")
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.Trim(s, ".")
	if s == "" {
		return ""
	}
	if strings.Count(s, ":") > 1 {
		return ""
	}
	if isIPLiteral(s) {
		return ""
	}
	return s
}

func isIPLiteral(s string) bool {
	if s == "" {
		return false
	}
	dot := 0
	for _, r := range s {
		if r == '.' {
			dot++
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return dot == 3
}

func stripPathAndPort(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 && strings.Count(s, ":") == 1 {
		s = s[:i]
	}
	return s
}
