package merge

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"rule-merger/internal/adguard"
	"rule-merger/internal/cidrmerge"
	"rule-merger/internal/config"
	"rule-merger/internal/domainmerge"
	"rule-merger/internal/downloader"
	"rule-merger/internal/ruleset"
)

type sourceJSON struct {
	Version int              `json:"version"`
	Rules   []map[string]any `json:"rules"`
}

func LoadGroup(cfg *config.Config, client *http.Client, tmpDir string, srcs []config.SourceSpec) (*ruleset.CollectResult, error) {
	out := &ruleset.CollectResult{}
	for _, src := range srcs {
		r, err := loadOne(cfg, client, tmpDir, src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Tag, err)
		}
		out.Domains = append(out.Domains, r.Domains...)
		out.DomainSuffix = append(out.DomainSuffix, r.DomainSuffix...)
		out.IPCIDR = append(out.IPCIDR, r.IPCIDR...)
	}
	return out, nil
}

func loadOne(cfg *config.Config, client *http.Client, tmpDir string, src config.SourceSpec) (*ruleset.CollectResult, error) {
	var data []byte
	var err error
	switch {
	case src.URL != "":
		data, err = downloader.FetchWithRetry(client, src.URL, cfg.DownloadRetries)
	case src.Path != "":
		data, err = os.ReadFile(src.Path)
	default:
		return nil, fmt.Errorf("missing url/path")
	}
	if err != nil {
		return nil, err
	}

	kind := strings.ToLower(src.Kind)
	format := strings.ToLower(src.Format)

	if kind == "adguard" || format == "text" || strings.HasSuffix(strings.ToLower(src.URL), ".txt") {
		return adguard.Parse(data), nil
		// txtPath := filepath.Join(tmpDir, src.Tag+".txt")
		// if err := os.WriteFile(txtPath, data, 0o644); err != nil {
		// 	return nil, err
		// }
		// defer os.Remove(txtPath)

		// srsPath := filepath.Join(tmpDir, src.Tag+".srs")
		// err := ruleset.ConvertAdGuard(cfg.SingBoxBinary, txtPath, srsPath)
		// if err != nil {
		// 	return nil, err
		// }
		// data, err = os.ReadFile(srsPath)
		// if err != nil {
		// 	return nil, err
		// }
		// defer os.Remove(srsPath)
		// format = "binary"
	}

	if format == "binary" || strings.HasSuffix(strings.ToLower(src.URL), ".srs") {
		jsonBytes, err := ruleset.Decompile(cfg.SingBoxBinary, data, tmpDir)
		if err != nil {
			return nil, err
		}
		return parseSourceJSON(jsonBytes)
	}

	return parseSourceJSON(data)
}

func parseSourceJSON(data []byte) (*ruleset.CollectResult, error) {
	var src sourceJSON
	if err := json.Unmarshal(data, &src); err != nil {
		return nil, err
	}
	res := &ruleset.CollectResult{}
	for _, r := range src.Rules {
		res.Domains = append(res.Domains, stringsFromAny(r["domain"])...)
		res.DomainSuffix = append(res.DomainSuffix, stringsFromAny(r["domain_suffix"])...)
		res.IPCIDR = append(res.IPCIDR, stringsFromAny(r["ip_cidr"])...)
	}
	return res, nil
}

func stringsFromAny(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, it := range x {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), x...)
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	default:
		return nil
	}
}

func MergeGroup(cfg *config.Config, in *ruleset.CollectResult, ads *ruleset.CollectResult) *ruleset.CollectResult {
	out := &ruleset.CollectResult{}
	out.Domains = unique(normalizeDomains(in.Domains))
	out.DomainSuffix = unique(normalizeDomains(in.DomainSuffix))
	out.IPCIDR = unique(normalizeCIDRs(in.IPCIDR, cfg.RemoveIPv6))

	if cfg.PreferShortestSfx {
		out.DomainSuffix = domainmerge.BuildShortestSuffixes(out.DomainSuffix)
	}

	if ads != nil && cfg.AdsPriorityOverCN {
		out.Domains = filterDomainCoverage(out.Domains, ads.Domains, ads.DomainSuffix)
		out.DomainSuffix = filterSuffixCoverage(out.DomainSuffix, ads.DomainSuffix)
	}

	out.Domains = filterDomainsBySuffix(out.Domains, out.DomainSuffix)
	out.Domains = unique(out.Domains)
	out.DomainSuffix = unique(out.DomainSuffix)

	if cfg.MergeIPv4 {
		out.IPCIDR = cidrmerge.Merge(out.IPCIDR, cfg.DropCoveredIPv4)
	}

	sort.Strings(out.Domains)
	sort.Strings(out.DomainSuffix)
	sort.Strings(out.IPCIDR)
	return out
}

func BuildSourceJSON(cfg *config.Config, r *ruleset.CollectResult) ([]byte, error) {
	obj := sourceJSON{
		Version: cfg.SourceVersion,
		Rules: []map[string]any{
			makeRule(r),
		},
	}
	b, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func makeRule(r *ruleset.CollectResult) map[string]any {
	m := map[string]any{}
	if len(r.Domains) > 0 {
		m["domain"] = r.Domains
	}
	if len(r.DomainSuffix) > 0 {
		m["domain_suffix"] = r.DomainSuffix
	}
	if len(r.IPCIDR) > 0 {
		m["ip_cidr"] = r.IPCIDR
	}
	return m
}

func WriteOutputs(cfg *config.Config, name string, r *ruleset.CollectResult) error {
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.TmpDir, 0o755); err != nil {
		return err
	}

	jsonBytes, err := BuildSourceJSON(cfg, r)
	if err != nil {
		return err
	}
	jsonPath := filepath.Join(cfg.OutDir, name+".json")
	if cfg.KeepJSON {
		if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
			return err
		}
	} else {
		// temporary JSON for sing-box compile
		if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
			return err
		}
		defer os.Remove(jsonPath)
	}

	if cfg.CompileSRS {
		srsPath := filepath.Join(cfg.OutDir, name+".srs")
		if err := ruleset.Compile(cfg.SingBoxBinary, jsonPath, srsPath); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.Trim(s, ".")
		s = stripPathAndPort(s)
		if s == "" || isIPLiteral(s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func normalizeCIDRs(in []string, removeIPv6 bool) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netipParsePrefix(s)
		if err != nil {
			continue
		}
		if removeIPv6 && !isIPv4Prefix(p) {
			continue
		}
		if isIPv4Prefix(p) {
			out = append(out, p.s)
		}
	}
	return out
}

func filterDomainsBySuffix(domains, suffixes []string) []string {
	if len(domains) == 0 || len(suffixes) == 0 {
		return domains
	}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if coveredByAnySuffix(d, suffixes) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func filterDomainCoverage(domains, exactDomains, suffixes []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if contains(exactDomains, d) || coveredByAnySuffix(d, suffixes) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func filterSuffixCoverage(suffixes, covered []string) []string {
	out := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		if isCoveredSuffix(s, covered) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func coveredByAnySuffix(domain string, suffixes []string) bool {
	for _, s := range suffixes {
		if domain == s || strings.HasSuffix(domain, "."+s) {
			return true
		}
	}
	return false
}

func isCoveredSuffix(s string, covered []string) bool {
	for _, c := range covered {
		if c == s || strings.HasSuffix(s, "."+c) {
			return true
		}
	}
	return false
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

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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

func isIPLiteral(s string) bool {
	return net.ParseIP(s) != nil
}

type prefix struct {
	s  string
	v4 bool
}

func netipParsePrefix(s string) (prefix, error) {
	// lightweight parser via net package-compatible formatting
	if strings.Contains(s, ":") && strings.Contains(s, "/") {
		return prefix{s: s, v4: false}, nil
	}
	if strings.Count(s, ".") == 3 && strings.Contains(s, "/") {
		return prefix{s: s, v4: true}, nil
	}
	// keep lenient; cidrmerge does the actual parse later
	return prefix{s: s, v4: strings.Count(s, ".") == 3}, nil
}

func isIPv4Prefix(p prefix) bool { return p.v4 }
