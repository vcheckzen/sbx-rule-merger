package adguard

import (
	"regexp"
	"strings"

	"rule-merger/internal/ruleset"
)

// 严格的域名合法性正则，确保提取出来的域名符合 RFC 规范
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9_]([a-zA-Z0-9-_]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,63}$`)

func Parse(data []byte) *ruleset.CollectResult {
	res := &ruleset.CollectResult{}
	lines := strings.Split(string(data), "\n")

	for _, raw := range lines {
		line := strings.TrimSpace(raw)

		// 1. 快速前置过滤：空行、注释(!, #)、元数据([) 以及白名单(@@)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "@@") {
			continue
		}

		// 2. 核心改变：只保留以 "||" 开头的广告域规则，其余关键字/元素隐藏规则一律丢弃
		if !strings.HasPrefix(line, "||") {
			continue
		}

		if !strings.HasSuffix(line, "^") {
			continue
		}

		// 3. 剥离规则末尾的修饰符 (丢弃 $ 之后的所有内容，如 $third-party,important)
		// if i := strings.IndexByte(line, '$'); i >= 0 {
		// 	line = line[:i]
		// }
		// line = strings.TrimSpace(line)

		// 4. 提取并验证域名
		if domain, ok := parseStrictDomainSuffix(line); ok {
			// AdGuard 的 "||" 对应 sing-box 的 "domain_suffix"
			res.DomainSuffix = append(res.DomainSuffix, domain)
		}
	}
	return res
}

func parseStrictDomainSuffix(line string) (string, bool) {
	// 移除 "||" 前缀
	r := strings.TrimPrefix(line, "||")

	// 过滤掉中间带通配符 * 的复杂规则（因为 sing-box 的 domain_suffix 不支持中间通配符）
	if strings.Contains(r, "*") {
		return "", false
	}

	// 斩断 AdGuard 的分隔符 ^ 及其后面的所有路径/参数内容
	if i := strings.IndexByte(r, '^'); i >= 0 {
		r = r[:i]
	}

	// 安全防线：如果规则不规范没写 ^ 却带了 / 或 ?，也进行截断
	// if i := strings.IndexAny(r, "/?"); i >= 0 {
	// 	r = r[:i]
	// }

	// 彻底清洗域名两端
	r = strings.TrimSpace(strings.ToLower(r))
	r = strings.Trim(r, ".")

	// 剥离端口号 (确保只有一个冒号，避免误伤 IPv6 地址)
	// if i := strings.IndexByte(r, ':'); i >= 0 && strings.Count(r, ":") == 1 {
	// 	r = r[:i]
	// }

	// 最终进行严格的域名格式校验 + 排除纯 IP
	if r != "" && domainRegex.MatchString(r) && !isIPLiteral(r) {
		return r, true
	}

	return "", false
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
