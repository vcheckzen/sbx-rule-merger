# rule-merger v2

A rule-set merger for sing-box:

- merges `cn-ip`, `cn-site`, `ads`
- decompiles `.srs` by using `sing-box rule-set decompile`
- converts AdGuard DNS filter lists into sing-box rules by using `sing-box rule-set convert --type adguard`
- removes IPv6 CIDR rules
- merges IPv4 CIDRs with sibling aggregation
- keeps shorter `domain_suffix` entries
- gives ads precedence over CN rules

## Requirements

- sing-box in PATH, or set `sing_box_binary` in config
- Go 1.22+

## Build

```bash
go build ./cmd/rule-merger
```

## Run

```bash
./rule-merger -config config.json
```

## Output

- `out/ads.json`
- `out/ads.srs` if `compile_srs=true`
- `out/cn-ip.json`
- `out/cn-ip.srs`
- `out/cn-site.json`
- `out/cn-site.srs`
