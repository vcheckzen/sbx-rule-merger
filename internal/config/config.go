package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type SourceSpec struct {
	Tag   string `json:"tag"`
	Type  string `json:"type"`
	Format string `json:"format"`
	Kind  string `json:"kind,omitempty"`
	URL   string `json:"url,omitempty"`
	Path  string `json:"path,omitempty"`
}

type Config struct {
	SourceVersion int `json:"source_version"`

	RemoveIPv6        bool `json:"remove_ipv6"`
	MergeIPv4         bool `json:"merge_ipv4"`
	DropCoveredIPv4   bool `json:"drop_covered_ipv4"`
	PreferShortestSfx bool `json:"prefer_shortest_suffix"`
	AdsPriorityOverCN bool `json:"ads_priority_over_cn"`

	CompileSRS bool `json:"compile_srs"`
	KeepJSON   bool `json:"keep_json"`

	SingBoxBinary string `json:"sing_box_binary"`
	OutDir        string `json:"out_dir"`
	TmpDir        string `json:"tmp_dir"`

	HTTPTimeoutSec     int `json:"http_timeout_sec"`
	DownloadRetries    int `json:"download_retries"`
	DownloadConcurrency int `json:"download_concurrency"`

	CNIP   []SourceSpec `json:"cn_ip"`
	CNSite []SourceSpec `json:"cn_site"`
	ADS    []SourceSpec `json:"ads"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.SourceVersion == 0 {
		cfg.SourceVersion = 3
	}
	if cfg.SingBoxBinary == "" {
		cfg.SingBoxBinary = "sing-box"
	}
	if cfg.OutDir == "" {
		cfg.OutDir = "out"
	}
	if cfg.TmpDir == "" {
		cfg.TmpDir = "tmp"
	}
	if cfg.HTTPTimeoutSec <= 0 {
		cfg.HTTPTimeoutSec = 120
	}
	if cfg.DownloadRetries <= 0 {
		cfg.DownloadRetries = 3
	}
	if cfg.DownloadConcurrency <= 0 {
		cfg.DownloadConcurrency = 6
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if len(c.CNIP) == 0 && len(c.CNSite) == 0 && len(c.ADS) == 0 {
		return fmt.Errorf("no sources configured")
	}
	return nil
}