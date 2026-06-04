package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"rule-merger/internal/config"
	"rule-merger/internal/merge"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "config.json", "config file path")
	flag.Parse()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		fatalf("config: %v", err)
	}

	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		fatalf("mkdir out: %v", err)
	}
	if err := os.MkdirAll(cfg.TmpDir, 0o755); err != nil {
		fatalf("mkdir tmp: %v", err)
	}

	client := &http.Client{Timeout: time.Duration(cfg.HTTPTimeoutSec) * time.Second}

	fmt.Println("[1/5] loading ads")
	ads, err := merge.LoadGroup(cfg, client, cfg.TmpDir, cfg.ADS)
	if err != nil {
		fatalf("load ads: %v", err)
	}
	fmt.Println("[2/5] normalizing ads")
	adsN := merge.MergeGroup(cfg, ads, nil)

	fmt.Println("[3/5] loading cn-site")
	cnSite, err := merge.LoadGroup(cfg, client, cfg.TmpDir, cfg.CNSite)
	if err != nil {
		fatalf("load cn-site: %v", err)
	}
	fmt.Println("[4/5] loading cn-ip")
	cnIP, err := merge.LoadGroup(cfg, client, cfg.TmpDir, cfg.CNIP)
	if err != nil {
		fatalf("load cn-ip: %v", err)
	}

	fmt.Println("[5/5] writing outputs")
	cnSiteN := merge.MergeGroup(cfg, cnSite, adsN)
	cnIPN := merge.MergeGroup(cfg, cnIP, adsN)

	if err := merge.WriteOutputs(cfg, "ads", adsN); err != nil {
		fatalf("write ads: %v", err)
	}
	if err := merge.WriteOutputs(cfg, "cn-site", cnSiteN); err != nil {
		fatalf("write cn-site: %v", err)
	}
	if err := merge.WriteOutputs(cfg, "cn-ip", cnIPN); err != nil {
		fatalf("write cn-ip: %v", err)
	}

	fmt.Printf("done; out=%s tmp=%s\n", filepath.Clean(cfg.OutDir), filepath.Clean(cfg.TmpDir))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}