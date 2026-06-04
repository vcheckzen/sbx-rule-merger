package ruleset

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func Decompile(binary string, srs []byte, tmpDir string) ([]byte, error) {
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, err
	}
	stamp := time.Now().UnixNano()
	srsPath := filepath.Join(tmpDir, fmt.Sprintf("decompile-%d.srs", stamp))
	jsonPath := filepath.Join(tmpDir, fmt.Sprintf("decompile-%d.json", stamp))
	if err := os.WriteFile(srsPath, srs, 0o644); err != nil {
		return nil, err
	}
	defer os.Remove(srsPath)
	defer os.Remove(jsonPath)

	cmd := exec.Command(binary, "rule-set", "decompile", srsPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sing-box decompile failed: %v: %s", err, stderr.String())
	}
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read decompile output: %w", err)
	}
	return b, nil
}

func Compile(binary, jsonPath, outPath string) error {
	cmd := exec.Command(binary, "rule-set", "compile", "--output", outPath, jsonPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sing-box compile failed: %v: %s", err, stderr.String())
	}
	return nil
}

func ConvertAdGuard(binary, txtPath, outPath string) error {
	cmd := exec.Command(binary, "rule-set", "convert", "--type", "adguard", "--output", outPath, txtPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sing-box convert failed: %v: %s", err, stderr.String())
	}
	return nil
}