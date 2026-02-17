package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	rs "github.com/opencontainers/runtime-spec/specs-go"
)

func LoadSpec(bundle string) (string, *rs.Spec, error) {
	specPath := filepath.Join(bundle, "config.json")
	b, err := os.ReadFile(specPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read OCI spec %s: %w", specPath, err)
	}
	var spec rs.Spec
	if err := json.Unmarshal(b, &spec); err != nil {
		return "", nil, fmt.Errorf("failed to parse OCI spec %s: %w", specPath, err)
	}
	return specPath, &spec, nil
}

func ResolveRootfsPath(bundle string, spec *rs.Spec) string {
	if spec.Root == nil || spec.Root.Path == "" {
		return filepath.Join(bundle, "rootfs")
	}
	if filepath.IsAbs(spec.Root.Path) {
		return spec.Root.Path
	}
	return filepath.Join(bundle, spec.Root.Path)
}

func SaveSpec(path string, spec *rs.Spec) ([]byte, error) {
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode updated OCI spec: %w", err)
	}
	return b, nil
}
