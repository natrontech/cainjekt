package oci

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type State struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Pid         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations"`
}

func ReadState(r io.Reader) (*State, error) {
	in, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read hook stdin: %w", err)
	}
	var state State
	if err := json.Unmarshal(in, &state); err != nil {
		return nil, fmt.Errorf("failed to parse OCI state: %w", err)
	}
	if state.Bundle == "" {
		return nil, errors.New("OCI state did not include bundle path")
	}
	if state.Annotations == nil {
		state.Annotations = map[string]string{}
	}
	return &state, nil
}
