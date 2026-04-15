// Package certs provides PEM certificate parsing and merging utilities.
package certs

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// MergeResult holds the outcome of merging PEM certificate bundles.
type MergeResult struct {
	Merged []byte
	Added  int
}

// MergePEM deduplicates and appends PEM certificates from addition into existing.
func MergePEM(existing []byte, addition []byte) (MergeResult, error) {
	existingHashes := map[[sha256.Size]byte]struct{}{}
	for _, block := range parseCertPEMBlocks(existing) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		existingHashes[sha256.Sum256(cert.Raw)] = struct{}{}
	}

	var additions [][]byte
	for _, block := range parseCertPEMBlocks(addition) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return MergeResult{}, fmt.Errorf("failed to parse certificate from CA bundle: %w", err)
		}
		fp := sha256.Sum256(cert.Raw)
		if _, ok := existingHashes[fp]; ok {
			continue
		}
		existingHashes[fp] = struct{}{}
		additions = append(additions, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	if len(additions) == 0 {
		return MergeResult{Merged: existing, Added: 0}, nil
	}

	var out bytes.Buffer
	out.Write(bytes.TrimRight(existing, "\n"))
	for _, certPEM := range additions {
		if out.Len() > 0 {
			out.WriteByte('\n')
		}
		out.Write(bytes.TrimSpace(certPEM))
		out.WriteByte('\n')
	}
	return MergeResult{Merged: out.Bytes(), Added: len(additions)}, nil
}

func parseCertPEMBlocks(data []byte) []*pem.Block {
	rest := data
	var blocks []*pem.Block
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
		rest = r
	}
	return blocks
}
