// Package api defines the processor interfaces and types for cainjekt's engine.
package api

import "strings"

// FactKey identifies a piece of detection metadata stored during processing.
type FactKey string

// Fact keys used by processors to communicate detection results.
const (
	FactTrustStorePath   FactKey = "trust_store_path"
	FactTrustStoreKind   FactKey = "trust_store_kind"
	FactDistro           FactKey = "distro"
	FactIndividualCAPath FactKey = "individual_ca_path"
	FactMergedCAPath     FactKey = "merged_ca_path"
	FactRootfsReadOnly   FactKey = "rootfs_read_only"
)

// PreferredCABundlePath returns the bundle that trust-REPLACING consumers
// (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, JVM trustStore) should point at: the merged
// bundle (system roots + org CA) when one was staged, else the individual org CA
// as a degraded fallback. Pointing such consumers at the bare org CA drops the
// system roots and breaks all public TLS. Additive consumers (NODE_EXTRA_CA_CERTS)
// should keep using FactIndividualCAPath.
func PreferredCABundlePath(facts FactStore) string {
	if facts == nil {
		return ""
	}
	if v, ok := facts.Get(FactMergedCAPath); ok {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	v, _ := facts.Get(FactIndividualCAPath)
	return strings.TrimSpace(v)
}

// DetectResult reports whether a processor is applicable to a container.
type DetectResult struct {
	Applicable bool
	Reason     string
	Priority   int
}

// Processor detects and applies CA injection for a specific OS or language.
type Processor interface {
	Name() string
	Category() string
	Detect(*Context) DetectResult
	Apply(*Context) error
}

// WrapperProcessor extends Processor with wrapper-runtime handling.
type WrapperProcessor interface {
	Processor
	ApplyWrapper(*Context) error
}

// ProcessorResult records the outcome of running a single processor.
type ProcessorResult struct {
	Name     string
	Category string
	Applied  bool
	Skipped  bool
	Err      error
	Reason   string
}

// FactStore is a key-value store for processor detection metadata.
type FactStore interface {
	Set(FactKey, string)
	Get(FactKey) (string, bool)
	Snapshot() map[FactKey]string
}

// MapFactStore is an in-memory FactStore backed by a map.
type MapFactStore struct {
	values map[FactKey]string
}

// NewMapFactStore returns an empty MapFactStore.
func NewMapFactStore() *MapFactStore {
	return &MapFactStore{values: map[FactKey]string{}}
}

// Set stores a fact.
func (s *MapFactStore) Set(key FactKey, value string) {
	s.values[key] = value
}

// Get retrieves a fact.
func (s *MapFactStore) Get(key FactKey) (string, bool) {
	v, ok := s.values[key]
	return v, ok
}

// Snapshot returns a copy of all stored facts.
func (s *MapFactStore) Snapshot() map[FactKey]string {
	out := make(map[FactKey]string, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out
}

// NewMapFactStoreFromSnapshot creates a MapFactStore pre-populated with the given values.
func NewMapFactStoreFromSnapshot(values map[FactKey]string) *MapFactStore {
	out := NewMapFactStore()
	for k, v := range values {
		out.values[k] = v
	}
	return out
}

// Context carries state through the processor pipeline.
type Context struct {
	Mode        string
	Bundle      string
	Annotations map[string]string
	Rootfs      string
	CAFile      string
	FailPolicy  string
	Env         []string

	Facts   FactStore
	Results []ProcessorResult
}

// AddResult appends a processor outcome to the context.
func (c *Context) AddResult(r ProcessorResult) {
	c.Results = append(c.Results, r)
}
