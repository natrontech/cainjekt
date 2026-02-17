package api

import (
	rs "github.com/opencontainers/runtime-spec/specs-go"
)

type Stage string

const (
	StageOS       Stage = "os"
	StageLanguage Stage = "language"
)

type FactKey string

const (
	FactTrustStorePath FactKey = "trust_store_path"
	FactTrustStoreKind FactKey = "trust_store_kind"
	FactDistro         FactKey = "distro"
)

type DetectResult struct {
	Applicable bool
	Reason     string
	Priority   int
}

type Processor interface {
	Name() string
	Stage() Stage
	Detect(*Context) DetectResult
	Apply(*Context) error
}

type ProcessorResult struct {
	Name    string
	Stage   Stage
	Applied bool
	Skipped bool
	Err     error
	Reason  string
}

type FactStore interface {
	Set(FactKey, string)
	Get(FactKey) (string, bool)
}

type MapFactStore struct {
	values map[FactKey]string
}

func NewMapFactStore() *MapFactStore {
	return &MapFactStore{values: map[FactKey]string{}}
}

func (s *MapFactStore) Set(key FactKey, value string) {
	s.values[key] = value
}

func (s *MapFactStore) Get(key FactKey) (string, bool) {
	v, ok := s.values[key]
	return v, ok
}

type Context struct {
	Mode        string
	Bundle      string
	Annotations map[string]string
	Rootfs      string
	SpecPath    string
	Spec        *rs.Spec
	CAFile      string
	FailPolicy  string

	Facts   FactStore
	Results []ProcessorResult

	SpecChanged bool
}

func (c *Context) AddResult(r ProcessorResult) {
	c.Results = append(c.Results, r)
}
