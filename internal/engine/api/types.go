package api

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
	Category() string
	Detect(*Context) DetectResult
	Apply(*Context) error
}

// WrapperProcessor extends Processor with wrapper-runtime handling.
type WrapperProcessor interface {
	Processor
	ApplyWrapper(*Context) error
}

type ProcessorResult struct {
	Name     string
	Category string
	Applied  bool
	Skipped  bool
	Err      error
	Reason   string
}

type FactStore interface {
	Set(FactKey, string)
	Get(FactKey) (string, bool)
	Snapshot() map[FactKey]string
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

func (s *MapFactStore) Snapshot() map[FactKey]string {
	out := make(map[FactKey]string, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out
}

func NewMapFactStoreFromSnapshot(values map[FactKey]string) *MapFactStore {
	out := NewMapFactStore()
	for k, v := range values {
		out.values[k] = v
	}
	return out
}

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

func (c *Context) AddResult(r ProcessorResult) {
	c.Results = append(c.Results, r)
}
