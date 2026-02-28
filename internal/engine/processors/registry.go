package processors

import (
	"sort"
	"strings"
	"sync"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/internal/engine/processors/nodejs"
	"github.com/tsuzu/cainjekt/internal/engine/processors/osstore"
)

var (
	registryMu sync.RWMutex
	registered []hookapi.Processor
	byName     = map[string]hookapi.Processor{}
)

func init() {
	Register(osstore.NewDebian())
	Register(osstore.NewRHEL())
	Register(osstore.NewOpenSUSE())
	Register(osstore.NewAlpine())
	Register(osstore.NewArch())
	Register(osstore.NewFallback())
	Register(nodejs.New())
}

// Register adds a processor to the default registry.
func Register(p hookapi.Processor) {
	if p == nil {
		panic("processor must not be nil")
	}
	name := strings.ToLower(strings.TrimSpace(p.Name()))
	if name == "" {
		panic("processor name must not be empty")
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := byName[name]; exists {
		panic("duplicate processor name: " + name)
	}
	registered = append(registered, p)
	byName[name] = p
}

func Default() []hookapi.Processor {
	registryMu.RLock()
	defer registryMu.RUnlock()

	out := make([]hookapi.Processor, len(registered))
	copy(out, registered)
	return out
}

func ByName(name string) (hookapi.Processor, bool) {
	registryMu.RLock()
	p, ok := byName[strings.ToLower(strings.TrimSpace(name))]
	registryMu.RUnlock()
	if !ok {
		return nil, false
	}
	return p, true
}

func ParseCSV(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(v))
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func FilterByNames(all []hookapi.Processor, include, exclude map[string]struct{}) []hookapi.Processor {
	var out []hookapi.Processor
	for _, p := range all {
		name := strings.ToLower(p.Name())
		if len(include) > 0 {
			if _, ok := include[name]; !ok {
				continue
			}
		}
		if _, ok := exclude[name]; ok {
			continue
		}
		out = append(out, p)
	}
	return out
}

func DetectSorted(ctx *hookapi.Context, list []hookapi.Processor) []Detected {
	out := make([]Detected, 0, len(list))
	for _, p := range list {
		out = append(out, Detected{Processor: p, Detect: p.Detect(ctx)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Detect.Priority > out[j].Detect.Priority
	})
	return out
}

type Detected struct {
	Processor hookapi.Processor
	Detect    hookapi.DetectResult
}
