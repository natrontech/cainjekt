package processors

import (
	"sort"
	"strings"

	hookapi "github.com/tsuzu/cainjekt/internal/hook/api"
	"github.com/tsuzu/cainjekt/internal/hook/processors/language/entrypoint"
	"github.com/tsuzu/cainjekt/internal/hook/processors/language/envvars"
	"github.com/tsuzu/cainjekt/internal/hook/processors/osstore"
)

func Default() []hookapi.Processor {
	return []hookapi.Processor{
		osstore.NewDebian(),
		osstore.NewRHEL(),
		osstore.NewAlpine(),
		osstore.NewFallback(),
		envvars.New(),
		entrypoint.New(),
	}
}

func ForStage(all []hookapi.Processor, stage hookapi.Stage) []hookapi.Processor {
	var out []hookapi.Processor
	for _, p := range all {
		if p.Stage() == stage {
			out = append(out, p)
		}
	}
	return out
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
