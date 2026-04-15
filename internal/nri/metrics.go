package nri

import (
	"sync"
	"sync/atomic"
)

// Metrics tracks injection statistics for the Prometheus endpoint.
type Metrics struct {
	InjectionsTotal   atomic.Int64
	InjectionsErrors  atomic.Int64
	SkippedTotal      atomic.Int64
	CleanupsTotal     atomic.Int64
	CleanupsErrors    atomic.Int64
	OrphansCleaned    atomic.Int64
	ActiveContainers  atomic.Int64
	processorDetected sync.Map // map[string]*atomic.Int64
	processorApplied  sync.Map // map[string]*atomic.Int64
}

// IncProcessorDetected increments the detection count for a processor.
func (m *Metrics) IncProcessorDetected(name string) {
	v, _ := m.processorDetected.LoadOrStore(name, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

// IncProcessorApplied increments the application count for a processor.
func (m *Metrics) IncProcessorApplied(name string) {
	v, _ := m.processorApplied.LoadOrStore(name, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

// ProcessorStats returns a snapshot of per-processor detection and application counts.
func (m *Metrics) ProcessorStats() (detected, applied map[string]int64) {
	detected = map[string]int64{}
	applied = map[string]int64{}
	m.processorDetected.Range(func(key, value any) bool {
		detected[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})
	m.processorApplied.Range(func(key, value any) bool {
		applied[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})
	return detected, applied
}
