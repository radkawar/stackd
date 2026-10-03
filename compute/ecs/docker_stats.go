package ecs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"time"
)

// Stats returns the Engine's non-streaming statistics without synthesizing or
// translating counters. Names can only select this environment's containers.
func (e *dockerEnvironment) Stats(ctx context.Context, name string) (json.RawMessage, error) {
	var stats json.RawMessage
	var identity struct {
		ID string `json:"id"`
	}
	err := e.readStats(ctx, name, &identity, &identity.ID, &stats)
	return stats, err
}

func (e *dockerEnvironment) Usage(ctx context.Context, name string) (ContainerUsage, error) {
	var stats struct {
		ID       string    `json:"id"`
		Read     time.Time `json:"read"`
		CPUStats struct {
			CPUUsage struct {
				TotalUsage *uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
		} `json:"cpu_stats"`
		MemoryStats struct {
			Usage *uint64 `json:"usage"`
			Stats struct {
				InactiveFile *uint64 `json:"inactive_file"`
				Cache        *uint64 `json:"cache"`
			} `json:"stats"`
		} `json:"memory_stats"`
	}
	if err := e.readStats(ctx, name, &stats, &stats.ID, nil); err != nil {
		return ContainerUsage{}, err
	}
	if stats.Read.IsZero() || stats.CPUStats.CPUUsage.TotalUsage == nil || stats.MemoryStats.Usage == nil {
		return ContainerUsage{}, fmt.Errorf("native Docker statistics lack usage counters or observation time for ECS execution container %s", name)
	}
	cpu := *stats.CPUStats.CPUUsage.TotalUsage
	if cpu > math.MaxInt64 {
		return ContainerUsage{}, fmt.Errorf("native Docker CPU usage overflows duration for ECS execution container %s", name)
	}
	memory := *stats.MemoryStats.Usage
	// The supported engine uses cgroup v2. Match the ECS agent's working set:
	// prefer inactive_file, then cache, and never subtract an invalid counter.
	if inactive := stats.MemoryStats.Stats.InactiveFile; inactive != nil && *inactive < memory {
		memory -= *inactive
	} else if cache := stats.MemoryStats.Stats.Cache; cache != nil && *cache < memory {
		memory -= *cache
	}
	return ContainerUsage{ObservedAt: stats.Read, CPUTime: time.Duration(cpu), MemoryBytes: memory}, nil
}

// readStats owns container selection and native identity validation. Metadata
// requests retain paired statistics in raw; utilization reads current counters
// directly, without waiting for Docker to collect another CPU sample.
func (e *dockerEnvironment) readStats(ctx context.Context, name string, output any, id *string, raw *json.RawMessage) error {
	container, ok := e.containers[name]
	if !ok || container.id == "" {
		return fmt.Errorf("unknown ECS execution container %q", name)
	}
	path := "/containers/" + url.PathEscape(container.id) + "/stats?stream=false"
	target := output
	if raw == nil {
		path += "&one-shot=true"
	} else {
		target = raw
	}
	if err := e.executor.client.JSON(ctx, http.MethodGet, path, nil, target); err != nil {
		return fmt.Errorf("read ECS container %s statistics: %w", name, err)
	}
	if raw != nil {
		if err := json.Unmarshal(*raw, output); err != nil {
			return fmt.Errorf("decode ECS container %s statistics: %w", name, err)
		}
	}
	if *id != container.id {
		return fmt.Errorf("native Docker statistics do not identify ECS execution container %s", name)
	}
	return nil
}
