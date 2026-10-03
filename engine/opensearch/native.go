package opensearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	service "stackd/internal/services/opensearch"
)

func (d *Docker) get(ctx context.Context, endpoint, path string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+path, nil)
	if err != nil {
		return err
	}
	response, err := d.native.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("native OpenSearch %s returned HTTP %d", path, response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(output)
}

type clusterHealth struct {
	ClusterName       string `json:"cluster_name"`
	Status            string
	TimedOut          bool `json:"timed_out"`
	NumberOfNodes     int  `json:"number_of_nodes"`
	NumberOfDataNodes int  `json:"number_of_data_nodes"`
}

func (d *Docker) health(ctx context.Context, endpoint, id string) error {
	var info struct {
		ClusterName string `json:"cluster_name"`
		Version     struct{ Number, Distribution string }
	}
	if err := d.get(ctx, endpoint, "/", &info); err != nil {
		return err
	}
	if info.Version.Number != Version || info.Version.Distribution != "opensearch" || info.ClusterName != d.name(id, "cluster") {
		return fmt.Errorf("unexpected native OpenSearch identity: distribution=%q version=%q cluster=%q", info.Version.Distribution, info.Version.Number, info.ClusterName)
	}
	var health clusterHealth
	if err := d.get(ctx, endpoint, "/_cluster/health?wait_for_status=yellow&timeout=1s", &health); err != nil {
		return err
	}
	if health.ClusterName != d.name(id, "cluster") || health.TimedOut || health.NumberOfNodes != 1 || health.NumberOfDataNodes != 1 || (health.Status != "green" && health.Status != "yellow") {
		return fmt.Errorf("native OpenSearch is not ready: status=%s nodes=%d data_nodes=%d timed_out=%t", health.Status, health.NumberOfNodes, health.NumberOfDataNodes, health.TimedOut)
	}
	return nil
}
func (d *Docker) ready(ctx context.Context, containerID, endpoint, id string) error {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		last = d.health(probe, endpoint, id)
		cancel()
		if last == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("native OpenSearch readiness (%v): %w", last, ctx.Err())
		}
		state, err := d.inspect(ctx, containerID)
		if err != nil {
			return err
		}
		if !state.State.Running {
			return fmt.Errorf("native OpenSearch exited before readiness (exit %d): %w", state.State.ExitCode, last)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("native OpenSearch readiness (%v): %w", last, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Statistics reads native cluster counters without creating or restarting a
// failed node. Missing engines, partial responses and unhealthy nodes are errors.
func (d *Docker) Statistics(ctx context.Context, spec service.NativeSpecification) (service.NativeStatistics, error) {
	var result service.NativeStatistics
	if err := validateSpecification(spec); err != nil {
		return result, err
	}
	ctx, leave, err := d.enter(ctx)
	if err != nil {
		return result, err
	}
	defer leave()
	state, err := d.inspect(ctx, d.name(spec.ID, "node"))
	if err != nil {
		return result, err
	}
	if err := d.checkContainer(state, spec.ID); err != nil {
		return result, err
	}
	if err := d.resources(ctx, spec.ID, false); err != nil {
		return result, err
	}
	if !state.State.Running {
		return result, errors.New("native OpenSearch node is not running")
	}
	endpoint, err := state.endpoint()
	if err != nil {
		return result, err
	}
	if err := d.health(ctx, endpoint, spec.ID); err != nil {
		return result, err
	}
	var stats struct {
		ClusterName string `json:"cluster_name"`
		Status      string
		Responses   struct{ Total, Successful, Failed int } `json:"_nodes"`
		Indices     struct {
			Docs  struct{ Count int64 }
			Store struct {
				Bytes int64 `json:"size_in_bytes"`
			}
		}
		Nodes struct {
			Count struct{ Total int64 }
			JVM   struct {
				Memory struct {
					Used int64 `json:"heap_used_in_bytes"`
					Max  int64 `json:"heap_max_in_bytes"`
				} `json:"mem"`
			}
		}
	}
	if err := d.get(ctx, endpoint, "/_cluster/stats", &stats); err != nil {
		return result, err
	}
	if stats.ClusterName != d.name(spec.ID, "cluster") || stats.Responses.Total != 1 || stats.Responses.Successful != 1 || stats.Responses.Failed != 0 || stats.Nodes.Count.Total != 1 || stats.Nodes.JVM.Memory.Max <= 0 || (stats.Status != "green" && stats.Status != "yellow") {
		return result, errors.New("native OpenSearch returned incomplete cluster statistics")
	}
	return service.NativeStatistics{Nodes: stats.Nodes.Count.Total, Documents: stats.Indices.Docs.Count, StoreBytes: stats.Indices.Store.Bytes, JVMPercent: 100 * float64(stats.Nodes.JVM.Memory.Used) / float64(stats.Nodes.JVM.Memory.Max), Health: stats.Status}, nil
}
