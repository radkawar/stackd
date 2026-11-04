package eks

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Called by TestK3dNativeWorkload: these are actual kubelet configz responses
// through the owned Kubernetes API, not simulated Kubernetes configuration.
func assertNativeStorageConfig(t *testing.T, ctx context.Context, runtime *K3d, id string, want nativeStoragePolicy, workerCount int) map[string]string {
	t.Helper()
	cluster := runtime.clusters[id]
	if cluster.state.StoragePolicy == nil || *cluster.state.StoragePolicy != want {
		t.Fatalf("creation storage policy changed: %+v; want %+v", cluster.state.StoragePolicy, want)
	}
	containers, err := runtime.ownedContainers(ctx, cluster.state)
	if err != nil {
		t.Fatal(err)
	}
	workers := make(map[string]string)
	reserve := strconv.FormatInt(want.ReserveGiB, 10) + "Gi"
	for _, container := range containers {
		name := strings.TrimPrefix(container.Name, "/")
		if container.Name != "/k3d-"+cluster.state.Name+"-agent-0" && !runtime.ownedFargateContainer(cluster.state, container) {
			continue
		}
		workers[name] = container.ID
		var observed struct {
			KubeletConfig struct {
				EvictionHard                     map[string]string `json:"evictionHard"`
				EvictionMinimumReclaim           map[string]string `json:"evictionMinimumReclaim"`
				ImageGCHighThresholdPercent      int               `json:"imageGCHighThresholdPercent"`
				ImageGCLowThresholdPercent       int               `json:"imageGCLowThresholdPercent"`
				EvictionPressureTransitionPeriod string            `json:"evictionPressureTransitionPeriod"`
			} `json:"kubeletconfig"`
		}
		ready, cancel := context.WithTimeout(ctx, 2*time.Minute)
		for {
			_, err = cluster.workerRequest(ready, http.MethodGet, "/api/v1/nodes/"+url.PathEscape(name)+"/proxy/configz", nil, &observed)
			if err == nil {
				break
			}
			select {
			case <-ready.Done():
				cancel()
				t.Fatalf("native worker %s configz unavailable: %v", name, err)
			case <-time.After(time.Second):
			}
		}
		cancel()
		config := observed.KubeletConfig
		wantHard := map[string]string{"memory.available": "100Mi", "nodefs.available": reserve, "imagefs.available": reserve, "nodefs.inodesFree": "5%", "imagefs.inodesFree": "5%"}
		wantReclaim := map[string]string{"nodefs.available": reserve, "imagefs.available": reserve}
		if !reflect.DeepEqual(config.EvictionHard, wantHard) || !reflect.DeepEqual(config.EvictionMinimumReclaim, wantReclaim) || config.ImageGCHighThresholdPercent != want.ImageGCHighThreshold || config.ImageGCLowThresholdPercent != want.ImageGCLowThreshold || config.EvictionPressureTransitionPeriod != "5m0s" {
			t.Fatalf("native worker %s configz=%+v; want hard=%v reclaim=%v high=%d low=%d transition=5m0s", name, config, wantHard, wantReclaim, want.ImageGCHighThreshold, want.ImageGCLowThreshold)
		}
	}
	if len(workers) != workerCount {
		t.Fatalf("expected %d real native workers; observed %v", workerCount, workers)
	}
	return workers
}
