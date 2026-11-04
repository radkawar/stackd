package eks

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This opt-in test observes a real CNI bridge and Kubernetes Node, then proves
// that an API-created lookalike Node cannot become a native routing authority.
// The upstream controller fixture separately proves ALB packet delivery.
func TestNativePodRouteAuthority(t *testing.T) {
	binary := os.Getenv("STACKD_EKS_NATIVE_BINARY")
	if binary == "" {
		t.Skip("set STACKD_EKS_NATIVE_BINARY to exercise real Kubernetes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	config := Config{DataDir: filepath.Join(t.TempDir(), "runtime"), Binary: binary, DockerHost: "unix:///var/run/docker.sock"}
	runtime, err := NewK3d(config)
	if err != nil {
		t.Fatal(err)
	}
	id := "pod-route-" + time.Now().UTC().Format("20060102T150405.000000000")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 90*time.Second)
		defer done()
		if err := runtime.Delete(cleanup, id); err != nil {
			t.Errorf("exact-owned cleanup: %v", err)
		}
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	})
	spec := Specification{ID: id}
	if _, err := runtime.Ensure(ctx, spec, http.NotFoundHandler()); err != nil {
		t.Fatal(err)
	}
	cluster := runtime.clusters[id]
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]string{"name": "route-proof"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "backend", "image": "busybox:1.37.0", "command": []string{"sh", "-c", "sleep 600"}}}}}
	if _, err := cluster.workerRequest(ctx, http.MethodPost, "/api/v1/namespaces/default/pods", pod, nil); err != nil {
		t.Fatal(err)
	}
	var podIP netip.Addr
	for {
		var observed struct {
			Status struct {
				PodIP      string
				Conditions []struct{ Type, Status string }
			}
		}
		_, err = cluster.workerRequest(ctx, http.MethodGet, "/api/v1/namespaces/default/pods/route-proof", nil, &observed)
		ready := false
		for _, condition := range observed.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				ready = true
			}
		}
		podIP, _ = netip.ParseAddr(observed.Status.PodIP)
		if err == nil && ready && podIP.Is4() {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("real pod did not become Ready: %v, last API error: %v", ctx.Err(), err)
		case <-time.After(time.Second):
		}
	}
	routes, err := runtime.ObservePodRoutes(ctx, spec)
	if err != nil || len(routes) != 1 || !routes[0].Prefix.Contains(podIP) || routes[0].NodeUID == "" || routes[0].ContainerID == "" || routes[0].NetworkID == "" {
		t.Fatalf("real native pod routing witness: %#v %v", routes, err)
	}
	original := routes[0]
	foreign := map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": "foreign-route-node", "labels": map[string]string{"stackd.eks.id": id}}, "spec": map[string]any{"podCIDR": original.Prefix.String(), "podCIDRs": []string{original.Prefix.String()}, "providerID": "aws:///synthetic/i-not-owned"}}
	var created struct{ Metadata struct{ UID string } }
	if _, err := cluster.workerRequest(ctx, http.MethodPost, "/api/v1/nodes", foreign, &created); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.ObservePodRoutes(ctx, spec); err == nil {
		t.Fatal("API-created foreign node became a route authority")
	}
	if _, err := cluster.workerRequest(ctx, http.MethodDelete, "/api/v1/nodes/foreign-route-node", map[string]any{"preconditions": map[string]string{"uid": created.Metadata.UID}}, nil); err != nil {
		t.Fatal(err)
	}
	routes, err = runtime.ObservePodRoutes(ctx, spec)
	if err != nil || len(routes) != 1 || routes[0].NodeUID != original.NodeUID {
		t.Fatalf("restored native authority: %#v %v", routes, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewK3d(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime = reopened
	if _, err := runtime.Ensure(ctx, spec, http.NotFoundHandler()); err != nil {
		t.Fatal(err)
	}
	routes, err = runtime.ObservePodRoutes(ctx, spec)
	if err != nil || len(routes) != 1 {
		t.Fatalf("retained native authority: %#v %v", routes, err)
	}
	retained := routes[0]
	retained.ResourceVersion = original.ResourceVersion
	if retained != original {
		t.Fatalf("restart changed owned routing incarnation: %#v %#v", original, retained)
	}
}
