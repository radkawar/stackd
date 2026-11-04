package eks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/compute/eks/ecrcredentials"
)

// TestK3dNativePrivateECRPull uses a real HTTPS registry and actual native
// kubelet/containerd. Only disposable copies of the supplied helper are mutated;
// the caller's registry, credentials, CA and installed helper are read-only inputs.
// No image is imported into k3d and no imagePullSecret is created.
func TestK3dNativePrivateECRPull(t *testing.T) {
	binary := os.Getenv("STACKD_EKS_NATIVE_BINARY")
	if binary == "" || os.Getenv("STACKD_EKS_ECR_PROVIDER") == "" {
		t.Skip("set STACKD_EKS_NATIVE_BINARY, STACKD_EKS_ECR_PROVIDER, STACKD_EKS_ECR_CREDENTIALS, STACKD_EKS_ECR_CA and STACKD_EKS_ECR_IMAGE")
	}
	credentialsPath := os.Getenv("STACKD_EKS_ECR_CREDENTIALS")
	credentials, err := ecrcredentials.Load(credentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(os.Getenv("STACKD_EKS_ECR_CA"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := credentials.Registry()
	if err != nil {
		t.Fatal(err)
	}
	image := os.Getenv("STACKD_EKS_ECR_IMAGE")
	if !strings.HasPrefix(image, registry+"/") {
		t.Fatal("native pull image must name the configured private ECR origin")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid registry CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	res, err := client.Get(strings.TrimRight(credentials.Endpoint, "/") + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("registry accepts unauthenticated access: %d", res.StatusCode)
	}
	helper, err := os.ReadFile(os.Getenv("STACKD_EKS_ECR_PROVIDER"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	original := filepath.Join(fixture, "original", ecrProviderName)
	relocated := filepath.Join(fixture, "relocated", ecrProviderName)
	for _, path := range []string{original, relocated} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, helper, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 9*time.Minute)
	defer cancel()
	dockerHost := os.Getenv("STACKD_EKS_DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}
	config := Config{DataDir: filepath.Join(fixture, "runtime"), Binary: binary, DockerHost: dockerHost, ECRCredentialProvider: original, ECRCredentialsFile: credentialsPath, ECRCA: ca}
	runtime, err := NewK3d(config)
	if err != nil {
		t.Fatal(err)
	}
	id := "private-ecr-" + time.Now().UTC().Format("20060102T150405.000000000")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ecr-fixture-admin" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		runtime.Proxy(w, r, id, Identity{Username: "ecr-fixture-admin", Grants: []Grant{{Role: "cluster-admin"}}})
	})
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 90*time.Second)
		defer done()
		if runtime.closed {
			reopened, err := NewK3d(config)
			if err != nil {
				t.Errorf("reopen exact-owned fixture for cleanup: %v", err)
				return
			}
			runtime = reopened
		}
		if err := runtime.Delete(cleanup, id); err != nil {
			t.Error(err)
		}
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
		if _, err := os.Lstat(runtime.resourceDir(id)); !os.IsNotExist(err) {
			t.Errorf("owned ECR artifact/configuration survived deletion: %v", err)
		}
		if body, err := os.ReadFile(relocated); err != nil || !bytes.Equal(body, helper) {
			t.Errorf("cluster cleanup changed the unrelated relocated helper: %v", err)
		}
	})
	endpoint, err := runtime.Ensure(ctx, Specification{ID: id}, handler)
	if err != nil {
		t.Fatal(err)
	}
	state := runtime.clusters[id].state
	if state.ECRProvider == nil || state.ECRProvider.Preparing {
		t.Fatal("fresh worker lacks a durable staged provider receipt")
	}
	identity := *state.ECRProvider
	workers := nativeECRWorkerIDs(t, ctx, runtime, state)
	cluster := runtime.clusters[id]
	live := nativeECRPod(t, ctx, cluster, image, "private-ecr-continuity", "sleep 600", "Running")
	nodes := nativeECRNodeUIDs(t, ctx, cluster)
	nativeECRPod(t, ctx, cluster, image, "private-ecr-initial", "echo authenticated-private-ecr", "Succeeded")
	publicCA, err := base64.StdEncoding.DecodeString(endpoint.CertificateAuthority)
	if err != nil {
		t.Fatal(err)
	}
	publicRoots := x509.NewCertPool()
	if !publicRoots.AppendCertsFromPEM(publicCA) {
		t.Fatal("invalid retained public API CA")
	}
	publicTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: publicRoots, MinVersion: tls.VersionTLS12}}
	defer publicTransport.CloseIdleConnections()
	publicClient := &http.Client{Transport: publicTransport, Timeout: 20 * time.Second}
	for index, phase := range []string{"relocated", "rebuilt", "deleted", "omitted"} {
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
		publicTransport.CloseIdleConnections()
		switch phase {
		case "relocated":
			config.ECRCredentialProvider = relocated
		case "rebuilt":
			// This is deliberately not a working provider. A controller rebuild
			// must not change the executable already used by the retained worker.
			if err := os.WriteFile(original, []byte("#!/bin/sh\nexit 79\n"), 0700); err != nil {
				t.Fatal(err)
			}
			config.ECRCredentialProvider = original
		case "deleted":
			if err := os.Remove(original); err != nil {
				t.Fatal(err)
			}
		case "omitted":
			config.ECRCredentialProvider = ""
		}
		reopenedRuntime, err := NewK3d(config)
		if err != nil {
			t.Fatalf("%s controller construction: %v", phase, err)
		}
		runtime = reopenedRuntime
		reopened, err := runtime.Ensure(ctx, Specification{ID: id}, handler)
		if err != nil || reopened != endpoint {
			t.Fatalf("%s retained API changed: error=%v", phase, err)
		}
		cluster = runtime.clusters[id]
		if cluster.state.ECRProvider == nil || *cluster.state.ECRProvider != identity || !reflect.DeepEqual(nativeECRWorkerIDs(t, ctx, runtime, state), workers) || !reflect.DeepEqual(nativeECRNodeUIDs(t, ctx, cluster), nodes) {
			t.Fatalf("%s changed retained provider, Docker worker or Kubernetes node identity", phase)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/api/v1/namespaces/default/pods/private-ecr-continuity", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer ecr-fixture-admin")
		response, err := publicClient.Do(req)
		if err != nil {
			t.Fatalf("%s authenticated retained API: %v", phase, err)
		}
		var observed nativeECRPodObservation
		err = json.NewDecoder(response.Body).Decode(&observed)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil || observed.Metadata.UID != live.Metadata.UID || observed.Status.Phase != "Running" || len(observed.Status.ContainerStatuses) != 1 || observed.Status.ContainerStatuses[0].RestartCount != live.Status.ContainerStatuses[0].RestartCount {
			t.Fatalf("%s lost retained authenticated API/workload continuity: status=%d error=%v", phase, response.StatusCode, err)
		}
		nativeECRPod(t, ctx, cluster, image, fmt.Sprintf("private-ecr-reopen-%d", index), "echo authenticated-after-relocation", "Succeeded")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(runtime.resourceDir(id), ecrProviderName)
	corrupted := bytes.Clone(helper)
	if len(corrupted) == 0 {
		t.Fatal("empty fixture executable")
	}
	corrupted[0] ^= 1
	if err := os.Chmod(artifact, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, corrupted, 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact, 0500); err != nil {
		t.Fatal(err)
	}
	reopenedRuntime, err := NewK3d(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime = reopenedRuntime
	if _, err := runtime.Ensure(ctx, Specification{ID: id}, handler); err == nil {
		t.Fatal("reattached a corrupted retained provider")
	}
	if body, err := os.ReadFile(artifact); err != nil || !bytes.Equal(body, corrupted) {
		t.Fatal("rejected retained provider was replaced")
	}
	// Renaming only disposable owned fixture state leaves the Docker bind inode
	// intact and tests that a missing host artifact is not silently regenerated.
	if err := os.Rename(artifact, filepath.Join(fixture, "held-corrupt-provider")); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Ensure(ctx, Specification{ID: id}, handler); err == nil {
		t.Fatal("reattached a missing retained provider")
	}
	if _, err := os.Lstat(artifact); !os.IsNotExist(err) {
		t.Fatal("regenerated a missing retained provider")
	}
	if !reflect.DeepEqual(nativeECRWorkerIDs(t, ctx, runtime, state), workers) {
		t.Fatal("negative retained-artifact checks replaced native workers")
	}
}

type nativeECRPodObservation struct {
	Metadata struct{ UID string } `json:"metadata"`
	Spec     struct {
		ImagePullSecrets []any `json:"imagePullSecrets"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			ImageID      string `json:"imageID"`
			RestartCount int    `json:"restartCount"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func nativeECRPod(t *testing.T, ctx context.Context, cluster *nativeCluster, image, name, command, phase string) nativeECRPodObservation {
	t.Helper()
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]string{"name": name}, "spec": map[string]any{"restartPolicy": "Never", "containers": []any{map[string]any{"name": "proof", "image": image, "imagePullPolicy": "Always", "command": []string{"/bin/sh", "-c", command}}}}}
	if _, err := cluster.workerRequest(ctx, http.MethodPost, "/api/v1/namespaces/default/pods", pod, nil); err != nil {
		t.Fatal(err)
	}
	var observed nativeECRPodObservation
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if _, err := cluster.workerRequest(ctx, http.MethodGet, "/api/v1/namespaces/default/pods/"+name, nil, &observed); err != nil {
			t.Fatal(err)
		}
		if len(observed.Spec.ImagePullSecrets) != 0 {
			t.Fatal("native pull unexpectedly uses workload imagePullSecrets")
		}
		if observed.Status.Phase == phase {
			if observed.Metadata.UID == "" || len(observed.Status.ContainerStatuses) != 1 || observed.Status.ContainerStatuses[0].ImageID == "" {
				t.Fatal("private workload lacks native pod/image identity")
			}
			return observed
		}
		if observed.Status.Phase == "Failed" {
			t.Fatal("private ECR workload failed")
		}
		select {
		case <-ctx.Done():
			t.Fatal(fmt.Errorf("waiting for authenticated private pull (phase %s): %w", observed.Status.Phase, ctx.Err()))
		case <-ticker.C:
		}
	}
}

func nativeECRWorkerIDs(t *testing.T, ctx context.Context, runtime *K3d, state diskState) map[string]string {
	t.Helper()
	containers, err := runtime.inspectOwnedContainers(ctx, state, false)
	if err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]string)
	for _, container := range containers {
		if strings.HasSuffix(container.Name, "-server-0") || strings.HasSuffix(container.Name, "-agent-0") {
			ids[container.Name] = container.ID
		}
	}
	if len(ids) != 2 {
		t.Fatalf("expected exact-owned control plane and bootstrap worker, got %d", len(ids))
	}
	return ids
}

func nativeECRNodeUIDs(t *testing.T, ctx context.Context, cluster *nativeCluster) map[string]string {
	t.Helper()
	var nodes struct {
		Items []struct {
			Metadata struct{ Name, UID string }
		}
	}
	if _, err := cluster.workerRequest(ctx, http.MethodGet, "/api/v1/nodes", nil, &nodes); err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]string, len(nodes.Items))
	for _, node := range nodes.Items {
		if node.Metadata.UID == "" {
			t.Fatal("native node has no UID")
		}
		ids[node.Metadata.Name] = node.Metadata.UID
	}
	if len(ids) == 0 {
		t.Fatal("native cluster has no nodes")
	}
	return ids
}
