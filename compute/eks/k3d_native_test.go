package eks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This opt-in fixture runs real Docker/k3d/k3s and kubectl, never mock Kubernetes.
// STACKD_EKS_NATIVE_BINARY must point to the pinned k3d binary.
func TestK3dNativeWorkload(t *testing.T) {
	binary := os.Getenv("STACKD_EKS_NATIVE_BINARY")
	if binary == "" {
		t.Skip("set STACKD_EKS_NATIVE_BINARY to exercise real Kubernetes")
	}
	t.Setenv("DOCKER_HOST", "unix:///nonexistent-ambient-docker.sock")
	t.Setenv("DOCKER_CONTEXT", "unowned-ambient-context")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	config := Config{DataDir: filepath.Join(t.TempDir(), "runtime"), Binary: binary, DockerHost: "unix:///var/run/docker.sock"}
	runtime, err := NewK3d(config)
	if err != nil {
		t.Fatal(err)
	}
	id := "native-" + time.Now().UTC().Format("20060102T150405.000000000")
	var revoked atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var identity Identity
		switch r.Header.Get("Authorization") {
		case "Bearer fixture-admin":
			identity = Identity{Username: "fixture-admin", Grants: []Grant{{Role: "cluster-admin"}}}
		case "Bearer fixture-edit":
			identity = Identity{Username: "fixture-edit", Grants: []Grant{{Role: "edit", Namespaces: []string{"default"}}}}
		case "Bearer fixture-policy-admin":
			identity = Identity{Username: "fixture-policy-admin", Grants: []Grant{{Role: "admin"}}}
		case "Bearer fixture-view":
			identity = Identity{Username: "fixture-view"}
			if !revoked.Load() {
				identity.Grants = []Grant{{Role: "view", Namespaces: []string{"default", "future-scope"}}}
			}
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		runtime.Proxy(w, r, id, identity)
	})
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
	endpoint, err := runtime.Ensure(ctx, Specification{ID: id}, handler)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Logf("native command stderr: %s", exit.Stderr)
		}
		t.Fatal(err)
	}
	t.Logf("real ready cluster endpoint %s", endpoint.URL)
	issuerConfiguration, issuerKeys := exerciseRetainedNativeIssuer(t, ctx, runtime, id, handler)
	ca, err := base64.StdEncoding.DecodeString(endpoint.CertificateAuthority)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid public CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	request := func(method, path, token, body string, impersonate bool) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, endpoint.URL+path, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if impersonate {
			req.Header.Set("Impersonate-User", "system:admin")
			req.Header.Set("Impersonate-Group", "system:masters")
			req.Header.Set("X-Remote-User", "system:admin")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	if status, data := request("GET", "/api/v1/nodes", "", "", false); status != 401 {
		t.Fatalf("unauthenticated: %d %s", status, data)
	}
	if status, data := request("GET", "/api/v1/nodes", "fixture-view", "", true); status != 403 {
		t.Fatalf("impersonation escape: %d %s", status, data)
	}
	if status, data := request("GET", "/api/v1/namespaces/default/pods", "fixture-view", "", false); status != 200 {
		t.Fatalf("namespace grant: %d %s", status, data)
	}
	if status, data := request("GET", "/api/v1/namespaces/kube-system/pods", "fixture-view", "", false); status != 403 {
		t.Fatalf("namespace escape: %d %s", status, data)
	}
	if status, data := request("POST", "/api/v1/namespaces", "fixture-admin", `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"future-scope"}}`, false); status != 201 {
		t.Fatalf("future namespace creation: %d %s", status, data)
	}
	if status, data := request("GET", "/api/v1/namespaces/future-scope/pods", "fixture-view", "", false); status != 200 {
		t.Fatalf("pre-associated namespace scope: %d %s", status, data)
	}
	secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"policy-proof"},"stringData":{"proof":"native-rbac"}}`
	if status, data := request("POST", "/api/v1/namespaces/default/secrets", "fixture-edit", secret, false); status != 201 {
		t.Fatalf("AWS edit secret creation: %d %s", status, data)
	}
	if status, data := request("GET", "/api/v1/namespaces/default/secrets/policy-proof", "fixture-view", "", false); status != 403 {
		t.Fatalf("AWS view disclosed secret: %d %s", status, data)
	}
	if status, data := request("GET", "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles", "fixture-edit", "", false); status != 403 {
		t.Fatalf("AWS edit widened RBAC: %d %s", status, data)
	}
	if status, data := request("GET", "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles", "fixture-policy-admin", "", false); status != 200 {
		t.Fatalf("AWS admin RBAC grant: %d %s", status, data)
	}
	if status, data := request("GET", "/api/v1/nodes", "fixture-policy-admin", "", false); status != 403 {
		t.Fatalf("AWS admin widened to cluster admin: %d %s", status, data)
	}
	t.Log("AWS view/edit/admin distinct permissions enforced by owned native roles")
	deployment := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"native-proof"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"native-proof"}},"template":{"metadata":{"labels":{"app":"native-proof"}},"spec":{"containers":[{"name":"worker","image":"busybox:1.37.0","command":["sh","-c","echo real-workload; sleep 3600"]}]}}}}`
	if status, data := request("POST", "/apis/apps/v1/namespaces/default/deployments", "fixture-admin", deployment, false); status != 201 {
		t.Fatalf("deployment create: %d %s", status, data)
	}
	var deploymentUID string
	for {
		status, data := request("GET", "/apis/apps/v1/namespaces/default/deployments/native-proof", "fixture-admin", "", false)
		if status != 200 {
			t.Fatalf("deployment observe: %d %s", status, data)
		}
		var observed struct {
			Metadata struct{ UID string }
			Status   struct{ AvailableReplicas int }
		}
		if err := json.Unmarshal(data, &observed); err != nil {
			t.Fatal(err)
		}
		deploymentUID = observed.Metadata.UID
		if observed.Status.AvailableReplicas == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	status, data := request("GET", "/api/v1/namespaces/default/pods?labelSelector=app%3Dnative-proof", "fixture-view", "", false)
	var pods struct {
		Items []struct {
			Metadata struct{ UID, Name string }
			Status   struct{ Phase string }
		}
	}
	if status != 200 || json.Unmarshal(data, &pods) != nil || len(pods.Items) != 1 || pods.Items[0].Status.Phase != "Running" {
		t.Fatalf("real running pod: %d %s", status, data)
	}
	podUID := pods.Items[0].Metadata.UID
	t.Logf("available deployment=%s running pod=%s", deploymentUID, podUID)
	status, data = request("GET", "/api/v1/namespaces/default/pods?watch=true&timeoutSeconds=2", "fixture-view", "", false)
	if status != 200 || !bytes.Contains(data, []byte(`"type":"ADDED"`)) {
		t.Fatalf("streaming watch: %d %s", status, data)
	}
	caPath := filepath.Join(t.TempDir(), "public-ca.crt")
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--kubeconfig=/dev/null", "--server=" + endpoint.URL, "--certificate-authority=" + caPath, "--token=fixture-admin", "exec", "deployment/native-proof", "--", "sh", "-c", "printf exec-through-authenticated-proxy"}
	output, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "exec-through-authenticated-proxy") {
		t.Fatalf("streaming exec: %v %s", err, output)
	}
	t.Log("authenticated watch and kubectl exec reached real Kubernetes")
	revoked.Store(true)
	if status, data := request("GET", "/api/v1/namespaces/default/pods", "fixture-view", "", true); status != 403 {
		t.Fatalf("revoked grant retained authority: %d %s", status, data)
	}
	t.Log("revoked grant denied immediately despite retained native binding")
	state, err := readState(runtime.resourceDir(id), id)
	if err != nil {
		t.Fatal(err)
	}
	nativeTransport := runtime.clusters[id].transport.Clone()
	nativeTransport.TLSClientConfig.Certificates = nil
	nativeClient := &http.Client{Transport: nativeTransport, Timeout: 10 * time.Second}
	nativeResponse, err := nativeClient.Get(runtime.clusters[id].nativeURL() + "/api/v1/nodes")
	if err != nil {
		t.Fatal(err)
	}
	nativeResponse.Body.Close()
	nativeTransport.CloseIdleConnections()
	if nativeResponse.StatusCode != 401 && nativeResponse.StatusCode != 403 {
		t.Fatalf("native API permitted access without private credentials: %d", nativeResponse.StatusCode)
	}
	for _, name := range []string{"owner.json", "admin.kubeconfig", "proxy.key", "proxy.crt", "ca.crt"} {
		if _, err := readPrivate(filepath.Join(runtime.resourceDir(id), name)); err != nil {
			t.Fatal(err)
		}
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	// Recover the credential checkpoint from the exact-owned native server.
	if err = os.Remove(filepath.Join(runtime.resourceDir(id), "admin.kubeconfig")); err != nil {
		t.Fatal(err)
	}
	wrongDaemon := config
	wrongDaemon.DockerHost = "unix:///wrong-explicit-daemon.sock"
	wrongOwner, err := NewK3d(wrongDaemon)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongOwner.Ensure(ctx, Specification{ID: id}, handler); err == nil {
		t.Fatal("reattached ownership on another daemon")
	}
	if err = wrongOwner.Delete(ctx, id); err == nil {
		t.Fatal("deleted ownership on another daemon")
	}
	if err = wrongOwner.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = NewK3d(config)
	if err != nil {
		t.Fatal(err)
	}
	// A valid name with a different persisted runtime ID cannot adopt or delete.
	foreign := state
	foreign.ID = "foreign-claim"
	foreignDir := runtime.resourceDir(foreign.ID)
	if err = os.Mkdir(foreignDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = saveState(foreignDir, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Ensure(ctx, Specification{ID: foreign.ID}, handler); err == nil {
		t.Fatal("adopted another runtime ID by name")
	}
	if err = runtime.Delete(ctx, foreign.ID); err == nil {
		t.Fatal("deleted another runtime ID by name")
	}
	if err = os.Remove(filepath.Join(foreignDir, "owner.json")); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(foreignDir); err != nil {
		t.Fatal(err)
	}
	reopened, err := runtime.Ensure(ctx, Specification{ID: id}, handler)
	if err != nil {
		t.Fatal(err)
	}
	if reopened != endpoint {
		t.Fatal("public endpoint or CA changed across restart")
	}
	assertRetainedNativeIssuer(t, ctx, runtime, id, issuerConfiguration, issuerKeys)
	status, data = request("GET", "/api/v1/namespaces/default/pods?labelSelector=app%3Dnative-proof", "fixture-admin", "", false)
	if status != 200 || json.Unmarshal(data, &pods) != nil || len(pods.Items) != 1 || pods.Items[0].Metadata.UID != podUID {
		t.Fatalf("pod lost across restart: %d %s", status, data)
	}
	t.Log("same native pod and TLS endpoint survived owner restart; foreign ownership rejected")
	sentinel := filepath.Join(runtime.resourceDir(id), "foreign.keep")
	if err = os.WriteFile(sentinel, []byte("not owned by runtime"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Delete(ctx, id); err == nil {
		t.Fatal("removed unrelated resource directory content")
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "not owned by runtime" {
		t.Fatalf("unrelated file changed: %v", err)
	}
	if _, err = runtime.Ensure(ctx, Specification{ID: id}, handler); err == nil {
		t.Fatal("recreated cluster during interrupted deletion")
	}
	if err = os.Remove(sentinel); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(runtime.resourceDir(id)); !os.IsNotExist(err) {
		t.Fatalf("owned files retained: %v", err)
	}
	containers, err := runtime.ownedContainers(ctx, state)
	if err != nil || len(containers) != 0 {
		t.Fatalf("owned containers retained: %v (count=%d)", err, len(containers))
	}
	network, err := runtime.ownedNetwork(ctx, state)
	if err != nil || network != "" {
		t.Fatalf("owned network retained: %v %s", err, network)
	}
	volume, err := runtime.ownedVolume(ctx, state)
	if err != nil || volume != "" {
		t.Fatalf("owned image volume retained: %v %s", err, volume)
	}
	t.Log("exact-owned cluster, network and private files deleted")
}
