package eks

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"stackd/compute/eks/ecrcredentials"
)

func newECRFixture(t *testing.T) (*K3d, diskState, string) {
	t.Helper()
	dir := t.TempDir()
	provider := filepath.Join(dir, "creation-provider")
	if err := os.WriteFile(provider, []byte("independent executable fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	credentialsPath := filepath.Join(dir, "credentials.json")
	credentials := ecrcredentials.Config{Endpoint: "https://172.17.0.1:40001", Region: "us-east-1", AccessKeyID: "fixture-node-key", SecretAccessKey: "fixture-node-secret"}
	data, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialsPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	config := Config{DataDir: dir, DockerHost: "unix:///fixture-daemon.sock", ListenHost: "127.0.0.1", AdvertiseHost: "127.0.0.1", ECRCredentialProvider: provider, ECRCredentialsFile: credentialsPath, ECRCA: ca}
	if err := configureECR(&config); err != nil {
		t.Fatal(err)
	}
	k := &K3d{config: config}
	state, resource, err := k.loadOrPrepare("registry-worker")
	if err != nil {
		t.Fatal(err)
	}
	return k, state, resource
}

func ecrFixtureContainer(t *testing.T, k *K3d, resource string) dockerContainer {
	t.Helper()
	mounts := []map[string]any{}
	for _, mount := range k.ecrMounts(resource) {
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": mount.Source, "Destination": mount.Destination, "RW": false})
	}
	body, err := json.Marshal(map[string]any{"Mounts": mounts})
	if err != nil {
		t.Fatal(err)
	}
	var container dockerContainer
	if err := json.Unmarshal(body, &container); err != nil {
		t.Fatal(err)
	}
	return container
}

func TestECRWorkerConfiguration(t *testing.T) {
	k, state, resource := newECRFixture(t)
	pending := k.config
	pending.ECRCredentialsFile = filepath.Join(t.TempDir(), "future-credentials.json")
	pending.ECRCredentialProvider = filepath.Join(t.TempDir(), "future-provider")
	if err := configureECR(&pending); err != nil {
		t.Fatal("daemon startup must not read cluster creation inputs:", err)
	}
	if err := (&K3d{config: pending}).prepareECR(&state, resource, true); err == nil {
		t.Fatal("cluster creation accepted a missing node credentials file")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.ECRCredentialsFile = "" }, func(c *Config) { c.ECRCA = nil }, func(c *Config) { c.ECRCA = []byte("invalid") }} {
		bad := k.config
		mutate(&bad)
		if err := configureECR(&bad); err == nil {
			t.Fatal("accepted incomplete ECR trust/identity configuration")
		}
	}
	if err := k.prepareECR(&state, resource, true); err != nil {
		t.Fatal(err)
	}
	retained, err := readState(resource, state.ID)
	if err != nil || retained.ECRProvider == nil || *retained.ECRProvider != *state.ECRProvider || retained.ECRProvider.Preparing {
		t.Fatalf("provider identity was not durable before worker arguments: state=%+v error=%v", retained.ECRProvider, err)
	}
	args, err := k.workerArguments(state, resource)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"--kubelet-arg=image-credential-provider-config=/etc/stackd/ecr/provider.json@agent:0", "--kubelet-arg=image-credential-provider-bin-dir=/opt/stackd/bin@agent:0", k.config.ECRCredentialsFile + ":/etc/stackd/ecr/credentials.json:ro@agent:0", filepath.Join(resource, ecrProviderName) + ":/opt/stackd/bin/stackd-ecr-credential-provider:ro@agent:0"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing worker argument %s", required)
		}
	}
	if strings.Contains(joined, k.config.ECRCredentialProvider+":") || strings.Contains(joined, "fixture-node-secret") || strings.Contains(joined, "fixture-node-key") {
		t.Fatal("worker command exposes the controller executable or private credentials")
	}
	for _, name := range []string{"ecr-ca.pem", "ecr-provider.json", "ecr-registries.yaml"} {
		body, err := readPrivate(filepath.Join(resource, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("fixture-node-secret")) || bytes.Contains(body, []byte("insecure_skip_verify")) || bytes.Contains(body, []byte(`"auth"`)) {
			t.Fatalf("%s contains credentials or TLS bypass", name)
		}
	}
	var registry struct {
		Configs map[string]struct {
			TLS struct {
				CAFile string `json:"ca_file"`
			} `json:"tls"`
		} `json:"configs"`
	}
	body, err := readPrivate(filepath.Join(resource, "ecr-registries.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &registry); err != nil {
		t.Fatal(err)
	}
	if registry.Configs["172.17.0.1:40001"].TLS.CAFile != "/etc/stackd/ecr/ca.pem" {
		t.Fatal("containerd registry CA does not match provider trust")
	}
	container := ecrFixtureContainer(t, k, resource)
	if err := k.validateWorkerECR(state, container); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []string{"writable", "source", "destination", "type", "duplicate", "missing"} {
		t.Run(tc, func(t *testing.T) {
			bad := ecrFixtureContainer(t, k, resource)
			switch tc {
			case "writable":
				bad.Mounts[0].RW = true
			case "source":
				bad.Mounts[0].Source = k.config.ECRCredentialProvider
			case "destination":
				bad.Mounts[0].Destination += "-other"
			case "type":
				bad.Mounts[0].Type = "volume"
			case "duplicate":
				bad.Mounts = append(bad.Mounts, bad.Mounts[0])
			case "missing":
				bad.Mounts = bad.Mounts[:len(bad.Mounts)-1]
			}
			if err := k.validateWorkerECR(state, bad); err == nil {
				t.Fatal("reattached an unsafe ECR mount")
			}
		})
	}
	disabled := &K3d{config: Config{DataDir: k.config.DataDir}}
	if err := disabled.validateWorkerECR(state, container); err == nil {
		t.Fatal("silently disabled retained worker ECR configuration")
	}
	legacy := state
	legacy.ECRProvider = nil
	if err := k.validateWorkerECR(legacy, container); err == nil || !strings.Contains(err.Error(), "recreation") {
		t.Fatalf("legacy provider was silently migrated: %v", err)
	}
	k.config.ECRCA = append(bytes.Clone(k.config.ECRCA), '\n')
	if err := k.prepareECR(&state, resource, false); err == nil {
		t.Fatal("silently replaced retained mounted CA")
	}
}

func TestECRCredentialRotationPreservesProvider(t *testing.T) {
	k, state, resource := newECRFixture(t)
	if err := k.prepareECR(&state, resource, true); err != nil {
		t.Fatal(err)
	}
	identity := *state.ECRProvider
	credentials, err := ecrcredentials.Load(k.config.ECRCredentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	credentials.AccessKeyID = "rotated-fixture-key"
	credentials.SecretAccessKey = "rotated-fixture-secret"
	data, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	// Credentials intentionally retain their mounted inode; executable and CA
	// ownership are independent of this explicitly supported rotation.
	if err := os.WriteFile(k.config.ECRCredentialsFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := k.prepareECR(&state, resource, false); err != nil {
		t.Fatal(err)
	}
	if *state.ECRProvider != identity {
		t.Fatal("credential rotation replaced provider identity")
	}
	credentials.Endpoint = "https://172.17.0.1:40002"
	data, err = json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.config.ECRCredentialsFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := k.prepareECR(&state, resource, false); err == nil {
		t.Fatal("credential rotation changed retained registry authority")
	}
}
