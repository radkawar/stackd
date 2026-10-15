package kafka

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"stackd/compute/docker"
	msk "stackd/internal/services/kafka"
)

func TestManagedBrokerStartsBehindEphemeralPacketAdmission(t *testing.T) {
	runtime := &Docker{imageID: "installed-native-image", endpointHost: "127.0.0.1"}
	spec := msk.Specification{Brokers: 1, DefaultMetrics: true, Networks: []msk.BrokerNetwork{{}}}
	material := &material{Nodes: []nodePorts{{Client: 9092, Admin: 19095}}, Networked: true}
	config := runtime.containerConfig(spec, "broker-1", material)
	if !strings.HasPrefix(config.Cmd[0], "while [ ! -e /mnt/shared/config/stackd-network-ready ];") {
		t.Fatal("native client can start before its current packet policy")
	}
	if _, exists := config.HostConfig.Tmpfs["/mnt/shared/config"]; !exists {
		t.Fatal("packet-admission marker can survive a broker restart")
	}
	if len(config.HostConfig.PortBindings["9092/tcp"]) != 0 {
		t.Fatal("managed client listener bypasses its EC2 address through a host port")
	}
	admin := config.HostConfig.PortBindings["9095/tcp"]
	if len(admin) != 1 || admin[0].HostIP != "127.0.0.1" || admin[0].HostPort != "19095" {
		t.Fatal("private administration lost its loopback binding")
	}
	for _, port := range []string{"9010/tcp", "9011/tcp"} {
		if _, exposed := config.ExposedPorts[port]; exposed || len(config.HostConfig.PortBindings[port]) != 0 {
			t.Fatal("native metrics exposes unauthenticated JMX outside broker loopback")
		}
	}
	environment := strings.Join(config.Env, " ")
	if !strings.Contains(environment, "-Dcom.sun.management.jmxremote.host=127.0.0.1") || !strings.Contains(environment, "-Djava.rmi.server.hostname=127.0.0.1") {
		t.Fatal("native JMX/RMI does not bind broker loopback")
	}
}

func TestAdministrationRequiresRuntimeOwnedClientIdentity(t *testing.T) {
	spec := msk.Specification{ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id", Incarnation: "id", Partition: "aws", AccountID: "111111111111", Region: "us-east-1", Brokers: 1, KafkaVersion: "3.7.1", SecurityMode: "SASL_SCRAM"}
	material, err := newMaterial(spec, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	material.Nodes = []nodePorts{{Client: 19092, Admin: 19095}}
	runtime := &Docker{endpointHost: "127.0.0.1"}
	properties := string(runtime.brokerProperties(spec, material, 0, nil))
	if !strings.Contains(properties, "listener.name.admin.ssl.client.auth=required\n") || !strings.Contains(properties, "listener.name.admin.sasl.enabled.mechanisms=SCRAM-SHA-512\n") {
		t.Fatal("customer SCRAM alone can authenticate on the native ADMIN listener")
	}
	_, transport, err := runtime.adminClient(material)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	if transport.TLS == nil || len(transport.TLS.Certificates) != 1 {
		t.Fatal("runtime admin client omitted its private TLS identity")
	}
	certificate, err := x509.ParseCertificate(transport.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: transport.TLS.RootCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("native client identity cannot authenticate: %v", err)
	}
	material.KeyPEM = nil
	if _, _, err := runtime.adminClient(material); err == nil {
		t.Fatal("admin client fell back to anonymous TLS without its runtime private key")
	}
}

func TestQuorumDNSAliasRemainsPrivateAndTLSVerified(t *testing.T) {
	spec := msk.Specification{ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id", Incarnation: "id", Partition: "aws", AccountID: "111111111111", Region: "us-east-1", Brokers: 2, KafkaVersion: "3.7.1", SecurityMode: "SASL_SCRAM"}
	material, err := newMaterial(spec, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(material.CertPEM)
	if block == nil {
		t.Fatal("missing native broker certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	material.Nodes = []nodePorts{{Client: 19092, Admin: 19095}, {Client: 29092, Admin: 29095}}
	spec.Networks = []msk.BrokerNetwork{{}, {}}
	runtime := &Docker{endpointHost: "127.0.0.1"}
	for node := range 2 {
		id := strconv.Itoa(node + 1)
		alias := resourceName(spec, "internal-"+id)
		if err := certificate.VerifyHostname(alias); err != nil {
			t.Fatalf("private quorum alias is not covered by native TLS identity: %v", err)
		}
		config := runtime.containerConfig(spec, "broker-"+id, material)
		endpoints := config.NetworkingConfig.EndpointsConfig
		if len(endpoints) != 1 || len(endpoints[resourceName(spec, "network")].Aliases) != 1 || endpoints[resourceName(spec, "network")].Aliases[0] != alias {
			t.Fatal("quorum alias escaped its exact owned private bridge")
		}
		if endpoints[resourceName(spec, "network")].GwPriority != 100 {
			t.Fatal("loopback ADMIN publication can select the customer interface")
		}
		properties := string(runtime.brokerProperties(spec, material, node, nil))
		if !strings.Contains(properties, id+"@"+alias+":9093") || !strings.Contains(properties, "INTERNAL://"+alias+":9094") {
			t.Fatal("quorum or interbroker traffic uses an ambiguous customer-facing container name")
		}
		if strings.Contains(properties, "@"+resourceName(spec, "broker-"+id)+":9093") || strings.Contains(properties, "INTERNAL://"+resourceName(spec, "broker-"+id)+":9094") {
			t.Fatal("customer bridge DNS can redirect private quorum traffic")
		}
	}
}

func TestDeleteRecoversOnlyExactInterruptedNetworkHelpers(t *testing.T) {
	spec := msk.Specification{ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id", Incarnation: "id", Partition: "aws", AccountID: "111111111111", Region: "us-east-1", Brokers: 1}
	for _, test := range []struct {
		name     string
		change   func(*containerState)
		conflict bool
	}{
		{name: "interrupted-create"},
		{name: "same-name-new-incarnation", change: func(s *containerState) { s.Config.Labels[labelPrefix+"id"] = "replacement" }, conflict: true},
		{name: "foreign-account", change: func(s *containerState) { s.Config.Labels[labelPrefix+"account"] = "222222222222" }, conflict: true},
		{name: "wrong-purpose", change: func(s *containerState) { s.Config.Labels[labelPrefix+"role"] = "broker-1" }, conflict: true},
		{name: "conflicting-image", change: func(s *containerState) { s.Image = "foreign-image-id" }, conflict: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &Docker{image: DockerImage, gate: make(chan struct{}, 1)}
			state := containerState{ID: "helper-id", Image: "toolkit-image-id"}
			state.Config.Image = docker.ToolkitImage
			state.Config.Labels = runtime.labels(spec, "network-helper")
			state.HostConfig.NetworkMode = "container:interrupted-owned-broker"
			state.State.Status = "created"
			if test.change != nil {
				test.change(&state)
			}
			var removed atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/v1.44")
				switch {
				case path == "/version":
					_, _ = w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
				case path == "/info":
					_, _ = w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
				case path == "/containers/json":
					var filters map[string][]string
					if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
						t.Error(err)
					}
					for key, value := range runtime.labels(spec, "network-helper") {
						if !strings.Contains(strings.Join(filters["label"], "\n"), key+"="+value) {
							t.Errorf("helper discovery lacks exact owner %s", key)
						}
					}
					if r.URL.Query().Get("all") != "true" {
						t.Error("interrupted create is not included in discovery")
					}
					_, _ = w.Write([]byte(`[{"Id":"helper-id"}]`))
				case strings.HasPrefix(path, "/images/"):
					_, _ = w.Write([]byte(`{"Id":"toolkit-image-id"}`))
				case path == "/containers/helper-id" && r.Method == http.MethodDelete:
					removed.Store(true)
					w.WriteHeader(http.StatusNoContent)
				case path == "/containers/helper-id/json" && !removed.Load():
					_ = json.NewEncoder(w).Encode(state)
				default:
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"absent"}`))
				}
			}))
			t.Cleanup(server.Close)
			client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			runtime.client = client
			err = runtime.Delete(t.Context(), spec)
			if (err != nil) != test.conflict {
				t.Fatalf("conflict=%t delete error=%v", test.conflict, err)
			}
			if removed.Load() == test.conflict {
				t.Fatal("Delete removed an ambiguous helper or retained its exact interrupted helper")
			}
		})
	}
}

func TestManagedKafkaRequiresGatewayPriorityCapabilityBeforeNativeEffects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/v1.47") {
		case "/version":
			_, _ = w.Write([]byte(`{"ApiVersion":"1.47","MinAPIVersion":"1.41","Os":"linux"}`))
		case "/info":
			_, _ = w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
		default:
			t.Errorf("unsupported dual-plane feature performed a native effect: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	runtime := &Docker{client: client, gate: make(chan struct{}, 1)}
	spec := msk.Specification{ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id", Incarnation: "id", Partition: "aws", AccountID: "111111111111", Region: "us-east-1", Brokers: 1, KafkaVersion: "3.7.1", SecurityMode: "TLS", Networks: []msk.BrokerNetwork{{}}}
	if _, err := runtime.Ensure(t.Context(), spec); err == nil || !strings.Contains(err.Error(), "requires Docker Engine API1.48") {
		t.Fatalf("managed Kafka did not reject missing negotiated capability: %v", err)
	}
	spec.Networks = nil
	if endpoint := runtime.containerConfig(spec, "broker-1", nil).NetworkingConfig.EndpointsConfig[resourceName(spec, "network")]; endpoint.GwPriority != 0 {
		t.Fatal("standalone Kafka unexpectedly requires a newer-daemon endpoint feature")
	}
}

func TestOwnedBrokerNamespaceExecFencesBeforeAndAfterProcessIdentity(t *testing.T) {
	cases := []struct {
		name          string
		before, after func(*containerState)
		wantExec      bool
		wantError     bool
	}{
		{name: "owned", wantExec: true},
		{name: "foreign-before", before: func(s *containerState) { s.Config.Labels[labelPrefix+"id"] = "replacement" }, wantError: true},
		{name: "stopped-before", before: func(s *containerState) { s.State.Running = false }, wantError: true},
		{name: "foreign-after", after: func(s *containerState) { s.Config.Labels[labelPrefix+"account"] = "222222222222" }, wantExec: true, wantError: true},
		{name: "same-id-restart-after", after: func(s *containerState) { s.State.Pid++; s.State.StartedAt = "replacement-start" }, wantExec: true, wantError: true},
		{name: "stopped-after", after: func(s *containerState) { s.State.Running = false }, wantExec: true, wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := &Docker{imageID: "owned-image"}
			spec := statusTestSpec()
			config := runtime.containerConfig(spec, "broker-1", nil)
			document := map[string]any{"Id": "owned-broker", "Image": runtime.imageID, "Config": config, "HostConfig": config.HostConfig,
				"State":           map[string]any{"Running": true, "Pid": 42, "StartedAt": "original-start"},
				"NetworkSettings": map[string]any{"Networks": map[string]any{resourceName(spec, "network"): map[string]any{"Aliases": []string{resourceName(spec, "internal-1")}, "GwPriority": 100}}}}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			var expected containerState
			if err = json.Unmarshal(encoded, &expected); err != nil {
				t.Fatal(err)
			}
			var executed atomic.Int32
			var finished atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/v1.44")
				switch {
				case path == "/version":
					w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
				case path == "/info":
					w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
				case path == "/containers/owned-broker/json":
					var current containerState
					json.Unmarshal(encoded, &current)
					if tc.before != nil {
						tc.before(&current)
					}
					if finished.Load() && tc.after != nil {
						tc.after(&current)
					}
					json.NewEncoder(w).Encode(current)
				case path == "/containers/owned-broker/exec":
					executed.Add(1)
					w.Write([]byte(`{"Id":"namespace-read"}`))
				case path == "/exec/namespace-read/start":
					finished.Store(true)
					payload := []byte("17\n")
					var header [8]byte
					header[0] = 1
					binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
					w.Write(header[:])
					w.Write(payload)
				case path == "/exec/namespace-read/json":
					w.Write([]byte(`{"Running":false,"ExitCode":0}`))
				default:
					t.Errorf("unexpected native exec request %s", path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			runtime.client = client
			output, err := runtime.executeOwnedBroker(context.Background(), spec, 0, expected, []string{"/bin/bash", "-ec", "read-iflink"})
			if (err != nil) != tc.wantError {
				t.Fatalf("identity proof error=%v wanted=%t", err, tc.wantError)
			}
			if (executed.Load() != 0) != tc.wantExec {
				t.Fatalf("foreign/non-running broker effect count=%d", executed.Load())
			}
			if !tc.wantError && string(output) != "17\n" {
				t.Fatalf("native namespace bytes=%q", output)
			}
		})
	}
}
