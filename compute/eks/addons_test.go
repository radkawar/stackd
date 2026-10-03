package eks

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func TestCoreDNSConfigurationSchemaBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/eks/addons_configuration.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Configuration string
			Valid               bool
			Replicas            *int32
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Cases {
		t.Run(row.Name, func(t *testing.T) {
			actual, err := ParseCoreDNSConfiguration(row.Configuration)
			if (err == nil) != row.Valid {
				t.Fatalf("configuration validity mismatch: %v", err)
			}
			if row.Valid && row.Replicas != nil && (actual.ReplicaCount == nil || *actual.ReplicaCount != *row.Replicas) {
				t.Fatalf("replica configuration lost: %+v", actual)
			}
		})
	}
}

func TestAddonPreserveUserOwnedFields(t *testing.T) {
	// Kubernetes FieldsV1 encodings match the retained native agent DaemonSet.
	// These are local user edits, not fabricated AWS captures.
	for _, row := range []struct {
		name, desired, actual, fields, expected string
	}{
		{
			name:     "Corefile",
			desired:  `{"data":{"Corefile":"managed","other":"requested"}}`,
			actual:   `{"data":{"Corefile":"user","other":"old"}}`,
			fields:   `{"f:data":{"f:Corefile":{}}}`,
			expected: `{"data":{"Corefile":"user","other":"requested"}}`,
		},
		{
			name:     "atomic-RBAC-rules",
			desired:  `{"rules":[{"resources":["pods"],"verbs":["list"]}],"metadata":{"labels":{"managed":"new"}}}`,
			actual:   `{"rules":[{"resources":["pods","configmaps"],"verbs":["list","get"]}],"metadata":{"labels":{"managed":"old"}}}`,
			fields:   `{"f:rules":{}}`,
			expected: `{"rules":[{"resources":["pods","configmaps"],"verbs":["list","get"]}],"metadata":{"labels":{"managed":"new"}}}`,
		},
		{
			name:     "PodIdentity-keyed-container-resource",
			desired:  `{"spec":{"template":{"metadata":{"annotations":{"requested":"new"}},"spec":{"containers":[{"name":"agent","resources":{"requests":{"cpu":"20m","memory":"64Mi"}}},{"name":"sidecar","image":"new"}]}}}}`,
			actual:   `{"spec":{"template":{"metadata":{"annotations":{"requested":"old"}},"spec":{"containers":[{"name":"sidecar","image":"old"},{"name":"agent","resources":{"requests":{"cpu":"15m","memory":"32Mi"}}}]}}}}`,
			fields:   `{"f:spec":{"f:template":{"f:spec":{"f:containers":{"k:{\"name\":\"agent\"}":{".":{},"f:name":{},"f:resources":{"f:requests":{"f:cpu":{}}}}}}}}}`,
			expected: `{"spec":{"template":{"metadata":{"annotations":{"requested":"new"}},"spec":{"containers":[{"name":"agent","resources":{"requests":{"cpu":"15m","memory":"64Mi"}}},{"name":"sidecar","image":"new"}]}}}}`,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			var desired, actual, fields, expected map[string]any
			for _, input := range []struct {
				raw string
				out *map[string]any
			}{{row.desired, &desired}, {row.actual, &actual}, {row.fields, &fields}, {row.expected, &expected}} {
				if err := json.Unmarshal([]byte(input.raw), input.out); err != nil {
					t.Fatal(err)
				}
			}
			preserveAddonFields(desired, actual, fields)
			if !reflect.DeepEqual(desired, expected) {
				t.Fatalf("PRESERVE changed user fields or suppressed unrelated requested changes: got=%#v want=%#v", desired, expected)
			}
		})
	}
}

func TestCoreDNSReadinessCurrentRevision(t *testing.T) {
	data, err := os.ReadFile("../../testdata/integration/eks_coredns_readiness_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Deployment  map[string]any
		ReplicaSets json.RawMessage
		Cases       []struct {
			Name, Want         string
			ObservedGeneration int64
			AvailableReplicas  int32
			Pods               json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Cases {
		t.Run(row.Name, func(t *testing.T) {
			status := fixture.Deployment["status"].(map[string]any)
			status["observedGeneration"] = row.ObservedGeneration
			status["availableReplicas"] = row.AvailableReplicas
			deployment, err := json.Marshal(fixture.Deployment)
			if err != nil {
				t.Fatal(err)
			}
			responses := map[string]json.RawMessage{
				"/apis/apps/v1/namespaces/kube-system/deployments/coredns": deployment,
				"/apis/apps/v1/namespaces/kube-system/replicasets":         fixture.ReplicaSets,
				"/api/v1/namespaces/kube-system/pods":                      row.Pods,
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, ok := responses[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			t.Cleanup(server.Close)
			cluster := nativeCluster{state: diskState{NativePort: server.Listener.Addr().(*net.TCPAddr).Port}, client: server.Client()}
			err = cluster.coreDNSReadiness(t.Context(), 2, "coredns/coredns:1.12.3")
			switch row.Want {
			case "ready":
				if err != nil {
					t.Fatal(err)
				}
			case "pending":
				var pending *AddonPending
				if !errors.As(err, &pending) {
					t.Fatalf("stale scheduling observation ended rollout: %v", err)
				}
			default:
				var failed *AddonError
				if !errors.As(err, &failed) || failed.Code != row.Want {
					t.Fatalf("current scheduling failure = %v, want %s", err, row.Want)
				}
			}
		})
	}
}
