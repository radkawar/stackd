package eks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestIRSAAdmissionNativeFixtures(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/eks/irsa_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Label, Service, Operation string
			Input, Output             json.RawMessage
			Status                    int
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var region string
	accounts := make(map[string]json.RawMessage)
	for _, row := range fixture.Observations {
		if row.Service == "eks" && row.Operation == "describe-cluster" {
			var description struct{ Cluster struct{ ARN string } }
			if err := json.Unmarshal(row.Output, &description); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(description.Cluster.ARN, ":")
			if len(parts) != 6 {
				t.Fatal("captured cluster ARN does not identify its region")
			}
			region = parts[3]
		}
		if row.Service != "kubernetes" {
			continue
		}
		var object struct {
			Kind     string
			Metadata podIdentityObjectMeta
		}
		if err = json.Unmarshal(row.Input, &object); err != nil {
			t.Fatal(err)
		}
		if object.Kind == "ServiceAccount" {
			accounts[object.Metadata.Namespace+"/"+object.Metadata.Name] = row.Output
		}
	}
	if region == "" {
		t.Fatal("fixture has no cluster region")
	}
	tested := make(map[string]bool)
	for _, row := range fixture.Observations {
		if row.Service != "kubernetes" {
			continue
		}
		var input struct {
			Kind     string
			Metadata podIdentityObjectMeta
			Spec     map[string]any
		}
		if err = json.Unmarshal(row.Input, &input); err != nil {
			t.Fatal(err)
		}
		if input.Kind != "Pod" || tested[row.Label] {
			continue
		}
		tested[row.Label] = true
		t.Run(row.Label, func(t *testing.T) {
			name, _ := input.Spec["serviceAccountName"].(string)
			account, ok := accounts[input.Metadata.Namespace+"/"+name]
			if !ok {
				t.Fatalf("missing captured ServiceAccount %s/%s", input.Metadata.Namespace, name)
			}
			cluster := irsaFixtureCluster(t, account, http.StatusOK)
			cluster.region = region
			cluster.fargateProfiles = func(context.Context) ([]FargateSpecification, error) { return nil, nil }
			cluster.podIdentityService = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if row.Label == "coexist" || row.Label == "association-only" {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			})
			runtime := &K3d{}
			response := admitIRSAFixture(t, runtime, cluster, input.Metadata.Namespace, row.Input)
			if row.Status >= 400 {
				if response.Allowed {
					t.Fatal("admitted a pod rejected by native EKS")
				}
				return
			}
			if !response.Allowed {
				t.Fatalf("admission denied: %+v", response.Status)
			}
			var patches []struct {
				Op, Path string
				Value    any
			}
			if len(response.Patch) != 0 {
				if err := json.Unmarshal(response.Patch, &patches); err != nil {
					t.Fatal(err)
				}
			}
			for _, patch := range patches {
				if patch.Op != "add" || !strings.HasPrefix(patch.Path, "/spec/") || strings.Contains(strings.TrimPrefix(patch.Path, "/spec/"), "/") {
					t.Fatalf("unexpected admission patch: %+v", patch)
				}
				input.Spec[strings.TrimPrefix(patch.Path, "/spec/")] = patch.Value
			}
			var expected struct{ Spec map[string]any }
			if err := json.Unmarshal(row.Output, &expected); err != nil {
				t.Fatal(err)
			}
			association := row.Label == "coexist" || row.Label == "association-only"
			actual, want := irsaCredentialSpec(input.Spec, association), irsaCredentialSpec(expected.Spec, association)
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf("credential projection differs from AWS\nactual: %s\nAWS: %s", jsonForIRSAFixture(actual), jsonForIRSAFixture(want))
			}
		})
	}
	for _, required := range []string{"defaults", "pod-expiry", "sa-expiry-below", "sa-expiry-above", "regional-false", "skip", "caller-role-only", "caller-volume", "coexist", "unannotated"} {
		if !tested[required] {
			t.Errorf("native fixture does not cover %s", required)
		}
	}
}

func TestIRSAAdmissionKeepsFargateIdentity(t *testing.T) {
	const account = `{"metadata":{"name":"workload","namespace":"workloads","annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/workload"}}}`
	for _, labeled := range []bool{false, true} {
		t.Run(fmt.Sprintf("compute-label=%t", labeled), func(t *testing.T) {
			cluster := irsaFixtureCluster(t, []byte(account), http.StatusOK)
			cluster.region = "us-east-1"
			cluster.fargateProfiles = func(context.Context) ([]FargateSpecification, error) {
				return []FargateSpecification{{Name: "profile", Selectors: []FargateSelector{{Namespace: "workloads"}}}}, nil
			}
			cluster.podIdentityService = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("Fargate attempted to use a Pod Identity association")
				w.WriteHeader(http.StatusNoContent)
			})
			labels := map[string]string{}
			if labeled {
				labels["eks.amazonaws.com/compute-type"] = "fargate"
			}
			pod, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"serviceAccountName": "workload", "containers": []any{map[string]any{"name": "main"}}}})
			if err != nil {
				t.Fatal(err)
			}
			response := admitIRSAFixture(t, &K3d{}, cluster, "workloads", pod)
			if !response.Allowed {
				t.Fatalf("Fargate IRSA admission denied: %+v", response.Status)
			}
			var patches []struct {
				Path  string
				Value json.RawMessage
			}
			if err := json.Unmarshal(response.Patch, &patches); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, patch := range patches {
				if patch.Path != "/spec/containers" {
					continue
				}
				var containers []struct {
					Env []struct{ Name, Value string }
				}
				if err := json.Unmarshal(patch.Value, &containers); err != nil {
					t.Fatal(err)
				}
				for _, container := range containers {
					for _, env := range container.Env {
						if env.Name == "AWS_ROLE_ARN" && env.Value == "arn:aws:iam::123456789012:role/workload" {
							found = true
						}
						if env.Name == "AWS_CONTAINER_CREDENTIALS_FULL_URI" {
							t.Fatal("Fargate received unsupported Pod Identity credentials")
						}
					}
				}
			}
			if !found {
				t.Fatal("Fargate did not receive its annotated IRSA role")
			}
		})
	}
}

func TestIRSAAdmissionRejectsUnavailableServiceAccountAuthority(t *testing.T) {
	cluster := irsaFixtureCluster(t, []byte(`{"kind":"Status","message":"unavailable"}`), http.StatusServiceUnavailable)
	response := admitIRSAFixture(t, &K3d{}, cluster, "default", json.RawMessage(`{"spec":{"serviceAccountName":"workload","containers":[{"name":"main"}]}}`))
	if response.Allowed || len(response.Patch) != 0 || response.Status == nil {
		t.Fatal("unavailable ServiceAccount authority admitted or mutated a pod")
	}
}

func irsaFixtureCluster(t *testing.T, account []byte, status int) *nativeCluster {
	t.Helper()
	var object struct{ Metadata podIdentityObjectMeta }
	if status == http.StatusOK {
		if err := json.Unmarshal(account, &object); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/serviceaccounts/") {
			t.Errorf("unexpected native request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if status == http.StatusOK && r.URL.Path != "/api/v1/namespaces/"+object.Metadata.Namespace+"/serviceaccounts/"+object.Metadata.Name {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(account)
	}))
	t.Cleanup(server.Close)
	_, rawPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	return &nativeCluster{state: diskState{NativePort: port}, client: server.Client()}
}

func admitIRSAFixture(t *testing.T, runtime *K3d, cluster *nativeCluster, namespace string, pod json.RawMessage) *podIdentityAdmissionResponse {
	t.Helper()
	body, err := json.Marshal(map[string]any{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": map[string]any{"uid": "fixture", "namespace": namespace, "operation": "CREATE", "object": pod}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	runtime.podIdentityHandler(cluster).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body)))
	var review podIdentityAdmission
	if err := json.Unmarshal(response.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || review.Response == nil {
		t.Fatalf("invalid admission response: %d %s", response.Code, response.Body.String())
	}
	return review.Response
}

// Keep credential behavior and caller configuration; omit API-server defaults
// unrelated to identity (DNS policy, image pull policy and kube-api-access).
// Association rows assert mechanism precedence, not a change to the preexisting
// Pod Identity regional-environment and jittered-token defaults.
func irsaCredentialSpec(spec map[string]any, association bool) map[string]any {
	out := make(map[string]any)
	for _, field := range []string{"containers", "initContainers"} {
		containers, _ := spec[field].([]any)
		for _, raw := range containers {
			container := raw.(map[string]any)
			entry := make(map[string]any)
			for _, key := range []string{"env", "volumeMounts"} {
				values, _ := container[key].([]any)
				indexed := make(map[string]any)
				for _, value := range values {
					item := value.(map[string]any)
					name := item["name"].(string)
					if strings.HasPrefix(name, "kube-api-access-") {
						continue
					}
					if association && key == "env" && (name == "AWS_REGION" || name == "AWS_DEFAULT_REGION" || name == "AWS_STS_REGIONAL_ENDPOINTS") {
						continue
					}
					if key == "volumeMounts" && item["readOnly"] == false {
						delete(item, "readOnly")
					}
					indexed[name] = item
				}
				entry[key] = indexed
			}
			out[field+"/"+container["name"].(string)] = entry
		}
	}
	volumes := make(map[string]any)
	items, _ := spec["volumes"].([]any)
	for _, raw := range items {
		volume := raw.(map[string]any)
		name := volume["name"].(string)
		if association && name == "eks-pod-identity-token" {
			projected, _ := volume["projected"].(map[string]any)
			sources, _ := projected["sources"].([]any)
			for _, source := range sources {
				projection, _ := source.(map[string]any)["serviceAccountToken"].(map[string]any)
				delete(projection, "expirationSeconds")
			}
		}
		if !strings.HasPrefix(name, "kube-api-access-") {
			volumes[name] = volume
		}
	}
	out["volumes"] = volumes
	return out
}

func jsonForIRSAFixture(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(err)
	}
	return string(encoded)
}
