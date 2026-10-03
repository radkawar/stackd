package eks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFargateDocumentedSelectorSemantics(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/eks/fargate_selectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name      string
			Selector  FargateSelector
			Namespace string
			Labels    map[string]string
			Matches   bool
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Cases {
		t.Run(row.Name, func(t *testing.T) {
			if err := ValidateFargateSelector(row.Selector); err != nil {
				t.Fatal(err)
			}
			if actual := MatchFargateSelector(row.Selector, row.Namespace, row.Labels); actual != row.Matches {
				t.Fatalf("matched=%t want %t", actual, row.Matches)
			}
		})
	}
}
func TestFargateNonmatchingAffinityExcludesEveryAlternative(t *testing.T) {
	var affinity map[string]any
	if err := json.Unmarshal([]byte(`{"podAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[]},"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"zone","operator":"In","values":["a"]}]},{"matchExpressions":[{"key":"zone","operator":"In","values":["b"]}]}]}}}`), &affinity); err != nil {
		t.Fatal(err)
	}
	actual := excludeFargateNodes(affinity)
	required := actual["nodeAffinity"].(map[string]any)["requiredDuringSchedulingIgnoredDuringExecution"].(map[string]any)
	for i, term := range required["nodeSelectorTerms"].([]any) {
		expressions := term.(map[string]any)["matchExpressions"].([]any)
		zone := expressions[0].(map[string]any)["values"].([]any)[0]
		if zone != []string{"a", "b"}[i] {
			t.Fatalf("existing alternative changed: %v", zone)
		}
		expression := expressions[1].(map[string]any)
		if expression["key"] != "eks.amazonaws.com/compute-type" || expression["operator"] != "NotIn" || expression["values"].([]string)[0] != "fargate" {
			t.Fatalf("Fargate can use alternative %d: %v", i, expression)
		}
	}
	if _, ok := actual["podAffinity"]; !ok {
		t.Fatal("unrelated pod affinity removed")
	}
}

func TestFargateWorkerNamesFitNativeHostnameLimit(t *testing.T) {
	state := diskState{Token: strings.Repeat("a", 64), Name: "stackd-" + strings.Repeat("a", 24)}
	first := fargateAgentName(state, strings.Repeat("b", 31)+"1")
	second := fargateAgentName(state, strings.Repeat("b", 31)+"2")
	for _, name := range []string{first, second} {
		if len(name) > 63 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			t.Fatalf("worker name cannot be used as a native hostname: %q", name)
		}
	}
	if first == second {
		t.Fatal("distinct pod slots collided after hostname shortening")
	}
}

func TestFargateAdmissionUsesCurrentlyEligibleProfiles(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/eks/fargate_selectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Admission struct {
			Profiles []FargateSpecification
			Stages   []struct {
				Name, Requested, Activate, Delete, WantName, WantID string
				Denied                                              bool
			}
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	profiles := fixture.Admission.Profiles
	cluster := &nativeCluster{
		state:           diskState{Name: "owned-fixture", Token: strings.Repeat("a", 64)},
		fargateProfiles: func(context.Context) ([]FargateSpecification, error) { return profiles, nil },
		fargateAuthorize: func(_ context.Context, id string) error {
			for _, profile := range profiles {
				if profile.ID == id && !profile.Delete && !profile.AdmissionDenied {
					return nil
				}
			}
			return errors.New("profile is not currently authorized")
		},
	}
	runtime := &K3d{clusters: map[string]*nativeCluster{"owned": cluster}}
	for _, stage := range fixture.Admission.Stages {
		t.Run(stage.Name, func(t *testing.T) {
			for i := range profiles {
				if profiles[i].Name == stage.Activate {
					profiles[i].AdmissionDenied = false
				}
				if profiles[i].Name == stage.Delete {
					profiles[i].Delete = true
				}
			}
			labels := map[string]string{}
			if stage.Requested != "" {
				labels[fargateProfileLabel] = stage.Requested
			}
			body, err := json.Marshal(map[string]any{"request": map[string]any{
				"uid": stage.Name, "namespace": "default", "operation": "CREATE",
				"object": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"containers": []any{map[string]any{"name": "workload", "image": "busybox:1.37.0"}}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			runtime.fargateAdmission("owned").ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body)))
			var review struct {
				Response struct {
					Allowed bool
					Patch   []byte
				}
			}
			if err := json.Unmarshal(response.Body.Bytes(), &review); err != nil {
				t.Fatal(err)
			}
			if stage.Denied {
				if review.Response.Allowed || len(review.Response.Patch) != 0 {
					t.Fatal("explicit inactive profile was admitted or redirected to another profile")
				}
				return
			}
			if !review.Response.Allowed {
				t.Fatal("an inactive matching profile prevented admission to an eligible profile")
			}
			var patches []struct {
				Path  string
				Value json.RawMessage
			}
			if err := json.Unmarshal(review.Response.Patch, &patches); err != nil {
				t.Fatal(err)
			}
			var admitted, selector map[string]string
			for _, patch := range patches {
				switch patch.Path {
				case "/metadata/labels":
					err = json.Unmarshal(patch.Value, &admitted)
				case "/spec/nodeSelector":
					err = json.Unmarshal(patch.Value, &selector)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if admitted[fargateProfileLabel] != stage.WantName || selector[fargateIDLabel] != stage.WantID {
				t.Fatalf("pod was not bound to the current eligible profile incarnation: labels=%v selector=%v", admitted, selector)
			}
		})
	}
}
