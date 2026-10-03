package eks_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite"
	eksdb "stackd/storage/sqlite/eks"
)

type podFixturePrincipals struct{}

func (podFixturePrincipals) ResolvePrincipal(_ context.Context, arn string) (string, error) {
	return "fixture-immutable-" + arn, nil
}

// Native captures distinguish create-token replay from update-token application.
// The database variant replaces its controller and connection after first create.
func TestPodIdentityNativeAssociationReplay(t *testing.T) {
	for _, fixtureName := range []string{"podidentity_native_controls.json", "depth_native_health.json"} {
		t.Run(fixtureName, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					var fixture struct {
						Region string
						Calls  []struct {
							Operation string
							Input     json.RawMessage
							Output    map[string]any
							Error     string
						}
					}
					data, err := os.ReadFile("../../../testdata/aws/eks/" + fixtureName)
					if err != nil {
						t.Fatal(err)
					}
					if err = json.Unmarshal(data, &fixture); err != nil {
						t.Fatal(err)
					}
					var clusterName string
					for _, call := range fixture.Calls {
						if call.Operation == "create-pod-identity-association" {
							var input struct{ ClusterName string }
							if err := json.Unmarshal(call.Input, &input); err != nil {
								t.Fatal(err)
							}
							clusterName = input.ClusterName
							break
						}
					}
					if clusterName == "" {
						t.Fatal("native capture has no association-create cluster")
					}
					var repository domain.Repository = domain.NewMemoryRepository(nil)
					restart := func() {}
					if backend == "sqlite" {
						path := filepath.Join(t.TempDir(), "podidentity.db")
						db, err := sqlite.Open(t.Context(), path)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = db.Close() })
						repository = eksdb.New(db)
						restart = func() {
							if err := db.Close(); err != nil {
								t.Fatal(err)
							}
							db, err = sqlite.Open(t.Context(), path)
							if err != nil {
								t.Fatal(err)
							}
							repository = eksdb.New(db)
						}
					}
					key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "000000000000", Region: fixture.Region}, Name: clusterName}
					if err = repository.Update(t.Context(), func(tx domain.Transaction) error {
						return tx.PutCluster(domain.Cluster{Key: key, ID: "fixture-cluster-incarnation", Status: "ACTIVE"})
					}); err != nil {
						t.Fatal(err)
					}
					service := domain.New(domain.Config{Repository: repository, Principals: podFixturePrincipals{}})
					t.Cleanup(func() { _ = service.Close() })
					ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PrincipalARN: "arn:aws:iam::" + key.AccountID + ":root", PrincipalID: key.AccountID})
					model, _ := awscatalog.LookupService("eks")
					ids := map[string]string{}
					errorCode := regexp.MustCompile(`\((\w+Exception)\)`)
					restarted := false
					for i, row := range fixture.Calls {
						if !strings.Contains(row.Operation, "pod-identity-association") {
							continue
						}
						operation := ""
						for _, part := range strings.Split(row.Operation, "-") {
							operation += strings.ToUpper(part[:1]) + part[1:]
						}
						input, err := awscommands.NewInput("eks", operation)
						if err != nil {
							t.Fatal(err)
						}
						body := string(row.Input)
						for native, local := range ids {
							body = strings.ReplaceAll(body, native, local)
						}
						if err = json.Unmarshal([]byte(body), input); err != nil {
							t.Fatal(err)
						}
						op, _ := model.Operation(operation)
						output, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
						if row.Error != "" {
							expected := errorCode.FindStringSubmatch(row.Error)
							if len(expected) != 2 {
								t.Fatalf("unrecognized native error: %s", row.Error)
							}
							if rejected == nil || rejected.Code != expected[1] {
								t.Fatalf("step %d %s: got %v, native %s", i, operation, rejected, expected[1])
							}
							continue
						}
						if rejected != nil {
							t.Fatalf("step %d %s: %v", i, operation, rejected)
						}
						encoded, err := awsapi.EncodeResponse(model, op, output)
						if err != nil {
							t.Fatal(err)
						}
						var actual map[string]any
						if err = json.Unmarshal(encoded, &actual); err != nil {
							t.Fatal(err)
						}
						if association, ok := row.Output["association"].(map[string]any); ok {
							observed := actual["association"].(map[string]any)
							nativeID := association["associationId"].(string)
							localID := observed["associationId"].(string)
							if old, ok := ids[nativeID]; ok && old != localID {
								t.Fatalf("step %d changed association incarnation on replay", i)
							}
							ids[nativeID] = localID
						}
						expected := podFixtureNormalize(row.Output, ids)
						actualNormalized := podFixtureNormalize(actual, nil)
						if !reflect.DeepEqual(actualNormalized, expected) {
							t.Fatalf("step %d %s differs from native state\nactual %s\nexpected %s", i, operation, mustPodJSON(actualNormalized), mustPodJSON(expected))
						}
						if !restarted && operation == "CreatePodIdentityAssociation" {
							if err = service.Close(); err != nil {
								t.Fatal(err)
							}
							restart()
							service = domain.New(domain.Config{Repository: repository, Principals: podFixturePrincipals{}})
							restarted = true
						}
					}
				})
			}
		})
	}
}
func podFixtureNormalize(v any, ids map[string]string) any {
	switch value := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			if key == "createdAt" || key == "modifiedAt" {
				continue
			}
			out[key] = podFixtureNormalize(item, ids)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = podFixtureNormalize(item, ids)
		}
		return out
	case string:
		for native, local := range ids {
			value = strings.ReplaceAll(value, native, local)
		}
		return value
	default:
		return v
	}
}
func mustPodJSON(value any) string { b, _ := json.Marshal(value); return string(b) }

func TestPodIdentityAdmissionLookupAvailability(t *testing.T) {
	// Retained cluster/association state is the authority behind the native
	// failurePolicy=Fail webhook. Only a successful lookup with no matching
	// association may return 404 and admit an unmodified pod.
	for _, scenario := range []struct {
		name, status, clusterID, associationClusterID, serviceAccount string
		canceled, missingCluster                                      bool
		want                                                          int
	}{
		{name: "active association", status: "ACTIVE", want: http.StatusNoContent},
		{name: "updating association", status: "UPDATING", want: http.StatusNoContent},
		{name: "unassociated account", status: "UPDATING", serviceAccount: "unassociated", want: http.StatusNotFound},
		{name: "creating cluster", status: "CREATING", want: http.StatusServiceUnavailable},
		{name: "deleting cluster", status: "DELETING", want: http.StatusServiceUnavailable},
		{name: "failed cluster", status: "FAILED", want: http.StatusServiceUnavailable},
		{name: "replaced cluster", status: "ACTIVE", clusterID: "replacement", want: http.StatusServiceUnavailable},
		{name: "stale association", status: "UPDATING", associationClusterID: "previous", want: http.StatusNotFound},
		{name: "deleted cluster", missingCluster: true, want: http.StatusServiceUnavailable},
		{name: "lookup canceled", status: "ACTIVE", canceled: true, want: http.StatusServiceUnavailable},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			repository := domain.NewMemoryRepository(nil)
			key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "pod-admission"}
			clusterID, associationClusterID := "current-cluster", "current-cluster"
			if scenario.clusterID != "" {
				clusterID = scenario.clusterID
			}
			if scenario.associationClusterID != "" {
				associationClusterID = scenario.associationClusterID
			}
			if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
				if !scenario.missingCluster {
					if err := tx.PutCluster(domain.Cluster{Key: key, ID: clusterID, Status: scenario.status}); err != nil {
						return err
					}
				}
				return tx.PutPodIdentityAssociation(domain.PodIdentityAssociation{Key: key, ID: "a-admission", ClusterID: associationClusterID, Namespace: "payments", ServiceAccount: "processor"})
			}); err != nil {
				t.Fatal(err)
			}
			service := domain.New(domain.Config{Repository: repository})
			t.Cleanup(func() { _ = service.Close() })
			account := scenario.serviceAccount
			if account == "" {
				account = "processor"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario.canceled {
				cancel()
			}
			request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/association?namespace=payments&serviceAccount="+account, nil)
			response := httptest.NewRecorder()
			service.PodIdentityHandler(key, "current-cluster").ServeHTTP(response, request)
			if response.Code != scenario.want {
				t.Fatalf("association lookup returned HTTP %d, want %d", response.Code, scenario.want)
			}
		})
	}
}
