package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type ecsControlRow struct {
	Label, Service, Operation, Region, Code string
	StartedAt                               time.Time
	Input                                   json.RawMessage
	HTTPStatus                              int `json:"http_status"`
	RawResponseBody                         json.RawMessage
}

type ecsControlFixture struct {
	Calls, CorrectionCalls, ClusterFollowupCalls []ecsControlRow
}

func ecsControls(t *testing.T) ecsControlFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/ecs/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture ecsControlFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func ecsControlBody(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	if len(raw) > 0 && raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			t.Fatal(err)
		}
		raw = []byte(text)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// Compare semantic fields and field presence, not diagnostic prose or unordered
// tag/capability sets. Pagination and container-definition ordering remain intact.
func ecsControlCanonical(body map[string]any, operation string) {
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				visit(child)
				if key == "tags" || key == "compatibilities" || key == "requiresAttributes" {
					if values, ok := child.([]any); ok {
						slices.SortFunc(values, func(a, b any) int {
							left, _ := json.Marshal(a)
							right, _ := json.Marshal(b)
							return strings.Compare(string(left), string(right))
						})
					}
				}
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(body)
	if strings.EqualFold(strings.ReplaceAll(operation, "-", ""), "DeleteTaskDefinitions") {
		if failures, ok := body["failures"].([]any); ok {
			for _, value := range failures {
				failure := value.(map[string]any)
				if _, ok := failure["reason"]; ok {
					failure["reason"] = "<diagnostic>"
				}
			}
		}
	}
}

func TestECSNativeControlsAcrossReopen(t *testing.T) {
	fixture := ecsControls(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source})
			_, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
			timestamps := map[string]map[string]float64{}
			rows := append(slices.Clone(fixture.Calls), fixture.CorrectionCalls...)
			for _, row := range rows {
				if row.Service != "ecs" {
					continue
				}
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				ok := t.Run(row.Label, func(t *testing.T) {
					wire := &awstest.WireClient{Client: clients.server.Client()}
					client := ecs.New(ecs.Options{Region: row.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: wire, RetryMaxAttempts: 1})
					_, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
					if row.Code != "Success" {
						assertAPIError(t, err, row.Code)
					} else if err != nil {
						t.Fatal(err)
					}
					if wire.Status != row.HTTPStatus {
						t.Fatalf("HTTP status %d want %d", wire.Status, row.HTTPStatus)
					}
					if err != nil {
						return
					}
					actual, expected := ecsControlBody(t, wire.Body), ecsControlBody(t, row.RawResponseBody)
					if definition, ok := expected["taskDefinition"].(map[string]any); ok {
						arn := definition["taskDefinitionArn"].(string)
						if row.Operation == "RegisterTaskDefinition" {
							timestamps[arn] = map[string]float64{"registeredAt": float64(source.Now().UnixMilli()) / 1000}
						}
						if row.Operation == "DeregisterTaskDefinition" && definition["previousStatus"] == "ACTIVE" {
							timestamps[arn]["deregisteredAt"] = float64(source.Now().UnixMilli()) / 1000
						}
					}
					var relocateTimes func(any)
					relocateTimes = func(value any) {
						switch value := value.(type) {
						case map[string]any:
							if arn, ok := value["taskDefinitionArn"].(string); ok {
								for field, at := range timestamps[arn] {
									if _, present := value[field]; present {
										value[field] = at
									}
								}
							}
							for _, child := range value {
								relocateTimes(child)
							}
						case []any:
							for _, child := range value {
								relocateTimes(child)
							}
						}
					}
					relocateTimes(expected)
					ecsControlCanonical(actual, row.Operation)
					ecsControlCanonical(expected, row.Operation)
					if !reflect.DeepEqual(actual, expected) {
						got, _ := json.Marshal(actual)
						want, _ := json.Marshal(expected)
						t.Fatalf("native response mismatch\n got %s\nwant %s", got, want)
					}
				})
				if !ok {
					return
				}
				// Reopening at successful creation and lifecycle transitions exercises
				// retained revisions, idempotency arguments, tags and timestamps.
				if row.Code == "Success" && (row.Operation == "CreateCluster" || row.Operation == "UpdateCluster" || row.Operation == "RegisterTaskDefinition" || row.Operation == "DeregisterTaskDefinition" || row.Operation == "DeleteTaskDefinitions") {
					clients = reopen()
				}
			}
		})
	}
}

func TestECSNativeClusterFollowupControls(t *testing.T) {
	fixture := ecsControls(t)
	clients := clockCloud(t, stackd.Config{AccountID: "000000000000"})
	for index, row := range fixture.ClusterFollowupCalls {
		t.Run(fmt.Sprintf("%02d_%s_%s", index, row.Region, row.Operation), func(t *testing.T) {
			wire := &awstest.WireClient{Client: clients.server.Client()}
			client := ecs.New(ecs.Options{Region: row.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: wire, RetryMaxAttempts: 1})
			_, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
			if row.Code != "Success" {
				assertAPIError(t, err, row.Code)
			} else if err != nil {
				t.Fatal(err)
			}
			if wire.Status != row.HTTPStatus {
				t.Fatalf("HTTP status %d want %d", wire.Status, row.HTTPStatus)
			}
			if err != nil {
				return
			}
			actual, expected := ecsControlBody(t, wire.Body), ecsControlBody(t, row.RawResponseBody)
			ecsControlCanonical(actual, row.Operation)
			ecsControlCanonical(expected, row.Operation)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("regional lifecycle response=%v want %v", actual, expected)
			}
		})
	}
}
