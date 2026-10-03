package ecs_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/smithy-go"

	"stackd"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awstest"
	domain "stackd/internal/services/ecs"
	"stackd/storage"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/backends"
)

type revisionCapture struct {
	Label, Operation, Code string
	Input, Output          json.RawMessage
}

// Replay the newly captured batch/scope boundaries through the real SDK and
// endpoint. Seed admitted ECS snapshots, not an execution adapter: no tasks run.
func TestDescribeServiceRevisionsNativeBoundariesAcrossReopen(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/ecs/service_revisions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Calls []revisionCapture }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	rows := map[string]revisionCapture{}
	for _, row := range fixture.Calls {
		rows[row.Label] = row
	}
	decode := func(label string, out any) {
		t.Helper()
		if err := json.Unmarshal(rows[label].Output, out); err != nil {
			t.Fatal(err)
		}
	}
	var cluster api.CreateClusterOutput
	var created api.CreateServiceOutput
	var definition api.RegisterTaskDefinitionOutput
	var updated api.UpdateServiceOutput
	var revisions api.DescribeServiceRevisionsOutput
	decode("owned-create-cluster", &cluster)
	decode("owned-create-zero-service", &created)
	decode("owned-register-definition", &definition)
	decode("owned-update-monitoring", &updated)
	decode("immutable-monitoring", &revisions)
	var monitoring api.UpdateServiceInput
	if err := json.Unmarshal(rows["owned-update-monitoring"].Input, &monitoring); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var db *sql.DB
			stores := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "revisions.db")
			openStorage := func() {
				t.Helper()
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					stores, err = backends.New(t.Context(), db)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			openStorage()
			key := domain.ServiceKey{ClusterKey: domain.ClusterKey{Scope: domain.Scope{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"}, Name: string(*cluster.Cluster.ClusterName)}, ServiceName: "zero"}
			record := domain.ServiceRecord{Key: key, Data: api.CloneService(*created.Service), Deployments: []domain.ServiceDeployment{{Data: api.CloneDeployment(created.Service.Deployments[0]), Definition: api.CloneTaskDefinition(*definition.TaskDefinition)}}}
			if err := stores.ECS.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutCluster(domain.ClusterRecord{Key: key.ClusterKey, Data: *cluster.Cluster}); err != nil {
					return err
				}
				return tx.PutService(record)
			}); err != nil {
				t.Fatal(err)
			}
			var cloud *stackd.Stack
			var server *httptest.Server
			var client *sdk.Client
			open := func() {
				t.Helper()
				var err error
				cloud, err = stackd.New(stackd.Config{AccountID: key.AccountID, Storage: stores})
				if err != nil {
					t.Fatal(err)
				}
				server = httptest.NewServer(cloud)
				client = sdk.New(sdk.Options{Region: key.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			}
			close := func() {
				if server != nil {
					server.Close()
					server = nil
				}
				if cloud != nil {
					_ = cloud.Close()
					cloud = nil
				}
				if db != nil {
					_ = db.Close()
					db = nil
				}
			}
			t.Cleanup(close)
			open()
			replay := func(t *testing.T, label string) {
				t.Helper()
				row := rows[label]
				out, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
				if row.Code != "Success" {
					var apiErr smithy.APIError
					if !errors.As(err, &apiErr) || apiErr.ErrorCode() != row.Code {
						t.Fatalf("%s: err=%v want %s", label, err, row.Code)
					}
					return
				}
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				actual := out.(*sdk.DescribeServiceRevisionsOutput)
				var expected sdk.DescribeServiceRevisionsOutput
				if err := json.Unmarshal(row.Output, &expected); err != nil {
					t.Fatal(err)
				}
				if len(actual.Failures) != len(expected.Failures) {
					t.Fatalf("%s failures=%+v want %+v", label, actual.Failures, expected.Failures)
				}
				for i := range expected.Failures {
					if aws.ToString(actual.Failures[i].Arn) != aws.ToString(expected.Failures[i].Arn) || aws.ToString(actual.Failures[i].Reason) != aws.ToString(expected.Failures[i].Reason) {
						t.Fatalf("%s failures=%+v want %+v", label, actual.Failures, expected.Failures)
					}
				}
				if len(actual.ServiceRevisions) != len(expected.ServiceRevisions) {
					t.Fatalf("%s revisions=%+v want %+v", label, actual.ServiceRevisions, expected.ServiceRevisions)
				}
				for i := range expected.ServiceRevisions {
					if aws.ToString(actual.ServiceRevisions[i].ServiceRevisionArn) != aws.ToString(expected.ServiceRevisions[i].ServiceRevisionArn) {
						t.Fatalf("%s returned a different revision", label)
					}
				}
			}
			for _, label := range []string{"empty-batch", "malformed-identifier", "over-limit", "active-revision", "active-duplicate", "missing-revision", "mixed-found-missing", "missing-service", "foreign-region", "foreign-account", "malformed-revision-number", "duplicate-missing", "mixed-service-batch"} {
				t.Run(label, func(t *testing.T) { replay(t, label) })
			}
			// Move the original snapshot to the durable archive and rewrite the
			// active deployment rows. Their foreign-key replacement must not erase
			// revision history or let the current monitoring overwrite its past.
			old := revisions.ServiceRevisions[0]
			oldKey := domain.ServiceRevisionKey{ServiceKey: key, ID: strings.TrimPrefix(string(*record.Deployments[0].Data.Id), "ecs-svc/")}
			record.Data = api.CloneService(*updated.Service)
			record.Deployments = []domain.ServiceDeployment{{Data: api.CloneDeployment(updated.Service.Deployments[0]), Definition: api.CloneTaskDefinition(*definition.TaskDefinition), Monitoring: monitoring.Monitoring}}
			if err := stores.ECS.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutServiceRevision(domain.ServiceRevisionRecord{Key: oldKey, Data: old}); err != nil {
					return err
				}
				return tx.PutService(record)
			}); err != nil {
				t.Fatal(err)
			}
			close()
			openStorage()
			open()
			replay(t, "immutable-monitoring")
			out, err := client.DescribeServiceRevisions(t.Context(), &sdk.DescribeServiceRevisionsInput{ServiceRevisionArns: []string{oldKey.ARN(), string(*revisions.ServiceRevisions[1].ServiceRevisionArn)}})
			if err != nil {
				t.Fatal(err)
			}
			if out.ServiceRevisions[0].Monitoring != nil || out.ServiceRevisions[1].Monitoring == nil || aws.ToInt32(out.ServiceRevisions[1].Monitoring.MetricConfigurations[0].ResolutionSeconds) != 20 {
				t.Fatalf("monitoring history changed across active-row replacement/reopen: %+v", out.ServiceRevisions)
			}
		})
	}
}
