package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/resourcegroups"
	"stackd/internal/services/s3"
	"stackd/internal/services/ssm"
	"stackd/storage"
	"stackd/storage/sqlite"
	sqlcfn "stackd/storage/sqlite/cloudformation"
	sqls3 "stackd/storage/sqlite/s3"
	sqlsqs "stackd/storage/sqlite/sqs"
	sqlssm "stackd/storage/sqlite/ssm"
)

func TestApplicationResourceIncarnationFences(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			fixed := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
			backends := storage.NewMemory()
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "owners.sqlite")
			open := func() {
				t.Helper()
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				current := db
				backends = &storage.Backends{
					Read: func(ctx context.Context, fn func(context.Context) error) error {
						return sqlite.Transact(ctx, current, true, func(ctx context.Context, _ *sql.Tx) error { return fn(ctx) })
					},
					S3: sqls3.New(db), SQS: sqlsqs.New(db), SSM: sqlssm.New(db), CloudFormation: sqlcfn.New(db),
				}
			}
			if backend == "sqlite" {
				open()
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			var bucketOwner *s3.Service
			var parameterOwner *ssm.Service
			var commands StepFunctionsCommands
			var adapter AppRegistryResources
			assemble := func() {
				bucketOwner = s3.New(s3.Config{Repository: backends.S3, Clock: fixed})
				parameterOwner = ssm.New(ssm.Config{Repository: backends.SSM, Clock: fixed})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"s3": bucketOwner, "ssm": parameterOwner})
				adapter = AppRegistryResources{Backends: backends, Tagging: &ResourceTaggingResources{Backends: backends, Commands: commands}}
			}
			assemble()
			t.Cleanup(func() { _ = bucketOwner.Close(); _ = parameterOwner.Close() })
			call := func(service, operation, input string) {
				t.Helper()
				if _, rejected := commands.Call(ctx, service, operation, json.RawMessage(input)); rejected != nil {
					t.Fatalf("%s.%s: %v", service, operation, rejected)
				}
			}
			resolve := func(arn string) resourcegroups.ApplicationResource {
				t.Helper()
				row, found, err := adapter.Resolve(ctx, arn)
				if err != nil || !found || row.Incarnation == "" {
					t.Fatalf("resolve %s: %#v, %v, %v", arn, row, found, err)
				}
				return row
			}
			call("s3", "CreateBucket", `{"Bucket":"application-owner-fence"}`)
			call("ssm", "PutParameter", `{"Name":"/application/owner-fence","Type":"String","Value":"first"}`)
			bucket := resolve("arn:aws:s3:::application-owner-fence")
			parameter := resolve("arn:aws:ssm:us-east-1:123456789012:parameter/application/owner-fence")
			for _, row := range []resourcegroups.ApplicationResource{bucket, parameter} {
				if err := adapter.Tag(ctx, row, map[string]string{"keep": "owner", "awsApplication": "old"}); err != nil {
					t.Fatal(err)
				}
			}
			// Neither S3's legacy idempotent create nor an SSM value version is creation.
			call("s3", "CreateBucket", `{"Bucket":"application-owner-fence"}`)
			call("ssm", "PutParameter", `{"Name":"/application/owner-fence","Type":"String","Value":"second","Overwrite":true}`)
			for _, row := range []resourcegroups.ApplicationResource{bucket, parameter} {
				current := resolve(row.ARN)
				if current.Incarnation != row.Incarnation || current.Tags["keep"] != "owner" {
					t.Fatalf("metadata update changed identity/tags: %#v", current)
				}
			}
			if backend == "sqlite" {
				_ = bucketOwner.Close()
				_ = parameterOwner.Close()
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				open()
				assemble()
				for _, row := range []resourcegroups.ApplicationResource{bucket, parameter} {
					if got := resolve(row.ARN); got.Incarnation != row.Incarnation || got.Tags["awsApplication"] != "old" {
						t.Fatalf("restart lost identity or tags: %#v", got)
					}
				}
			}
			// A nested native tag must roll back with the cross-owner transaction.
			rollback := errors.New("roll back membership")
			err := backends.S3.Update(ctx, func(tx s3.Transaction) error {
				if err := adapter.Tag(tx.Context(), parameter, map[string]string{"awsApplication": "rolled-back"}); err != nil {
					return err
				}
				return rollback
			})
			if !errors.Is(err, rollback) || resolve(parameter.ARN).Tags["awsApplication"] != "old" {
				t.Fatalf("membership transaction leaked tags: %v", err)
			}
			call("s3", "DeleteBucket", `{"Bucket":"application-owner-fence"}`)
			call("ssm", "DeleteParameter", `{"Name":"/application/owner-fence"}`)
			call("s3", "CreateBucket", `{"Bucket":"application-owner-fence"}`)
			call("ssm", "PutParameter", `{"Name":"/application/owner-fence","Type":"String","Value":"replacement"}`)
			for _, old := range []resourcegroups.ApplicationResource{bucket, parameter} {
				current := resolve(old.ARN)
				if current.Incarnation == old.Incarnation {
					t.Fatalf("same-time recreation reused identity: %#v", current)
				}
				if err := adapter.Tag(ctx, current, map[string]string{"keep": "replacement", "awsApplication": "new"}); err != nil {
					t.Fatal(err)
				}
				for _, mutate := range []func() error{
					func() error { return adapter.Tag(ctx, old, map[string]string{"awsApplication": "stale"}) },
					func() error { return adapter.Untag(ctx, old, []string{"awsApplication"}) },
				} {
					var rejected *awswire.Error
					if err := mutate(); !errors.As(err, &rejected) || rejected.Code != "ResourceNotFoundException" {
						t.Fatalf("stale mutation = %v", err)
					}
				}
				got := resolve(old.ARN)
				if got.Tags["awsApplication"] != "new" || got.Tags["keep"] != "replacement" {
					t.Fatalf("stale mutation reached replacement: %#v", got)
				}
				if err := adapter.Untag(ctx, current, []string{"awsApplication"}); err != nil {
					t.Fatal(err)
				}
				got = resolve(old.ARN)
				if _, exists := got.Tags["awsApplication"]; exists || got.Tags["keep"] != "replacement" {
					t.Fatalf("native untag lost unrelated tags: %#v", got)
				}
			}
		})
	}
}
