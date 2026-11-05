package s3tables_test

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"path/filepath"
	"sync"
	"testing"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awsctx"
	owner "stackd/internal/services/s3tables"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqljournal "stackd/storage/sqlite/journal"
	tablesql "stackd/storage/sqlite/s3tables"
)

type tagEventFailure struct{ err error }

func (f tagEventFailure) Record(context.Context, journal.Envelope, journal.APICallCompleted) error {
	return f.err
}

func TestResourceTagsIsolationTransactionsAndReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			scope := owner.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
			domain := memory.NewDomain()
			var repository owner.Repository = owner.NewMemoryRepository(domain)
			var history journal.Storage = journal.NewMemory(domain)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "tags.sqlite")
			openSQLite := func() {
				t.Helper()
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository, history = tablesql.New(db), sqljournal.New(db)
			}
			if backend == "sqlite" {
				openSQLite()
			}
			t.Cleanup(func() {
				if db != nil {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				}
			})
			service := owner.New(owner.Config{Repository: repository, Recorder: apievents.New(history)})
			bucket, rejected := service.CreateTableBucket(ctx, &api.CreateTableBucketInput{Name: new(api.TableBucketName("durable-tags")), Tags: api.Tags{"project": "bucket"}})
			if rejected != nil {
				t.Fatal(rejected)
			}
			if _, rejected = service.CreateNamespace(ctx, &api.CreateNamespaceInput{TableBucketARN: bucket.Arn, Namespace: api.NamespaceList{"analytics"}}); rejected != nil {
				t.Fatal(rejected)
			}
			table, rejected := service.CreateTable(ctx, &api.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), Format: new(api.OpenTableFormatICEBERG), Tags: api.Tags{"project": "table"}})
			if rejected != nil {
				t.Fatal(rejected)
			}
			arn := string(*table.TableARN)
			assertTags := func(expected owner.Tags) {
				t.Helper()
				if err := repository.View(ctx, func(r owner.Reader) error {
					got, err := r.ResourceTags(scope, arn)
					if err != nil {
						return err
					}
					if !maps.Equal(got, expected) {
						t.Fatalf("tag state = %#v, want %#v", got, expected)
					}
					got["local"] = "must not escape reader"
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			input := owner.Tags{"project": "isolated"}
			if err := repository.Update(ctx, func(tx owner.Transaction) error { return tx.PutResourceTags(scope, arn, input) }); err != nil {
				t.Fatal(err)
			}
			input["project"] = "must not escape writer"
			assertTags(owner.Tags{"project": "isolated"})
			assertTags(owner.Tags{"project": "isolated"})
			rollback := errors.New("outer tag mutation rolls back")
			err := repository.Update(ctx, func(tx owner.Transaction) error {
				if _, rejected := service.TagResource(tx.Context(), &api.TagResourceInput{ResourceArn: new(api.ResourceArn(arn)), Tags: api.Tags{"project": "staged", "added": "staged"}}); rejected != nil {
					return rejected
				}
				if _, rejected := service.UntagResource(tx.Context(), &api.UntagResourceInput{ResourceArn: new(api.ResourceArn(arn)), TagKeys: api.TagKeyList{"project"}}); rejected != nil {
					return rejected
				}
				tags, err := tx.ResourceTags(scope, arn)
				if err != nil {
					return err
				}
				if !maps.Equal(tags, owner.Tags{"added": "staged"}) {
					t.Fatalf("nested command state unavailable: %#v", tags)
				}
				if _, rejected := service.CreateTableBucket(tx.Context(), &api.CreateTableBucketInput{Name: new(api.TableBucketName("rolled-back-tags")), Tags: api.Tags{"project": "rollback"}}); rejected != nil {
					return rejected
				}
				if _, rejected := service.CreateTable(tx.Context(), &api.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("rolled_back")), Format: new(api.OpenTableFormatICEBERG), Tags: api.Tags{"project": "rollback"}}); rejected != nil {
					return rejected
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			assertTags(owner.Tags{"project": "isolated"})
			if _, rejected = service.GetTable(ctx, &api.GetTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("rolled_back"))}); rejected == nil || rejected.Code != "NotFoundException" {
				t.Fatalf("tagged table escaped outer rollback: %v", rejected)
			}
			if _, rejected = service.GetTableBucket(ctx, &api.GetTableBucketInput{TableBucketARN: new(api.TableBucketARN("arn:aws:s3tables:us-east-1:123456789012:bucket/rolled-back-tags"))}); rejected == nil || rejected.Code != "NotFoundException" {
				t.Fatalf("tagged bucket escaped outer rollback: %v", rejected)
			}
			assertEventCounts := func(tag, untag int) {
				t.Helper()
				events, err := history.Read(ctx, 0, 1000)
				if err != nil {
					t.Fatal(err)
				}
				counts := map[string]int{}
				for _, event := range events {
					if event.APICallCompleted != nil && event.APICallCompleted.ErrorCode == "" {
						counts[event.APICallCompleted.EventName]++
					}
				}
				if counts["TagResource"] != tag || counts["UntagResource"] != untag || counts["CreateTable"] != 1 || counts["CreateTableBucket"] != 1 {
					t.Fatalf("accepted tag events = %#v, expected %d tags and %d untags and one initial bucket/table create", counts, tag, untag)
				}
			}
			assertEventCounts(0, 0)
			failed := owner.New(owner.Config{Repository: repository, Recorder: tagEventFailure{errors.New("event sink unavailable")}})
			if _, rejected = failed.TagResource(ctx, &api.TagResourceInput{ResourceArn: new(api.ResourceArn(arn)), Tags: api.Tags{"project": "must not commit without event"}}); rejected == nil {
				t.Fatal("accepted mutation without its event")
			}
			assertTags(owner.Tags{"project": "isolated"})
			if _, rejected = failed.CreateTable(ctx, &api.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("failed_tagged_create")), Format: new(api.OpenTableFormatICEBERG), Tags: api.Tags{"project": "must not commit without event"}}); rejected == nil {
				t.Fatal("accepted tagged table without its event")
			}
			if _, rejected = service.GetTable(ctx, &api.GetTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("failed_tagged_create"))}); rejected == nil || rejected.Code != "NotFoundException" {
				t.Fatalf("tagged table survived journal failure: %v", rejected)
			}
			if _, rejected = service.TagResource(ctx, &api.TagResourceInput{ResourceArn: new(api.ResourceArn(arn)), Tags: api.Tags{"project": "committed", "remove": "yes"}}); rejected != nil {
				t.Fatal(rejected)
			}
			if _, rejected = service.UntagResource(ctx, &api.UntagResourceInput{ResourceArn: new(api.ResourceArn(arn)), TagKeys: api.TagKeyList{"remove"}}); rejected != nil {
				t.Fatal(rejected)
			}
			assertEventCounts(1, 1)
			for _, foreign := range []owner.Scope{{Partition: "aws-cn", AccountID: scope.AccountID, Region: scope.Region}, {Partition: scope.Partition, AccountID: "999999999999", Region: scope.Region}, {Partition: scope.Partition, AccountID: scope.AccountID, Region: "eu-west-1"}} {
				if err := repository.View(ctx, func(r owner.Reader) error { _, err := r.ResourceTags(foreign, arn); return err }); !errors.Is(err, owner.ErrNotFound) {
					t.Fatalf("foreign tag read: %v", err)
				}
				if err := repository.Update(ctx, func(tx owner.Transaction) error {
					return tx.PutResourceTags(foreign, arn, owner.Tags{"foreign": "denied"})
				}); !errors.Is(err, owner.ErrNotFound) {
					t.Fatalf("foreign tag write: %v", err)
				}
			}
			if backend == "sqlite" {
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				db = nil
				openSQLite()
			}
			service = owner.New(owner.Config{Repository: repository, Recorder: apievents.New(history)})
			assertTags(owner.Tags{"project": "committed"})
			assertEventCounts(1, 1)
			// A deleted table's private reclamation row does not retain public tags.
			if _, rejected = service.DeleteTable(ctx, &api.DeleteTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: table.VersionToken}); rejected != nil {
				t.Fatal(rejected)
			}
			if err := repository.View(ctx, func(r owner.Reader) error { _, err := r.ResourceTags(scope, arn); return err }); !errors.Is(err, owner.ErrNotFound) {
				t.Fatalf("deleted tag read: %v", err)
			}
			if err := repository.Update(ctx, func(tx owner.Transaction) error {
				return tx.PutResourceTags(scope, arn, owner.Tags{"deleted": "denied"})
			}); !errors.Is(err, owner.ErrNotFound) {
				t.Fatalf("deleted tag write: %v", err)
			}
		})
	}
}

func TestMemoryTagConcurrentMergeAndViewCopies(t *testing.T) {
	f := owner.NewMemoryRepository(nil)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	service := owner.New(owner.Config{Repository: f})
	bucket, rejected := service.CreateTableBucket(ctx, &api.CreateTableBucketInput{Name: new(api.TableBucketName("concurrent-tags"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	var workers sync.WaitGroup
	errors := make(chan error, 32)
	for i := range 32 {
		workers.Go(func() {
			key := api.TagKey("key" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
			_, rejected := service.TagResource(ctx, &api.TagResourceInput{ResourceArn: new(api.ResourceArn(*bucket.Arn)), Tags: api.Tags{key: "concurrent"}})
			if rejected != nil {
				errors <- rejected
			}
		})
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	tags, rejected := service.ListTagsForResource(ctx, &api.ListTagsForResourceInput{ResourceArn: new(api.ResourceArn(*bucket.Arn))})
	if rejected != nil || len(tags.Tags) != 32 {
		t.Fatalf("atomic merges lost tags: %#v %v", tags, rejected)
	}
}
