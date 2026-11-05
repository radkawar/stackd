package s3tables_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awsctx"
	"stackd/internal/services/glue/icebergmeta"
	owner "stackd/internal/services/s3tables"
	"stackd/storage/sqlite"
	tablesql "stackd/storage/sqlite/s3tables"
)

func TestSQLiteMetadataAuthorityAndReclamationSurviveReopen(t *testing.T) {
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	path := filepath.Join(t.TempDir(), "tables.sqlite")
	source := clock.NewManual(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	db, e := sqlite.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	service := owner.New(owner.Config{Repository: tablesql.New(db), Objects: sqliteObjects(t, ctx, db), Clock: source})
	bucket, rejected := service.CreateTableBucket(ctx, &api.CreateTableBucketInput{Name: new(api.TableBucketName("durable-tables"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected = service.CreateNamespace(ctx, &api.CreateNamespaceInput{TableBucketARN: bucket.Arn, Namespace: api.NamespaceList{"analytics"}}); rejected != nil {
		t.Fatal(rejected)
	}
	created, rejected := service.CreateTable(ctx, &api.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), Format: new(api.OpenTableFormatICEBERG), Metadata: &api.TableMetadata{Iceberg: &api.IcebergMetadata{Schema: &api.IcebergSchema{Fields: api.SchemaFieldList{{Name: new(api.String("id")), Type: new(api.String("long"))}}}}}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	table, rejected := service.GetTable(ctx, &api.GetTableInput{TableArn: created.TableARN})
	if rejected != nil {
		t.Fatal(rejected)
	}
	initial, rejected := service.TableColumns(ctx, string(*bucket.Arn), "analytics", "events")
	if rejected != nil || len(initial) != 1 || initial[0].Name != "id" || initial[0].Type != "bigint" {
		t.Fatalf("initial schema was not accepted atomically: %#v %v", initial, rejected)
	}
	data, e := service.Read(ctx, string(*table.MetadataLocation))
	if e != nil {
		t.Fatal(e)
	}
	initialWarehouse := string(*table.WarehouseLocation)
	initialKey := strings.TrimPrefix(string(*table.MetadataLocation), initialWarehouse+"/")
	encryptedEnvelope(t, objectEnvelope(t, db, initialWarehouse, initialKey), data)
	var metadata icebergmeta.Metadata
	if e = json.Unmarshal(data, &metadata); e != nil {
		t.Fatal(e)
	}
	metadata.Schemas = append(metadata.Schemas, icebergmeta.Schema{SchemaID: 1, Type: "struct", Fields: []icebergmeta.Field{{ID: 1, Name: "id", Type: json.RawMessage(`"long"`)}, {ID: 2, Name: "label", Type: json.RawMessage(`"string"`), Doc: "durable label"}}})
	metadata.CurrentSchemaID = 1
	metadata.LastColumnID = 2
	data, e = json.Marshal(metadata)
	if e != nil {
		t.Fatal(e)
	}
	location := string(*table.WarehouseLocation) + "/staged/current-schema"
	if e = service.Write(ctx, location, data); e != nil {
		t.Fatal(e)
	}
	committed, rejected := service.UpdateTableMetadataLocation(ctx, &api.UpdateTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: created.VersionToken, MetadataLocation: new(api.MetadataLocation(location))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = sqlite.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	service = owner.New(owner.Config{Repository: tablesql.New(db), Objects: sqliteObjects(t, ctx, db), Clock: source})
	loaded, rejected := service.GetTable(ctx, &api.GetTableInput{TableArn: created.TableARN})
	if rejected != nil || *loaded.VersionToken != *committed.VersionToken || string(*loaded.MetadataLocation) != location {
		t.Fatalf("reopened authority lost committed state: %v", rejected)
	}
	if _, rejected = service.UpdateTableMetadataLocation(ctx, &api.UpdateTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: created.VersionToken, MetadataLocation: new(api.MetadataLocation(location))}); rejected == nil || rejected.Code != "ConflictException" {
		t.Fatalf("reopened CAS accepted stale writer: %v", rejected)
	}
	columns, rejected := service.TableColumns(ctx, string(*bucket.Arn), "analytics", "events")
	if rejected != nil || len(columns) != 2 || columns[0].Name != "id" || columns[0].Type != "bigint" || columns[1].Name != "label" || columns[1].Type != "string" || columns[1].Comment != "durable label" {
		t.Fatalf("reopened or stale-CAS schema lost accepted evolution: %#v %v", columns, rejected)
	}
	nextLocation := string(*table.WarehouseLocation) + "/staged/next-schema"
	if e = service.Write(ctx, nextLocation, data); e != nil {
		t.Fatal(e)
	}
	next, rejected := service.UpdateTableMetadataLocation(ctx, &api.UpdateTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: loaded.VersionToken, MetadataLocation: new(api.MetadataLocation(nextLocation))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	loaded.VersionToken = next.VersionToken
	if e = service.Write(ctx, location, []byte(`{"schemas":[]}`)); e == nil {
		t.Fatal("reopened historical metadata key lost durable immutability")
	}
	if _, rejected = service.DeleteTable(ctx, &api.DeleteTableInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: loaded.VersionToken}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected = service.DeleteNamespace(ctx, &api.DeleteNamespaceInput{TableBucketARN: bucket.Arn, Namespace: new(api.NamespaceName("analytics"))}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected = service.DeleteTableBucket(ctx, &api.DeleteTableBucketInput{TableBucketARN: bucket.Arn}); rejected != nil {
		t.Fatal(rejected)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = sqlite.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	objects := sqliteObjects(t, ctx, db)
	service = owner.New(owner.Config{Repository: tablesql.New(db), Objects: objects, Clock: source})
	if _, e = service.Read(ctx, location); !errors.Is(e, owner.ErrNotFound) {
		t.Fatalf("deleted data readable after reopen: %v", e)
	}
	job, ok, e := service.Next(ctx)
	if e != nil || !ok {
		t.Fatalf("cleanup intent lost on reopen: %v", e)
	}
	if e = service.Run(ctx, job); e != nil {
		t.Fatal(e)
	}
	remaining, e := objects.List(ctx, string(*table.WarehouseLocation), "")
	if e != nil || len(remaining) != 0 {
		t.Fatalf("durable cleanup retained bytes: %v %v", remaining, e)
	}
	if _, ok, e = service.Next(ctx); e != nil || ok {
		t.Fatalf("cleanup did not finish: %v %v", ok, e)
	}
}
