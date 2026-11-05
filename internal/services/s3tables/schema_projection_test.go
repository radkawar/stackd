package s3tables_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awsctx"
	"stackd/internal/services/glue/icebergmeta"
	"stackd/internal/services/iam"
	owner "stackd/internal/services/s3tables"
	"stackd/journal"
)

func projectionColumns(t *testing.T, f *fixture, name string, want []owner.Column) {
	t.Helper()
	got, rejected := f.service.TableColumns(f.ctx, string(*f.bucket), "analytics", name)
	if rejected != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("accepted schema = %#v, want %#v: %v", got, want, rejected)
	}
}

func TestSchemaProjectionInitialEvolutionGzipAndStaleCAS(t *testing.T) {
	f := newFixture(t, nil)
	history := journal.NewMemory(f.domain)
	f.service = owner.New(owner.Config{Repository: f.repository, Objects: f.objects, Recorder: apievents.New(history)})
	table := f.create(t, "events")
	initial := []owner.Column{{Name: "id", Type: "bigint"}}
	projectionColumns(t, f, "events", initial)
	data, err := f.service.Read(f.ctx, string(*table.MetadataLocation))
	if err != nil {
		t.Fatal(err)
	}
	var metadata icebergmeta.Metadata
	if err = json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata.Schemas = append(metadata.Schemas, icebergmeta.Schema{SchemaID: 1, Type: "struct", Fields: []icebergmeta.Field{
		{ID: 1, Name: "id", Type: json.RawMessage(`"long"`), Required: true},
		{ID: 2, Name: "attributes", Doc: "event attributes", Type: json.RawMessage(`{"type":"map","key-id":3,"key":"string","value-id":4,"value":"string","value-required":false}`)},
	}})
	metadata.CurrentSchemaID = 1
	metadata.LastColumnID = 4
	evolved, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(evolved); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	location := string(*table.WarehouseLocation) + "/staged/evolved-schema"
	if err = f.service.Write(f.ctx, location, compressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	update := &api.UpdateTableMetadataLocationInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: table.VersionToken, MetadataLocation: new(api.MetadataLocation(location))}
	prepared, rejected := f.service.PrepareTableMetadataUpdate(f.ctx, update)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if err = f.service.Write(f.ctx, location, data); err == nil {
		t.Fatal("prepared arbitrary metadata key remained mutable before CAS")
	}
	request := httptest.NewRequest(http.MethodDelete, "/"+strings.TrimPrefix(location, "s3://"), nil).WithContext(f.ctx)
	response := httptest.NewRecorder()
	if !f.service.HandleData(response, request) || response.Code != http.StatusNotImplemented {
		t.Fatalf("unsupported managed object deletion was admitted: %d", response.Code)
	}
	losingLocation := string(*table.WarehouseLocation) + "/staged/losing-schema"
	if err = f.service.Write(f.ctx, losingLocation, data); err != nil {
		t.Fatal(err)
	}
	loser := *update
	loser.MetadataLocation = new(api.MetadataLocation(losingLocation))
	losingPrepared, rejected := f.service.PrepareTableMetadataUpdate(f.ctx, &loser)
	if rejected != nil {
		t.Fatal(rejected)
	}
	want := []owner.Column{{Name: "id", Type: "bigint"}, {Name: "attributes", Type: "map<string,string>", Comment: "event attributes"}}
	rollback := errors.New("outer Glue command rolls back")
	err = f.repository.Update(f.ctx, func(tx owner.Transaction) error {
		if _, rejected := f.service.PublishTableMetadataUpdate(tx.Context(), update, prepared); rejected != nil {
			return rejected
		}
		columns, rejected := f.service.TableColumns(tx.Context(), string(*f.bucket), "analytics", "events")
		if rejected != nil || !reflect.DeepEqual(columns, want) {
			t.Fatalf("transaction did not observe accepted schema: %#v %v", columns, rejected)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	projectionColumns(t, f, "events", initial)
	unchanged, rejected := f.service.GetTableMetadataLocation(f.ctx, &api.GetTableMetadataLocationInput{TableBucketARN: f.bucket, Namespace: update.Namespace, Name: update.Name})
	if rejected != nil || *unchanged.MetadataLocation != *table.MetadataLocation || *unchanged.VersionToken != *table.VersionToken {
		t.Fatalf("rolled-back pointer/token escaped with schema: %v", rejected)
	}
	committed, rejected := f.service.PublishTableMetadataUpdate(f.ctx, update, prepared)
	if rejected != nil {
		t.Fatal(rejected)
	}
	projectionColumns(t, f, "events", want)
	if _, rejected = f.service.PublishTableMetadataUpdate(f.ctx, &loser, losingPrepared); rejected == nil || rejected.Code != "ConflictException" {
		t.Fatalf("prepared stale CAS accepted: %v", rejected)
	}
	projectionColumns(t, f, "events", want)
	current, rejected := f.service.GetTableMetadataLocation(f.ctx, &api.GetTableMetadataLocationInput{TableBucketARN: f.bucket, Namespace: update.Namespace, Name: update.Name})
	if rejected != nil || *current.MetadataLocation != *committed.MetadataLocation || *current.VersionToken != *committed.VersionToken {
		t.Fatalf("stale writer changed current authority: %v", rejected)
	}
	events, err := history.Read(f.ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, event := range events {
		if event.APICallCompleted != nil && event.APICallCompleted.EventName == "UpdateTableMetadataLocation" && event.APICallCompleted.ErrorCode == "" {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("schema/pointer journal escaped outer rollback or stale CAS: %d accepted updates", accepted)
	}
}

func TestMetadataImmutabilityProtectsAcceptedProjection(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "immutable")
	location := string(*table.MetadataLocation)
	data, err := f.service.Read(f.ctx, location)
	if err != nil {
		t.Fatal(err)
	}
	multipartCode(t, f.service.Write(f.ctx, location, data), "PreconditionFailed")
	multipartCode(t, f.service.Write(f.ctx, location, []byte(`{"schemas":[]}`)), "PreconditionFailed")
	path := "/" + strings.TrimPrefix(location, "s3://")
	for _, operation := range []struct {
		method string
		status int
	}{{http.MethodPut, http.StatusPreconditionFailed}, {http.MethodDelete, http.StatusNotImplemented}} {
		request := httptest.NewRequest(operation.method, path, strings.NewReader(`{"schemas":[]}`)).WithContext(f.ctx)
		response := httptest.NewRecorder()
		if !f.service.HandleData(response, request) || response.Code != operation.status {
			t.Fatalf("metadata %s bypassed owner operation policy: %d %s", operation.method, response.Code, response.Body.String())
		}
	}
	remaining, err := f.service.Read(f.ctx, location)
	if err != nil || !bytes.Equal(remaining, data) {
		t.Fatalf("accepted metadata bytes changed: %v", err)
	}
	projectionColumns(t, f, "immutable", []owner.Column{{Name: "id", Type: "bigint"}})
	dataLocation := string(*table.WarehouseLocation) + "/data/reusable.parquet"
	if err = f.service.Write(f.ctx, dataLocation, []byte("first")); err != nil {
		t.Fatal(err)
	}
	multipartCode(t, f.service.Write(f.ctx, dataLocation, []byte("second")), "PreconditionFailed")
	retained, err := f.service.Read(f.ctx, dataLocation)
	if err != nil || string(retained) != "first" {
		t.Fatalf("write-once data changed: %q %v", retained, err)
	}
}

func TestPreparedSchemaPublicationRechecksCurrentIAM(t *testing.T) {
	identities := iam.NewMemoryRepository(nil)
	identityService := iam.NewWithConfig(iam.Config{Repository: identities})
	f := newFixture(t, authorization.NewWithClock(identityService, nil, nil))
	table := f.create(t, "events")
	user := iam.User{UserName: "publisher", UserId: "AIDASCHEMAPUBLISHER", Arn: "arn:aws:iam::123456789012:user/publisher", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	setAllowed := func(allowed bool) {
		t.Helper()
		policy := `{"Statement":[]}`
		if allowed {
			policy = `{"Statement":[{"Effect":"Allow","Action":["s3tables:CreateTable","s3tables:PutTableData","s3tables:UpdateTableMetadataLocation"],"Resource":"*"}]}`
		}
		user.IdentityPolicies.Inline["publish"] = policy
		if err := identities.Update(f.ctx, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	setAllowed(true)
	caller := awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
	data, err := f.service.Read(f.ctx, string(*table.MetadataLocation))
	if err != nil {
		t.Fatal(err)
	}
	location := string(*table.WarehouseLocation) + "/metadata/00001-prepared.metadata.json"
	if err = f.service.Write(f.ctx, location, data); err != nil {
		t.Fatal(err)
	}
	update := &api.UpdateTableMetadataLocationInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: table.VersionToken, MetadataLocation: new(api.MetadataLocation(location))}
	preparedUpdate, rejected := f.service.PrepareTableMetadataUpdate(caller, update)
	if rejected != nil {
		t.Fatal(rejected)
	}
	create := &api.CreateTableInput{TableBucketARN: f.bucket, Namespace: update.Namespace, Name: new(api.TableName("new_table")), Format: new(api.OpenTableFormatICEBERG), Metadata: &api.TableMetadata{Iceberg: &api.IcebergMetadata{Schema: &api.IcebergSchema{Fields: api.SchemaFieldList{{Name: new(api.String("id")), Type: new(api.String("long"))}}}}}}
	preparedCreate, rejected := f.service.PrepareTableCreate(caller, create)
	if rejected != nil {
		t.Fatal(rejected)
	}
	setAllowed(false)
	if _, rejected = f.service.PublishTableMetadataUpdate(caller, update, preparedUpdate); rejected == nil || rejected.Code != "ForbiddenException" {
		t.Fatalf("prepared update retained revoked IAM: %v", rejected)
	}
	if _, rejected = f.service.PublishTableCreate(caller, create, preparedCreate); rejected == nil || rejected.Code != "ForbiddenException" {
		t.Fatalf("prepared creation retained revoked IAM: %v", rejected)
	}
	if err = f.service.DiscardTableCreate(caller, preparedCreate); err != nil {
		t.Fatal(err)
	}
	projectionColumns(t, f, "events", []owner.Column{{Name: "id", Type: "bigint"}})
	current, rejected := f.service.GetTable(f.ctx, &api.GetTableInput{TableArn: table.TableARN})
	if rejected != nil || *current.MetadataLocation != *table.MetadataLocation || *current.VersionToken != *table.VersionToken {
		t.Fatalf("revoked publication changed current pointer/token: %v", rejected)
	}
	if _, rejected = f.service.GetTable(f.ctx, &api.GetTableInput{TableBucketARN: create.TableBucketARN, Namespace: create.Namespace, Name: create.Name}); rejected == nil || rejected.Code != "NotFoundException" {
		t.Fatalf("revoked initial schema became visible: %v", rejected)
	}
}

func TestPreparedInitialSchemaJoinsOuterTransaction(t *testing.T) {
	f := newFixture(t, nil)
	history := journal.NewMemory(f.domain)
	f.service = owner.New(owner.Config{Repository: f.repository, Objects: f.objects, Recorder: apievents.New(history)})
	input := &api.CreateTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("atomic")), Format: new(api.OpenTableFormatICEBERG), Metadata: &api.TableMetadata{Iceberg: &api.IcebergMetadata{Schema: &api.IcebergSchema{Fields: api.SchemaFieldList{{Name: new(api.String("id")), Type: new(api.String("long"))}}}}}}
	prepared, rejected := f.service.PrepareTableCreate(f.ctx, input)
	if rejected != nil {
		t.Fatal(rejected)
	}
	rollback := errors.New("outer publication rollback")
	var warehouse string
	err := f.repository.Update(f.ctx, func(tx owner.Transaction) error {
		created, rejected := f.service.PublishTableCreate(tx.Context(), input, prepared)
		if rejected != nil {
			return rejected
		}
		table, rejected := f.service.GetTable(tx.Context(), &api.GetTableInput{TableArn: created.TableARN})
		if rejected != nil {
			return rejected
		}
		warehouse = string(*table.WarehouseLocation)
		columns, rejected := f.service.TableColumns(tx.Context(), string(*f.bucket), "analytics", "atomic")
		if rejected != nil || len(columns) != 1 || columns[0].Type != "bigint" {
			t.Fatalf("initial accepted pointer lacked typed schema: %#v %v", columns, rejected)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if _, rejected = f.service.TableColumns(f.ctx, string(*f.bucket), "analytics", "atomic"); rejected == nil || rejected.Code != "NotFoundException" {
		t.Fatalf("initial schema escaped outer rollback: %v", rejected)
	}
	if err = f.service.DiscardTableCreate(f.ctx, prepared); err != nil {
		t.Fatal(err)
	}
	objects, err := f.objects.List(context.Background(), warehouse, "")
	if err != nil || len(objects) != 0 {
		t.Fatalf("unadmitted metadata was not discarded: %#v %v", objects, err)
	}
	events, err := history.Read(f.ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.APICallCompleted != nil && event.APICallCompleted.EventName == "CreateTable" && event.APICallCompleted.ErrorCode == "" {
			t.Fatal("initial schema accepted event escaped outer rollback")
		}
	}
}

func TestMetadataPublicationRejectsMissingSchema(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "validated")
	location := string(*table.WarehouseLocation) + "/staged/not-a-table"
	if err := f.service.Write(f.ctx, location, []byte(`{"format-version":2}`)); err != nil {
		t.Fatal(err)
	}
	_, rejected := f.service.UpdateTableMetadataLocation(f.ctx, &api.UpdateTableMetadataLocationInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("validated")), VersionToken: table.VersionToken, MetadataLocation: new(api.MetadataLocation(location))})
	if rejected == nil || rejected.Code != "BadRequestException" {
		t.Fatalf("metadata without a real current schema was accepted: %v", rejected)
	}
	projectionColumns(t, f, "validated", []owner.Column{{Name: "id", Type: "bigint"}})
	current, rejected := f.service.GetTable(f.ctx, &api.GetTableInput{TableArn: table.TableARN})
	if rejected != nil || *current.MetadataLocation != *table.MetadataLocation || *current.VersionToken != *table.VersionToken {
		t.Fatalf("invalid metadata changed accepted pointer/token: %v", rejected)
	}
}
