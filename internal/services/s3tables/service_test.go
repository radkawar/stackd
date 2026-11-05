package s3tables_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
	owner "stackd/internal/services/s3tables"
	"stackd/journal"
	"stackd/storage/memory"
	storage "stackd/storage/s3tables"
)

// Independently authored public fixtures; behavior sources:
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_s3Buckets_CreateTable.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_s3Buckets_UpdateTableMetadataLocation.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-tables-delete.html
// https://iceberg.apache.org/spec/#table-metadata
func rootContext() context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
}

type fixture struct {
	ctx        context.Context
	service    *owner.Service
	repository *owner.MemoryRepository
	objects    owner.WarehouseObjects
	domain     *memory.Domain
	bucket     *api.TableBucketARN
}

func newFixture(t *testing.T, authorizer authorization.Authorizer) *fixture {
	t.Helper()
	d := memory.NewDomain()
	repo := owner.NewMemoryRepository(d)
	objects := storage.NewMemoryObjects(d)
	ctx := rootContext()
	s := owner.New(owner.Config{Repository: repo, Objects: objects, Authorizer: authorizer, Clock: clock.NewManual(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))})
	b, e := s.CreateTableBucket(ctx, &api.CreateTableBucketInput{Name: new(api.TableBucketName("native-tables"))})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.CreateNamespace(ctx, &api.CreateNamespaceInput{TableBucketARN: b.Arn, Namespace: api.NamespaceList{"analytics"}}); e != nil {
		t.Fatal(e)
	}
	return &fixture{ctx, s, repo, objects, d, b.Arn}
}
func (f *fixture) create(t *testing.T, name string) *api.GetTableOutput {
	t.Helper()
	_, e := f.service.CreateTable(f.ctx, &api.CreateTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName(name)), Format: new(api.OpenTableFormatICEBERG), Metadata: &api.TableMetadata{Iceberg: &api.IcebergMetadata{Schema: &api.IcebergSchema{Fields: api.SchemaFieldList{{Name: new(api.String("id")), Type: new(api.String("long")), Required: new(api.Boolean(true))}}}}}})
	if e != nil {
		t.Fatal(e)
	}
	out, e := f.service.GetTable(f.ctx, &api.GetTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName(name))})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestMetadataCreateCASRenameAndDeletion(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "events")
	data, e := f.service.Read(f.ctx, string(*table.MetadataLocation))
	if e != nil {
		t.Fatal(e)
	}
	var metadata struct {
		FormatVersion int    `json:"format-version"`
		Location      string `json:"location"`
		Schemas       []struct {
			Fields []struct {
				ID   int    `json:"id"`
				Type string `json:"type"`
			} `json:"fields"`
		} `json:"schemas"`
	}
	if e = json.Unmarshal(data, &metadata); e != nil || metadata.FormatVersion != 2 || metadata.Location != string(*table.WarehouseLocation) || len(metadata.Schemas) != 1 || metadata.Schemas[0].Fields[0].ID != 1 {
		t.Fatalf("Invalid Iceberg metadata %s: %v", data, e)
	}
	location := string(*table.WarehouseLocation) + "/metadata/next.metadata.json"
	if e = f.service.Write(f.ctx, location, data); e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	results := make(chan *awswire.Error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, e := f.service.UpdateTableMetadataLocation(f.ctx, &api.UpdateTableMetadataLocationInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), VersionToken: table.VersionToken, MetadataLocation: new(api.MetadataLocation(location))})
			results <- e
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if e.Code == "ConflictException" {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("writers success=%d conflicts=%d", success, conflicts)
	}
	current, rejected := f.service.GetTable(f.ctx, &api.GetTableInput{TableArn: table.TableARN})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if *current.VersionToken == *table.VersionToken {
		t.Fatal("CAS did not rotate token")
	}
	if string(*current.MetadataLocation) != location {
		t.Fatalf("CAS metadata location = %q, want %q", *current.MetadataLocation, location)
	}
	if _, rejected = f.service.RenameTable(f.ctx, &api.RenameTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("events")), NewName: new(api.TableName("renamed")), VersionToken: current.VersionToken}); rejected != nil {
		t.Fatal(rejected)
	}
	renamed, rejected := f.service.GetTable(f.ctx, &api.GetTableInput{TableArn: table.TableARN})
	if rejected != nil || string(*renamed.Name) != "renamed" || *renamed.WarehouseLocation != *table.WarehouseLocation {
		t.Fatalf("rename lost table identity: %v", rejected)
	}
	if _, rejected := f.service.DeleteNamespace(f.ctx, &api.DeleteNamespaceInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics"))}); rejected == nil || rejected.Code != "ConflictException" {
		t.Fatalf("nonempty namespace deletion: %v", rejected)
	}
	if _, rejected = f.service.DeleteTable(f.ctx, &api.DeleteTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("renamed")), VersionToken: renamed.VersionToken}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, e = f.service.Read(f.ctx, location); !errors.Is(e, owner.ErrNotFound) {
		t.Fatalf("deleted table data remained readable: %v", e)
	}
	// A replacement has an independent warehouse; cleanup of the old incarnation
	// cannot remove its bytes, even when name and table bucket are reused.
	replacement := f.create(t, "renamed")
	if *replacement.WarehouseLocation == *table.WarehouseLocation {
		t.Fatal("reused deleted warehouse")
	}
	job, ok, e := f.service.Next(f.ctx)
	if e != nil || !ok {
		t.Fatalf("missing durable cleanup: %v", e)
	}
	if e = f.service.Run(f.ctx, job); e != nil {
		t.Fatal(e)
	}
	objects, e := f.objects.List(f.ctx, string(*table.WarehouseLocation), "")
	if e != nil || len(objects) != 0 {
		t.Fatalf("old bytes survived cleanup: %v %v", objects, e)
	}
	if _, e = f.service.Read(f.ctx, string(*replacement.MetadataLocation)); e != nil {
		t.Fatalf("cleanup removed replacement bytes: %v", e)
	}
	if e = f.service.Run(f.ctx, job); e != nil {
		t.Fatalf("stale cleanup not harmless: %v", e)
	}
}
func TestCurrentIAMForeignScopesAndDataRouting(t *testing.T) {
	identities := iam.NewMemoryRepository(nil)
	identityService := iam.NewWithConfig(iam.Config{Repository: identities})
	authorizer := authorization.NewWithClock(identityService, nil, nil)
	f := newFixture(t, authorizer)
	table := f.create(t, "events")
	user := iam.User{UserName: "reader", UserId: "AIDATABLESREADER", Arn: "arn:aws:iam::123456789012:user/reader", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	setPolicy := func(actions string) {
		t.Helper()
		user.IdentityPolicies.Inline["tables"] = fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":%s,"Resource":"*"}]}`, actions)
		if e := identities.Update(f.ctx, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); e != nil {
			t.Fatal(e)
		}
	}
	setPolicy(`["s3tables:GetTable","s3tables:GetTableData"]`)
	caller := awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
	if _, e := f.service.Read(caller, string(*table.MetadataLocation)); e != nil {
		t.Fatal(e)
	}
	setPolicy(`["s3tables:GetTable"]`)
	if columns, rejected := f.service.TableColumns(caller, string(*f.bucket), "analytics", "events"); rejected != nil || len(columns) != 1 || columns[0].Type != "bigint" {
		t.Fatalf("authorized typed schema read: %#v %v", columns, rejected)
	}
	setPolicy(`[]`)
	if _, rejected := f.service.TableColumns(caller, string(*f.bucket), "analytics", "events"); rejected == nil || rejected.Code != "ForbiddenException" {
		t.Fatalf("schema read retained revoked GetTable permission: %v", rejected)
	}
	setPolicy(`["s3tables:GetTable"]`)
	if _, e := f.service.Read(caller, string(*table.MetadataLocation)); e == nil {
		t.Fatal("cached table-data permission survived IAM revocation")
	}
	if e := f.service.Write(caller, string(*table.WarehouseLocation)+"/data/denied.parquet", []byte("denied")); e == nil {
		t.Fatal("PutTableData was bypassed")
	}
	for _, change := range []func(*awsctx.Metadata){func(m *awsctx.Metadata) {
		m.AccountID = "999999999999"
		m.PrincipalARN = "arn:aws:iam::999999999999:root"
	}, func(m *awsctx.Metadata) { m.Region = "us-west-2" }, func(m *awsctx.Metadata) { m.Partition = "aws-cn" }} {
		m := awsctx.FromContext(f.ctx)
		change(&m)
		foreign := awsctx.WithMetadata(f.ctx, m)
		if _, e := f.service.GetTable(foreign, &api.GetTableInput{TableArn: table.TableARN}); e == nil || e.Code != "NotFoundException" {
			t.Fatalf("foreign table leaked: %v", e)
		}
		if _, e := f.service.Read(foreign, string(*table.MetadataLocation)); !errors.Is(e, owner.ErrNotFound) {
			t.Fatalf("foreign data leaked: %v", e)
		}
		if _, rejected := f.service.TableColumns(foreign, string(*f.bucket), "analytics", "events"); rejected == nil || rejected.Code != "NotFoundException" {
			t.Fatalf("foreign typed schema leaked: %v", rejected)
		}
	}
	path := "/" + strings.TrimPrefix(string(*table.MetadataLocation), "s3://")
	request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(caller)
	response := httptest.NewRecorder()
	if !f.service.ClaimsData(request) || !f.service.HandleData(response, request) || response.Code != 403 {
		t.Fatalf("denied owner route fell through: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/ordinary-bucket/object", nil).WithContext(f.ctx)
	if f.service.ClaimsData(request) || f.service.HandleData(httptest.NewRecorder(), request) {
		t.Fatal("ordinary S3 route was claimed")
	}
	request = httptest.NewRequest(http.MethodGet, path, nil).WithContext(f.ctx)
	request.Header.Set("Range", "bytes=0-9")
	response = httptest.NewRecorder()
	if !f.service.HandleData(response, request) || response.Code != 206 || response.Body.Len() != 10 {
		t.Fatalf("native range read: %d %s", response.Code, response.Body.String())
	}
	if e := f.service.Write(f.ctx, string(*table.WarehouseLocation)+"/../escape", []byte("escape")); e == nil {
		t.Fatal("warehouse traversal accepted")
	}
}

func TestCatalogStateAndJournalJoinOuterTransaction(t *testing.T) {
	ctx := rootContext()
	domain := memory.NewDomain()
	repo := owner.NewMemoryRepository(domain)
	history := journal.NewMemory(domain)
	s := owner.New(owner.Config{Repository: repo, Recorder: apievents.New(history)})
	rollback := errors.New("caller rolls back")
	err := repo.Update(ctx, func(tx owner.Transaction) error {
		if _, e := s.CreateTableBucket(tx.Context(), &api.CreateTableBucketInput{Name: new(api.TableBucketName("atomic-tables"))}); e != nil {
			return e
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	listed, rejected := s.ListTableBuckets(ctx, &api.ListTableBucketsInput{})
	if rejected != nil || len(listed.TableBuckets) != 0 {
		t.Fatalf("rolled-back bucket retained: %v", rejected)
	}
	events, err := history.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.APICallCompleted != nil && event.APICallCompleted.EventName == "CreateTableBucket" {
			t.Fatal("accepted journal escaped resource rollback")
		}
	}
	if _, rejected = s.CreateTableBucket(ctx, &api.CreateTableBucketInput{Name: new(api.TableBucketName("atomic-tables"))}); rejected != nil {
		t.Fatal(rejected)
	}
	events, err = history.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	creates := 0
	for _, event := range events {
		if event.APICallCompleted != nil && event.APICallCompleted.EventName == "CreateTableBucket" {
			creates++
		}
	}
	if creates != 1 {
		t.Fatalf("committed create events=%d", creates)
	}
}

func TestNativePayloadChecksumAdmission(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "checksums")
	location := string(*table.WarehouseLocation) + "/data/content.parquet"
	path := "/" + strings.TrimPrefix(location, "s3://")
	for _, tc := range []struct {
		md5, crc32 string
		status     int
	}{{"not-base64", "", 400}, {"AAAAAAAAAAAAAAAAAAAAAA==", "", 400}, {"XUFAKrxLKna5cZ2REBfFkg==", "", 200}, {"", "AAAAAA==", 400}} {
		r := httptest.NewRequest(http.MethodPut, path, strings.NewReader("hello")).WithContext(f.ctx)
		if tc.md5 != "" {
			r.Header.Set("Content-MD5", tc.md5)
		}
		if tc.crc32 != "" {
			r.Header.Set("X-Amz-Checksum-Crc32", tc.crc32)
		}
		w := httptest.NewRecorder()
		if !f.service.HandleData(w, r) || w.Code != tc.status {
			t.Fatalf("checksum admission status=%d body=%s", w.Code, w.Body.String())
		}
	}
	data, e := f.service.Read(f.ctx, location)
	if e != nil || string(data) != "hello" {
		t.Fatalf("corrupt upload changed stored bytes: %s %v", data, e)
	}
	r := httptest.NewRequest(http.MethodGet, path, nil).WithContext(f.ctx)
	r.Header.Set("X-Amz-Request-Payer", "requester")
	w := httptest.NewRecorder()
	if !f.service.HandleData(w, r) || w.Code != 403 {
		t.Fatalf("requester-pays table data admitted: %d", w.Code)
	}
}

func TestSmithySchemaV2PartitionOrderAndProperties(t *testing.T) {
	f := newFixture(t, nil)
	_, rejected := f.service.CreateTable(f.ctx, &api.CreateTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("partitioned")), Format: new(api.OpenTableFormatICEBERG), Metadata: &api.TableMetadata{Iceberg: &api.IcebergMetadata{
		SchemaV2:      &api.IcebergSchemaV2{Type: new(api.SchemaV2FieldTypeSTRUCT), Fields: api.SchemaV2FieldList{{Id: new(api.Integer(5)), Name: new(api.String("category")), Doc: new(api.String("event category")), Required: new(api.Boolean(true)), Type: "string"}, {Id: new(api.Integer(9)), Name: new(api.String("id")), Required: new(api.Boolean(true)), Type: "long"}}, IdentifierFieldIds: api.IntegerList{9}},
		PartitionSpec: &api.IcebergPartitionSpec{Fields: api.IcebergPartitionFieldList{{Name: new(api.String("category_bucket")), SourceId: new(api.Integer(5)), Transform: new(api.String("bucket[16]"))}}},
		WriteOrder:    &api.IcebergSortOrder{OrderId: new(api.Integer(1)), Fields: api.IcebergSortFieldList{{SourceId: new(api.Integer(9)), Transform: new(api.String("identity")), Direction: new(api.IcebergSortDirectionASC), NullOrder: new(api.IcebergNullOrderNULLS_LAST)}}},
		Properties:    api.TableProperties{"write.format.default": "parquet"},
	}}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	table, rejected := f.service.GetTable(f.ctx, &api.GetTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("partitioned"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	data, err := f.service.Read(f.ctx, string(*table.MetadataLocation))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Properties     map[string]string `json:"properties"`
		PartitionSpecs []struct {
			Fields []struct {
				SourceID  int    `json:"source-id"`
				Transform string `json:"transform"`
			} `json:"fields"`
		} `json:"partition-specs"`
		SortOrders []struct {
			Fields []struct {
				SourceID int `json:"source-id"`
			} `json:"fields"`
		} `json:"sort-orders"`
	}
	if err = json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Properties["write.format.default"] != "parquet" || len(metadata.PartitionSpecs) != 1 || len(metadata.PartitionSpecs[0].Fields) != 1 || metadata.PartitionSpecs[0].Fields[0].SourceID != 1 || metadata.PartitionSpecs[0].Fields[0].Transform != "bucket[16]" || len(metadata.SortOrders) != 1 || metadata.SortOrders[0].Fields[0].SourceID != 2 {
		t.Fatalf("Smithy metadata did not reach Iceberg owner: %s", data)
	}
	columns, rejected := f.service.TableColumns(f.ctx, string(*f.bucket), "analytics", "partitioned")
	if rejected != nil || len(columns) != 2 || columns[0].Name != "category" || columns[0].Type != "string" || columns[0].Comment != "event category" || columns[1].Name != "id" || columns[1].Type != "bigint" {
		t.Fatalf("initial SchemaV2 projection lost typed fields/comments: %#v %v", columns, rejected)
	}
}
