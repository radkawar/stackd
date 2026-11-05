package glue_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
	"stackd/internal/awsctx"
	"stackd/internal/services/glue"
	"stackd/internal/services/glue/icebergmeta"
	"stackd/internal/services/iam"
	owner "stackd/internal/services/s3tables"
	"stackd/storage/memory"
	warehouses "stackd/storage/s3tables"
)

type forbiddenOrdinaryIcebergObjects struct{ calls int }

func (o *forbiddenOrdinaryIcebergObjects) Read(context.Context, string) ([]byte, error) {
	o.calls++
	return nil, errors.New("ordinary S3 must not own managed metadata")
}
func (o *forbiddenOrdinaryIcebergObjects) Write(context.Context, string, []byte) error {
	o.calls++
	return errors.New("ordinary S3 must not own managed metadata")
}

type interleavedManagedOwner struct {
	*owner.Service
	afterWrite func()
}

func (o *interleavedManagedOwner) Write(ctx context.Context, location string, data []byte) error {
	if e := o.Service.Write(ctx, location, data); e != nil {
		return e
	}
	if o.afterWrite != nil {
		hook := o.afterWrite
		o.afterWrite = nil
		hook()
	}
	return nil
}

func TestS3TablesRESTUsesManagedOwnerWithoutShadowState(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	repo := glue.NewMemoryRepository(domain)
	objects := warehouses.NewMemoryObjects(domain)
	actual := owner.New(owner.Config{Repository: owner.NewMemoryRepository(domain), Objects: objects})
	managed := &interleavedManagedOwner{Service: actual}
	ordinary := &forbiddenOrdinaryIcebergObjects{}
	service := glue.New(glue.Config{Repository: repo, S3Tables: managed, IcebergObjects: ordinary})
	defer service.Close()
	bucket, rejected := actual.CreateTableBucket(ctx, &tables.CreateTableBucketInput{Name: new(tables.TableBucketName("rest-bucket"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	catalogTestCall[api.CreateCatalogOutput](t, service, ctx, "CreateCatalog", &api.CreateCatalogInput{Name: new(api.CatalogNameString("s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: &api.FederatedCatalog{Identifier: new(api.FederationIdentifier("arn:aws:s3tables:us-east-1:123456789012:bucket/*")), ConnectionName: new(api.NameString("aws:s3tables"))}}})
	child := "123456789012:s3tablescatalog/rest-bucket"
	prefix := "/iceberg/v1/catalogs/" + url.PathEscape(child)
	call := func(caller context.Context, method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(caller)
		response := httptest.NewRecorder()
		service.ServePrivateOperation(response, request)
		if response.Code != want {
			t.Fatalf("%s %s status=%d body=%s want=%d", method, path, response.Code, response.Body.String(), want)
		}
		return response
	}
	call(ctx, http.MethodPost, "/iceberg/v1/catalogs/123456789012:s3tablescatalog/namespaces", `{"namespace":["shadow"]}`, 400)
	call(ctx, http.MethodPost, "/iceberg/v1/catalogs/123456789012:s3tablescatalog/namespaces/shadow/tables", `{"name":"shadow","location":"s3://ordinary/shadow","schema":{"type":"struct","schema-id":0,"fields":[]}}`, 400)
	config := call(ctx, http.MethodGet, "/iceberg/v1/config?warehouse="+url.QueryEscape(child), "", 200)
	var cfg struct {
		Overrides map[string]string `json:"overrides"`
	}
	if e := json.Unmarshal(config.Body.Bytes(), &cfg); e != nil {
		t.Fatal(e)
	}
	if cfg.Overrides["prefix"] != "catalogs/"+url.PathEscape(child) {
		t.Fatal("config did not preserve escaped mounted catalog identity")
	}
	call(ctx, http.MethodPost, prefix+"/namespaces", `{"namespace":["analytics"]}`, 200)
	call(ctx, http.MethodGet, prefix+"/namespaces", "", 200)
	call(ctx, http.MethodGet, prefix+"/namespaces/analytics", "", 200)
	call(ctx, http.MethodHead, prefix+"/namespaces/analytics", "", 204)
	create := `{"name":"events","schema":{"type":"struct","schema-id":0,"fields":[{"id":1,"name":"id","required":true,"type":"long"}]},"properties":{"format-version":"2"}}`
	call(ctx, http.MethodPost, prefix+"/namespaces/analytics/tables", strings.Replace(create, `"name":"events"`, `"stage-create":true,"name":"events"`, 1), 400)
	response := call(ctx, http.MethodPost, prefix+"/namespaces/analytics/tables", create, 200)
	var loaded struct {
		MetadataLocation string               `json:"metadata-location"`
		Metadata         icebergmeta.Metadata `json:"metadata"`
	}
	if e := json.Unmarshal(response.Body.Bytes(), &loaded); e != nil {
		t.Fatal(e)
	}
	if loaded.MetadataLocation == "" || !strings.HasSuffix(strings.Split(strings.TrimPrefix(loaded.MetadataLocation, "s3://"), "/")[0], "--table-s3") || len(loaded.Metadata.Schemas) != 1 {
		t.Fatal("REST create did not materialize managed Iceberg metadata")
	}
	table, rejected := actual.GetTable(ctx, &tables.GetTableInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("analytics")), Name: new(tables.TableName("events"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if string(*table.MetadataLocation) != loaded.MetadataLocation {
		t.Fatal("REST published an independent metadata head")
	}
	projected := catalogTestCall[api.GetTableOutput](t, service, ctx, "GetTable", &api.GetTableInput{CatalogId: new(api.CatalogIdString(child)), DatabaseName: new(api.NameString("analytics")), Name: new(api.NameString("events"))})
	if len(projected.Table.StorageDescriptor.Columns) != 1 || catalogTestValue(projected.Table.StorageDescriptor.Columns[0].Type) != "bigint" {
		t.Fatal("Glue did not expose the actual managed schema")
	}
	call(ctx, http.MethodGet, prefix+"/namespaces/analytics/tables", "", 200)
	call(ctx, http.MethodHead, prefix+"/namespaces/analytics/tables/events", "", 204)
	call(ctx, http.MethodDelete, prefix+"/namespaces/analytics", "", 409)
	commit := `{"requirements":[{"type":"assert-table-uuid","uuid":"` + loaded.Metadata.UUID + `"}],"updates":[{"action":"set-properties","updates":{"fixture":"committed"}}]}`
	call(ctx, http.MethodPost, prefix+"/namespaces/analytics/tables/events", commit, 200)
	current, rejected := actual.GetTable(ctx, &tables.GetTableInput{TableArn: table.TableARN})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if *current.VersionToken == *table.VersionToken {
		t.Fatal("REST commit did not advance actual owner token")
	}
	managed.afterWrite = func() {
		_, e := actual.UpdateTableMetadataLocation(ctx, &tables.UpdateTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("analytics")), Name: new(tables.TableName("events")), VersionToken: current.VersionToken, MetadataLocation: current.MetadataLocation})
		if e != nil {
			t.Fatal(e)
		}
	}
	call(ctx, http.MethodPost, prefix+"/namespaces/analytics/tables/events", commit, 409)
	call(ctx, http.MethodGet, prefix+"/namespaces/analytics/tables/events", "", 200)
	foreign := awsctx.FromContext(ctx)
	foreign.Region = "us-west-2"
	call(awsctx.WithMetadata(ctx, foreign), http.MethodGet, prefix+"/namespaces/analytics/tables/events", "", 404)
	call(ctx, http.MethodDelete, prefix+"/namespaces/analytics/tables/events", "", 400)
	call(ctx, http.MethodDelete, prefix+"/namespaces/analytics/tables/events?purgeRequested=false", "", 400)
	call(ctx, http.MethodDelete, prefix+"/namespaces/analytics/tables/events?purgeRequested=true", "", 204)
	if _, e := actual.Read(ctx, loaded.MetadataLocation); !errors.Is(e, owner.ErrNotFound) {
		t.Fatalf("managed drop retained live data authority: %v", e)
	}
	source := actual.JobSource()
	job, found, e := source.Next(ctx)
	if e != nil || !found {
		t.Fatalf("missing durable cleanup: %v", e)
	}
	if e = source.Run(ctx, job); e != nil {
		t.Fatal(e)
	}
	bytes, e := objects.List(ctx, string(*table.WarehouseLocation), "")
	if e != nil || len(bytes) != 0 {
		t.Fatalf("managed REST drop did not reclaim data: %v %+v", e, bytes)
	}
	call(ctx, http.MethodDelete, prefix+"/namespaces/analytics", "", 204)
	if ordinary.calls != 0 {
		t.Fatalf("managed REST used ordinary S3 %d times", ordinary.calls)
	}
	if e := repo.View(ctx, func(r glue.Reader) error {
		for _, id := range []string{"123456789012:s3tablescatalog", child} {
			dbs, e := r.Databases(glue.CatalogKey{Scope: glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, CatalogID: id})
			if e != nil {
				return e
			}
			if len(dbs) != 0 {
				t.Fatal("managed REST created shadow Glue database rows")
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestS3TablesRESTRechecksGlueIAMAfterExternalMetadataWrite(t *testing.T) {
	root := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	identityService := iam.NewWithConfig(iam.Config{Repository: identities})
	authorizer := authorization.New(identityService, nil)
	actual := owner.New(owner.Config{Repository: owner.NewMemoryRepository(domain), Objects: warehouses.NewMemoryObjects(domain), Authorizer: authorizer})
	managed := &interleavedManagedOwner{Service: actual}
	ordinary := &forbiddenOrdinaryIcebergObjects{}
	service := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), S3Tables: managed, IcebergObjects: ordinary, Authorizer: authorizer})
	defer service.Close()
	bucket, rejected := actual.CreateTableBucket(root, &tables.CreateTableBucketInput{Name: new(tables.TableBucketName("iam-rest-bucket"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	catalogTestCall[api.CreateCatalogOutput](t, service, root, "CreateCatalog", &api.CreateCatalogInput{Name: new(api.CatalogNameString("s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: &api.FederatedCatalog{Identifier: new(api.FederationIdentifier("arn:aws:s3tables:us-east-1:123456789012:bucket/*")), ConnectionName: new(api.NameString("aws:s3tables"))}}})
	if _, rejected = actual.CreateNamespace(root, &tables.CreateNamespaceInput{TableBucketARN: bucket.Arn, Namespace: tables.NamespaceList{"analytics"}}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected = actual.CreateTable(root, &tables.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("analytics")), Name: new(tables.TableName("events")), Format: new(tables.OpenTableFormatICEBERG), Metadata: &tables.TableMetadata{Iceberg: &tables.IcebergMetadata{Schema: &tables.IcebergSchema{Fields: tables.SchemaFieldList{{Name: new(tables.String("id")), Type: new(tables.String("long"))}}}}}}); rejected != nil {
		t.Fatal(rejected)
	}
	before, rejected := actual.GetTable(root, &tables.GetTableInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("analytics")), Name: new(tables.TableName("events"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	user := iam.User{UserName: "rest-writer", UserId: "AIDARESTWRITER", Arn: "arn:aws:iam::123456789012:user/rest-writer", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	setPolicy := func(document string) {
		t.Helper()
		user.IdentityPolicies.Inline["access"] = document
		if e := identities.Update(root, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); e != nil {
			t.Fatal(e)
		}
	}
	setPolicy(`{"Statement":[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"}]}`)
	caller := awsctx.FromContext(root)
	caller.PrincipalARN = user.Arn
	caller.PrincipalID = user.UserId
	ctx := awsctx.WithMetadata(root, caller)
	managed.afterWrite = func() {
		setPolicy(`{"Statement":[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"},{"Effect":"Deny","Action":"glue:UpdateTable","Resource":"*"}]}`)
	}
	path := "/iceberg/v1/catalogs/" + url.PathEscape("123456789012:s3tablescatalog/iam-rest-bucket") + "/namespaces/analytics/tables/events"
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"requirements":[],"updates":[{"action":"set-properties","updates":{"must-not-publish":"true"}}]}`)).WithContext(ctx)
	response := httptest.NewRecorder()
	service.ServePrivateOperation(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("revoked Glue authority published metadata: %d %s", response.Code, response.Body.String())
	}
	after, rejected := actual.GetTable(root, &tables.GetTableInput{TableArn: before.TableARN})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if *after.VersionToken != *before.VersionToken || *after.MetadataLocation != *before.MetadataLocation {
		t.Fatal("revoked REST writer changed the authoritative owner")
	}
	if ordinary.calls != 0 {
		t.Fatal("revoked managed request fell back to ordinary S3")
	}
}
