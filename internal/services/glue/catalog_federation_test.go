package glue_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/glue"
	"stackd/internal/services/glue/icebergmeta"
	"stackd/internal/services/iam"
	owner "stackd/internal/services/s3tables"
	"stackd/storage/memory"
	warehouses "stackd/storage/s3tables"
)

// Public independently authored fixtures for the documented IAM integration:
// https://docs.aws.amazon.com/glue/latest/dg/enable-s3-tables-catalog-integration.html
// https://docs.aws.amazon.com/glue/latest/dg/s3tables-catalog-prerequisites.html
func TestS3TablesFederationUsesCurrentOwnerAndVersionToken(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	repository := glue.NewMemoryRepository(domain)
	tableOwner := owner.New(owner.Config{Repository: owner.NewMemoryRepository(domain), Objects: warehouses.NewMemoryObjects(domain)})
	service := glue.New(glue.Config{Repository: repository, S3Tables: tableOwner})
	defer service.Close()
	federation := &api.FederatedCatalog{ConnectionName: new(api.NameString("aws:s3tables")), Identifier: new(api.FederationIdentifier("arn:aws:s3tables:us-east-1:123456789012:bucket/*"))}
	catalogTestCall[api.CreateCatalogOutput](t, service, ctx, "CreateCatalog", &api.CreateCatalogInput{Name: new(api.CatalogNameString("s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: federation}})
	children := func() *api.GetCatalogsOutput {
		return catalogTestCall[api.GetCatalogsOutput](t, service, ctx, "GetCatalogs", &api.GetCatalogsInput{ParentCatalogId: new(api.CatalogIdString("s3tablescatalog"))})
	}
	if len(children().CatalogList) != 0 {
		t.Fatal("integration invented a table bucket")
	}
	bucket, rejected := tableOwner.CreateTableBucket(ctx, &tables.CreateTableBucketInput{Name: new(tables.TableBucketName("native-bucket"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if len(children().CatalogList) != 1 {
		t.Fatal("new authoritative bucket was not discovered dynamically")
	}
	id := new(api.CatalogIdString("123456789012:s3tablescatalog/native-bucket"))
	if got := catalogTestValue(children().CatalogList[0].CatalogId); got != string(*id) {
		t.Fatalf("AWS child catalog identifier = %q, want %q", got, *id)
	}
	mounted := catalogTestCall[api.GetCatalogOutput](t, service, ctx, "GetCatalog", &api.GetCatalogInput{CatalogId: new(api.CatalogIdString("s3tablescatalog/native-bucket"))})
	if catalogTestValue(mounted.Catalog.CatalogId) != string(*id) || catalogTestValue(mounted.Catalog.ResourceArn) != "arn:aws:glue:us-east-1:123456789012:catalog/s3tablescatalog/native-bucket" {
		t.Fatal("AWS-shaped slash child did not retain its catalog identity and ARN")
	}
	catalogTestCall[api.CreateDatabaseOutput](t, service, ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: id, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("analytics"))}})
	if _, rejected := tableOwner.GetNamespace(ctx, &tables.GetNamespaceInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("analytics"))}); rejected != nil {
		t.Fatalf("Glue did not write authoritative namespace: %v", rejected)
	}
	catalogTestError(t, service, ctx, "GetDatabase", &api.GetDatabaseInput{CatalogId: new(api.CatalogIdString("123456789012:s3tablescatalog:native-bucket")), Name: new(api.NameString("analytics"))}, "EntityNotFoundException")
	catalogTestCall[api.GetDatabaseOutput](t, service, ctx, "GetDatabase", &api.GetDatabaseInput{CatalogId: new(api.CatalogIdString("s3tablescatalog/native-bucket")), Name: new(api.NameString("analytics"))})
	created, rejected := tableOwner.CreateTable(ctx, &tables.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("analytics")), Name: new(tables.TableName("events")), Format: new(tables.OpenTableFormatICEBERG), Metadata: &tables.TableMetadata{Iceberg: &tables.IcebergMetadata{Schema: &tables.IcebergSchema{Fields: tables.SchemaFieldList{{Name: new(tables.String("id")), Type: new(tables.String("long"))}}}}}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	load := func() *api.GetTableOutput {
		return catalogTestCall[api.GetTableOutput](t, service, ctx, "GetTable", &api.GetTableInput{CatalogId: id, DatabaseName: new(api.NameString("analytics")), Name: new(api.NameString("events"))})
	}
	before := load()
	if catalogTestValue(before.Table.VersionId) != string(*created.VersionToken) {
		t.Fatal("Glue invented a second table version")
	}
	if len(before.Table.StorageDescriptor.Columns) != 1 || catalogTestValue(before.Table.StorageDescriptor.Columns[0].Type) != "bigint" {
		t.Fatal("Glue did not project the actual initial Iceberg schema")
	}
	writeMetadata := func(location, column string) {
		t.Helper()
		current := load()
		data, err := tableOwner.Read(ctx, string(current.Table.Parameters["metadata_location"]))
		if err != nil {
			t.Fatal(err)
		}
		var metadata icebergmeta.Metadata
		if err = json.Unmarshal(data, &metadata); err != nil {
			t.Fatal(err)
		}
		schema := metadata.Schemas[len(metadata.Schemas)-1]
		schema.Fields = append(append([]icebergmeta.Field(nil), schema.Fields...), icebergmeta.Field{ID: metadata.LastColumnID + 1, Name: column, Type: json.RawMessage(`"string"`), Doc: "actual evolved field"})
		schema.SchemaID++
		metadata.Schemas = append(metadata.Schemas, schema)
		metadata.CurrentSchemaID = schema.SchemaID
		metadata.LastColumnID++
		data, err = json.Marshal(metadata)
		if err != nil {
			t.Fatal(err)
		}
		if err = tableOwner.Write(ctx, location, data); err != nil {
			t.Fatal(err)
		}
	}
	location := catalogTestValue(before.Table.StorageDescriptor.Location) + "/metadata/00001-native.metadata.json"
	writeMetadata(location, "label")
	update := &api.UpdateTableInput{CatalogId: id, DatabaseName: new(api.NameString("analytics")), VersionId: before.Table.VersionId, TableInput: &api.TableInput{Name: new(api.NameString("events")), Parameters: api.ParametersMap{"table_type": "ICEBERG", "metadata_location": api.ParametersMapValue(location)}}}
	catalogTestCall[api.UpdateTableOutput](t, service, ctx, "UpdateTable", update)
	catalogTestError(t, service, ctx, "UpdateTable", update, "ConcurrentModificationException")
	after := load()
	if string(after.Table.Parameters["metadata_location"]) != location || catalogTestValue(after.Table.VersionId) == catalogTestValue(before.Table.VersionId) {
		t.Fatal("Glue commit did not advance the authoritative metadata pointer and token")
	}
	if len(after.Table.StorageDescriptor.Columns) != 2 || catalogTestValue(after.Table.StorageDescriptor.Columns[1].Name) != "label" {
		t.Fatal("native metadata publication did not project the evolved schema")
	}
	directLocation := catalogTestValue(after.Table.StorageDescriptor.Location) + "/metadata/00002-direct.metadata.json"
	writeMetadata(directLocation, "score")
	direct, rejected := tableOwner.UpdateTableMetadataLocation(ctx, &tables.UpdateTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("analytics")), Name: new(tables.TableName("events")), VersionToken: new(tables.VersionToken(catalogTestValue(after.Table.VersionId))), MetadataLocation: new(tables.MetadataLocation(directLocation))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	update.VersionId = after.Table.VersionId
	catalogTestError(t, service, ctx, "UpdateTable", update, "ConcurrentModificationException")
	current := load()
	if string(current.Table.Parameters["metadata_location"]) != directLocation || catalogTestValue(current.Table.VersionId) != string(*direct.VersionToken) {
		t.Fatal("stale Glue writer overwrote the direct S3 Tables commit")
	}
	if len(current.Table.StorageDescriptor.Columns) != 3 || catalogTestValue(current.Table.StorageDescriptor.Columns[2].Name) != "score" {
		t.Fatal("stale native CAS replaced the direct owner's accepted schema")
	}
	rows := catalogTestCall[api.GetTablesOutput](t, service, ctx, "GetTables", &api.GetTablesInput{CatalogId: id, DatabaseName: new(api.NameString("analytics"))})
	if len(rows.TableList) != 1 {
		t.Fatal("authoritative tables were not discovered")
	}
	if err := repository.View(ctx, func(r glue.Reader) error {
		key := glue.CatalogKey{Scope: glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, CatalogID: string(*id)}
		if _, err := r.Catalog(key); err == nil {
			t.Fatal("mounted catalog was persisted as a Glue alias")
		}
		dbs, err := r.Databases(key)
		if err != nil {
			return err
		}
		if len(dbs) != 0 {
			t.Fatal("federated namespace was duplicated in Glue")
		}
		tables, err := r.Tables(glue.DatabaseKey{CatalogKey: key, Name: "analytics"})
		if err == nil && len(tables) != 0 {
			t.Fatal("federated table was duplicated in Glue")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	catalogTestCall[api.DeleteTableOutput](t, service, ctx, "DeleteTable", &api.DeleteTableInput{CatalogId: id, DatabaseName: new(api.NameString("analytics")), Name: new(api.NameString("events"))})
	catalogTestCall[api.DeleteDatabaseOutput](t, service, ctx, "DeleteDatabase", &api.DeleteDatabaseInput{CatalogId: id, Name: new(api.NameString("analytics"))})
	if _, rejected := tableOwner.DeleteTableBucket(ctx, &tables.DeleteTableBucketInput{TableBucketARN: bucket.Arn}); rejected != nil {
		t.Fatal(rejected)
	}
	if len(children().CatalogList) != 0 {
		t.Fatal("deleted bucket survived as a Glue alias")
	}
}

type federationCreateObserver struct {
	glue.S3Tables
	tableCreates, namespaceCreates, metadataUpdates int
}

func (s *federationCreateObserver) CreateTable(ctx context.Context, in *tables.CreateTableInput) (*tables.CreateTableOutput, *awswire.Error) {
	s.tableCreates++
	return s.S3Tables.CreateTable(ctx, in)
}

func (s *federationCreateObserver) CreateNamespace(ctx context.Context, in *tables.CreateNamespaceInput) (*tables.CreateNamespaceOutput, *awswire.Error) {
	s.namespaceCreates++
	return s.S3Tables.CreateNamespace(ctx, in)
}

func (s *federationCreateObserver) UpdateTableMetadataLocation(ctx context.Context, in *tables.UpdateTableMetadataLocationInput) (*tables.UpdateTableMetadataLocationOutput, *awswire.Error) {
	s.metadataUpdates++
	return s.S3Tables.UpdateTableMetadataLocation(ctx, in)
}

type federationCreateObjects struct {
	owner.WarehouseObjects
	writes, deletes int
}

func (o *federationCreateObjects) Write(ctx context.Context, warehouse, key string, data []byte, modified time.Time) error {
	o.writes++
	return o.WarehouseObjects.Write(ctx, warehouse, key, data, modified)
}

func (o *federationCreateObjects) Delete(ctx context.Context, warehouse, key string) error {
	o.deletes++
	return o.WarehouseObjects.Delete(ctx, warehouse, key)
}

// A registered Athena data source does not support DDL. Direct native Glue
// creation is a separate API, but this adapter cannot adopt an existing metadata
// file into the new, owner-allocated S3 Tables warehouse.
// https://docs.aws.amazon.com/athena/latest/ug/gdc-register-s3-table-bucket-cat.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_s3Buckets_UpdateTableMetadataLocation.html
func TestS3TablesFederationRejectsMetadataLocationCreateWithoutSideEffects(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	repository := glue.NewMemoryRepository(domain)
	ownerRepository := owner.NewMemoryRepository(domain)
	objects := &federationCreateObjects{WarehouseObjects: warehouses.NewMemoryObjects(domain)}
	tableOwner := owner.New(owner.Config{Repository: ownerRepository, Objects: objects})
	bucket, rejected := tableOwner.CreateTableBucket(ctx, &tables.CreateTableBucketInput{Name: new(tables.TableBucketName("create-bucket"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected := tableOwner.CreateNamespace(ctx, &tables.CreateNamespaceInput{TableBucketARN: bucket.Arn, Namespace: tables.NamespaceList{"analytics"}}); rejected != nil {
		t.Fatal(rejected)
	}
	observed := &federationCreateObserver{S3Tables: tableOwner}
	service := glue.New(glue.Config{Repository: repository, S3Tables: observed})
	defer service.Close()
	catalogTestCall[api.CreateCatalogOutput](t, service, ctx, "CreateCatalog", &api.CreateCatalogInput{Name: new(api.CatalogNameString("s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: &api.FederatedCatalog{ConnectionName: new(api.NameString("aws:s3tables")), Identifier: new(api.FederationIdentifier(string(*bucket.Arn)))}}})
	id := new(api.CatalogIdString("123456789012:s3tablescatalog/create-bucket"))
	for _, namespace := range []string{"analytics", "missing"} {
		t.Run(namespace, func(t *testing.T) {
			input := &api.CreateTableInput{CatalogId: id, DatabaseName: new(api.NameString(namespace)), TableInput: &api.TableInput{Name: new(api.NameString("events")), Parameters: api.ParametersMap{"table_type": "ICEBERG", "metadata_location": "s3://existing-bucket/metadata/existing.metadata.json"}}}
			_, rejected := catalogTestExecute(service, ctx, "CreateTable", input)
			if rejected == nil || rejected.Code != "InvalidInputException" {
				t.Fatalf("CreateTable error=%v, want InvalidInputException", rejected)
			}
		})
	}
	if observed.tableCreates != 0 || observed.namespaceCreates != 0 || observed.metadataUpdates != 0 {
		t.Fatalf("rejected creation called owner mutations: tables=%d namespaces=%d metadata=%d", observed.tableCreates, observed.namespaceCreates, observed.metadataUpdates)
	}
	if objects.writes != 0 || objects.deletes != 0 {
		t.Fatalf("rejected creation touched warehouse objects: writes=%d deletes=%d", objects.writes, objects.deletes)
	}
	scope := owner.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	if err := ownerRepository.View(ctx, func(r owner.Reader) error {
		rows, err := r.Tables(scope, string(*bucket.Arn))
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			t.Fatal("rejected creation allocated owner table or warehouse state")
		}
		namespaces, err := r.Namespaces(scope, string(*bucket.Arn))
		if err == nil && (len(namespaces) != 1 || namespaces[0].Name != "analytics") {
			t.Fatal("rejected creation changed owner namespaces")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(ctx, func(r glue.Reader) error {
		key := glue.CatalogKey{Scope: glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, CatalogID: string(*id)}
		databases, err := r.Databases(key)
		if err != nil {
			return err
		}
		if len(databases) != 0 {
			t.Fatal("rejected creation allocated Glue namespace state")
		}
		for _, namespace := range []string{"analytics", "missing"} {
			rows, err := r.Tables(glue.DatabaseKey{CatalogKey: key, Name: namespace})
			if err != nil {
				return err
			}
			if len(rows) != 0 {
				t.Fatal("rejected creation allocated Glue table state")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestS3TablesFederationCurrentIAMAndForeignScope(t *testing.T) {
	root := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	identityService := iam.NewWithConfig(iam.Config{Repository: identities})
	authorizer := authorization.NewWithClock(identityService, nil, nil)
	tableOwner := owner.New(owner.Config{Repository: owner.NewMemoryRepository(domain), Authorizer: authorizer})
	service := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), Authorizer: authorizer, S3Tables: tableOwner})
	defer service.Close()
	bucket, rejected := tableOwner.CreateTableBucket(root, &tables.CreateTableBucketInput{Name: new(tables.TableBucketName("iam-bucket"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	user := iam.User{UserName: "federator", UserId: "AIDAFEDERATOR", Arn: "arn:aws:iam::123456789012:user/federator", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	caller := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
	setPolicy := func(statements string) {
		t.Helper()
		user.IdentityPolicies.Inline["federation"] = `{"Version":"2012-10-17","Statement":` + statements + `}`
		if err := identities.Update(root, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	create := &api.CreateCatalogInput{Name: new(api.CatalogNameString("s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: &api.FederatedCatalog{Identifier: new(api.FederationIdentifier(string(*bucket.Arn))), ConnectionName: new(api.NameString("aws:s3tables"))}}}
	setPolicy(`[{"Effect":"Allow","Action":["glue:CreateCatalog","s3tables:*"],"Resource":"*"}]`)
	catalogTestError(t, service, caller, "CreateCatalog", create, "AccessDeniedException")
	setPolicy(`[{"Effect":"Allow","Action":"glue:*","Resource":"*"}]`)
	catalogTestError(t, service, caller, "CreateCatalog", create, "AccessDeniedException")
	setPolicy(`[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"}]`)
	catalogTestCall[api.CreateCatalogOutput](t, service, caller, "CreateCatalog", create)
	id := new(api.CatalogIdString("123456789012:s3tablescatalog/iam-bucket"))
	catalogTestCall[api.CreateDatabaseOutput](t, service, caller, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: id, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("data"))}})
	get := &api.GetDatabaseInput{CatalogId: id, Name: new(api.NameString("data"))}
	catalogTestCall[api.GetDatabaseOutput](t, service, caller, "GetDatabase", get)
	for _, denied := range []string{"s3tables:GetNamespace", "glue:GetDatabase", "s3tables:GetTableBucket"} {
		setPolicy(fmt.Sprintf(`[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"},{"Effect":"Deny","Action":%q,"Resource":"*"}]`, denied))
		catalogTestError(t, service, caller, "GetDatabase", get, "AccessDeniedException")
	}
	setPolicy(`[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"},{"Effect":"Deny","Action":"glue:GetDatabase","Resource":"arn:aws:glue:us-east-1:123456789012:catalog/s3tablescatalog"}]`)
	catalogTestError(t, service, caller, "GetDatabase", get, "AccessDeniedException")
	setPolicy(`[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"}]`)
	catalogTestCall[api.GetDatabaseOutput](t, service, caller, "GetDatabase", get)
	for _, arn := range []string{"arn:aws:s3tables:us-west-2:123456789012:bucket/*", "arn:aws:s3tables:us-east-1:999999999999:bucket/*", "arn:aws-cn:s3tables:us-east-1:123456789012:bucket/*"} {
		catalogTestError(t, service, caller, "UpdateCatalog", &api.UpdateCatalogInput{CatalogId: new(api.CatalogIdString("123456789012:s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: &api.FederatedCatalog{Identifier: new(api.FederationIdentifier(arn)), ConnectionName: new(api.NameString("aws:s3tables"))}}}, "AccessDeniedException")
	}
	foreign := catalogTestContext("999999999999", "us-east-1")
	catalogTestError(t, service, foreign, "GetDatabase", get, "AccessDeniedException")
	catalogTestError(t, service, catalogTestContext("123456789012", "us-west-2"), "GetDatabase", get, "EntityNotFoundException")
	setPolicy(`[{"Effect":"Allow","Action":["glue:UpdateCatalog","s3tables:*"],"Resource":"*"}]`)
	catalogTestError(t, service, caller, "UpdateCatalog", &api.UpdateCatalogInput{CatalogId: new(api.CatalogIdString("123456789012:s3tablescatalog")), CatalogInput: create.CatalogInput}, "AccessDeniedException")
}
