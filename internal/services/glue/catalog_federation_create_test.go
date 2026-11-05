package glue_test

import (
	"encoding/json"
	"strings"
	"testing"

	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
	"stackd/internal/services/glue"
	owner "stackd/internal/services/s3tables"
	"stackd/storage/memory"
	warehouses "stackd/storage/s3tables"
)

// The first fixture is the AWS CLI TableInput example, not OpenTableFormatInput
// or a caller-selected metadata location.
// https://docs.aws.amazon.com/lake-formation/latest/dg/create-databases-tables-s3-catalog.html
func TestS3TablesFederationCreatesDocumentedNativeSchema(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	tableOwner := owner.New(owner.Config{Repository: owner.NewMemoryRepository(domain), Objects: warehouses.NewMemoryObjects(domain)})
	bucket, rejected := tableOwner.CreateTableBucket(ctx, &tables.CreateTableBucketInput{Name: new(tables.TableBucketName("native-schema"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	service := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), S3Tables: tableOwner})
	defer service.Close()
	catalogTestCall[api.CreateCatalogOutput](t, service, ctx, "CreateCatalog", &api.CreateCatalogInput{Name: new(api.CatalogNameString("s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: &api.FederatedCatalog{ConnectionName: new(api.NameString("aws:s3tables")), Identifier: new(api.FederationIdentifier(string(*bucket.Arn)))}}})
	id := new(api.CatalogIdString("123456789012:s3tablescatalog/native-schema"))
	catalogTestCall[api.CreateDatabaseOutput](t, service, ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: id, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("testglueclidbcreation"))}})
	fixtures := []struct {
		name, input string
		types       []string
		required    []bool
	}{
		{"documented", `{"Name":"testtablegluecli","Parameters":{"format":"ICEBERG"},"StorageDescriptor":{"Columns":[{"Name":"x","Type":"int","Parameters":{"required":"true"}}]}}`, []string{"int"}, []bool{true}},
		{"modeled-zero-defaults", `{"Name":"defaults","Retention":0,"Parameters":{"format":"ICEBERG"},"StorageDescriptor":{"Compressed":false,"NumberOfBuckets":0,"StoredAsSubDirectories":false,"Columns":[{"Name":"id","Type":"bigint","Parameters":{"required":"true"}}]}}`, []string{"long"}, []bool{true}},
		{"primitive-schema", `{"Name":"primitives","Parameters":{"format":"ICEBERG"},"StorageDescriptor":{"Columns":[{"Name":"id","Type":"bigint","Parameters":{"required":"true"}},{"Name":"optional","Type":"string","Parameters":{"required":"false"},"Comment":"preserved comment"},{"Name":"flag","Type":"boolean"},{"Name":"ratio","Type":"float"},{"Name":"amount","Type":"double"},{"Name":"day","Type":"date"},{"Name":"created","Type":"timestamp"},{"Name":"payload","Type":"binary"}]}}`, []string{"long", "string", "boolean", "float", "double", "date", "timestamp", "binary"}, []bool{true, false, false, false, false, false, false, false}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			var input api.TableInput
			if err := json.Unmarshal([]byte(fixture.input), &input); err != nil {
				t.Fatal(err)
			}
			catalogTestCall[api.CreateTableOutput](t, service, ctx, "CreateTable", &api.CreateTableInput{CatalogId: id, DatabaseName: new(api.NameString("testglueclidbcreation")), TableInput: &input})
			table, rejected := tableOwner.GetTable(ctx, &tables.GetTableInput{TableBucketARN: bucket.Arn, Namespace: new(tables.NamespaceName("testglueclidbcreation")), Name: new(tables.TableName(string(*input.Name)))})
			if rejected != nil {
				t.Fatal(rejected)
			}
			warehouse, location := catalogTestValue(table.WarehouseLocation), catalogTestValue(table.MetadataLocation)
			if !strings.HasSuffix(warehouse, "--table-s3") || !strings.HasPrefix(location, warehouse+"/metadata/") {
				t.Fatalf("table metadata is not in its managed warehouse: warehouse=%q metadata=%q", warehouse, location)
			}
			data, err := tableOwner.Read(ctx, location)
			if err != nil {
				t.Fatal(err)
			}
			var metadata struct {
				Location string `json:"location"`
				Schemas  []struct {
					Fields []struct {
						ID       int    `json:"id"`
						Name     string `json:"name"`
						Type     string `json:"type"`
						Required bool   `json:"required"`
						Doc      string `json:"doc"`
					} `json:"fields"`
				} `json:"schemas"`
			}
			if err := json.Unmarshal(data, &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.Location != warehouse || len(metadata.Schemas) != 1 || len(metadata.Schemas[0].Fields) != len(fixture.types) {
				t.Fatalf("unexpected initial metadata: %s", data)
			}
			for index, field := range metadata.Schemas[0].Fields {
				if field.ID != index+1 || field.Name != string(*input.StorageDescriptor.Columns[index].Name) || field.Type != fixture.types[index] || field.Required != fixture.required[index] || field.Doc != catalogTestValue(input.StorageDescriptor.Columns[index].Comment) {
					t.Fatalf("column %d did not preserve its schema: %+v", index, field)
				}
			}
			projected := catalogTestCall[api.GetTableOutput](t, service, ctx, "GetTable", &api.GetTableInput{CatalogId: id, DatabaseName: new(api.NameString("testglueclidbcreation")), Name: input.Name})
			if string(projected.Table.Parameters["metadata_location"]) != location || catalogTestValue(projected.Table.StorageDescriptor.Location) != warehouse || len(projected.Table.StorageDescriptor.Columns) != len(fixture.types) {
				t.Fatal("native creation was not visible through the authoritative Glue projection")
			}
		})
	}
}

func TestS3TablesFederationRejectsUnrepresentableNativeCreateFields(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	objects := &federationCreateObjects{WarehouseObjects: warehouses.NewMemoryObjects(domain)}
	repository := owner.NewMemoryRepository(domain)
	tableOwner := owner.New(owner.Config{Repository: repository, Objects: objects})
	bucket, rejected := tableOwner.CreateTableBucket(ctx, &tables.CreateTableBucketInput{Name: new(tables.TableBucketName("native-rejections"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	service := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), S3Tables: tableOwner})
	defer service.Close()
	catalogTestCall[api.CreateCatalogOutput](t, service, ctx, "CreateCatalog", &api.CreateCatalogInput{Name: new(api.CatalogNameString("s3tablescatalog")), CatalogInput: &api.CatalogInput{FederatedCatalog: &api.FederatedCatalog{ConnectionName: new(api.NameString("aws:s3tables")), Identifier: new(api.FederationIdentifier(string(*bucket.Arn)))}}})
	id := new(api.CatalogIdString("123456789012:s3tablescatalog/native-rejections"))
	catalogTestCall[api.CreateDatabaseOutput](t, service, ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: id, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("analytics"))}})
	for _, fixture := range []struct {
		name   string
		mutate func(*api.CreateTableInput)
	}{
		{"location", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.Location = new(api.LocationString("s3://caller-selected/location"))
		}},
		{"metadata-location", func(in *api.CreateTableInput) {
			in.TableInput.Parameters["metadata_location"] = "s3://existing/metadata/existing.metadata.json"
		}},
		{"table-property", func(in *api.CreateTableInput) { in.TableInput.Parameters["unmapped"] = "value" }},
		{"column-property", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.Columns[0].Parameters["unmapped"] = "value"
		}},
		{"required-value", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.Columns[0].Parameters["required"] = "not-a-boolean"
		}},
		{"nested-type", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.Columns[0].Type = new(api.ColumnTypeString("array<int>"))
		}},
		{"partitions", func(in *api.CreateTableInput) {
			in.TableInput.PartitionKeys = api.ColumnList{{Name: new(api.NameString("day")), Type: new(api.ColumnTypeString("date"))}}
		}},
		{"hive-storage", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.InputFormat = new(api.FormatString("unsupported.HiveInputFormat"))
		}},
		{"retention", func(in *api.CreateTableInput) {
			in.TableInput.Retention = new(api.NonNegativeInteger(1))
		}},
		{"compressed", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.Compressed = new(api.Boolean(true))
		}},
		{"bucket-count", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.NumberOfBuckets = new(api.Integer(1))
		}},
		{"subdirectories", func(in *api.CreateTableInput) {
			in.TableInput.StorageDescriptor.StoredAsSubDirectories = new(api.Boolean(true))
		}},
		{"open-format", func(in *api.CreateTableInput) { in.OpenTableFormatInput = &api.OpenTableFormatInput{} }},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			input := &api.CreateTableInput{CatalogId: id, DatabaseName: new(api.NameString("analytics")), TableInput: &api.TableInput{Name: new(api.NameString("events")), Parameters: api.ParametersMap{"format": "ICEBERG"}, StorageDescriptor: &api.StorageDescriptor{Columns: api.ColumnList{{Name: new(api.NameString("x")), Type: new(api.ColumnTypeString("int")), Parameters: api.ParametersMap{"required": "true"}}}}}}
			fixture.mutate(input)
			catalogTestError(t, service, ctx, "CreateTable", input, "InvalidInputException")
		})
	}
	if objects.writes != 0 || objects.deletes != 0 {
		t.Fatalf("rejected fields touched warehouse objects: writes=%d deletes=%d", objects.writes, objects.deletes)
	}
	if err := repository.View(ctx, func(r owner.Reader) error {
		rows, err := r.Tables(owner.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, string(*bucket.Arn))
		if err == nil && len(rows) != 0 {
			t.Fatal("rejected fields allocated table or warehouse ownership")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
