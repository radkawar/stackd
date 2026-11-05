package glue

import (
	"context"
	"reflect"
	"strings"

	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
	managed "stackd/internal/services/s3tables"
)

type federatedCreateContextKey struct{}

type federatedCreatePublication struct {
	catalog  CatalogKey
	input    *tables.CreateTableInput
	prepared *managed.PreparedTableCreate
}

func matchesFederatedCreate(publication *federatedCreatePublication, catalog CatalogKey, input *tables.CreateTableInput) bool {
	return publication != nil && publication.catalog == catalog && reflect.DeepEqual(publication.input, input)
}

// prepareFederatedCreate implements the documented Glue TableInput creation
// shape, not existing-metadata registration or general Glue open-format DDL.
// Warehouse bytes are prepared only after the authorization transaction ends.
// https://docs.aws.amazon.com/lake-formation/latest/dg/create-databases-tables-s3-catalog.html
func (s *Service) prepareFederatedCreate(ctx context.Context, in *api.CreateTableInput) (context.Context, error) {
	var publication federatedCreatePublication
	var mounted bool
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		key, db, _, selected := federationInputKey(tx.Context(), in)
		if !selected {
			return nil
		}
		bucket, found, err := s.mountedBucket(tx.Context(), tx, key)
		if err != nil {
			return err
		}
		mounted = found
		if !found {
			return nil
		}
		name := value(in.Name)
		if in.TableInput != nil {
			name = value(in.TableInput.Name)
		}
		if err := s.authorizeTable(tx.Context(), tx, "CreateTable", TableKey{DatabaseKey: db, TableName: strings.ToLower(name)}); err != nil {
			return err
		}
		publication.catalog = key
		publication.input, err = federatedCreateInput(in, bucket, db)
		return err
	})
	if err != nil || !mounted {
		return ctx, err
	}
	prepared, rejected := s.s3Tables.PrepareTableCreate(ctx, publication.input)
	if rejected != nil {
		return ctx, federationError(rejected)
	}
	publication.prepared = prepared
	return context.WithValue(ctx, federatedCreateContextKey{}, &publication), nil
}

// discardFederatedCreate runs after the outer catalog transaction ends, on both
// success and failure. The owner preserves admitted metadata and removes only
// unadmitted candidate bytes, including after an outer transaction rollback.
func (s *Service) discardFederatedCreate(ctx context.Context) error {
	publication, ok := ctx.Value(federatedCreateContextKey{}).(*federatedCreatePublication)
	if !ok {
		return nil
	}
	return s.s3Tables.DiscardTableCreate(ctx, publication.prepared)
}

// federatedCreateInput accepts only fields represented by owner-managed Iceberg
// metadata. It never drops a caller's location, properties, partitions or views.
func federatedCreateInput(in *api.CreateTableInput, bucket string, db DatabaseKey) (*tables.CreateTableInput, error) {
	if err := validateTableInput(in.TableInput); err != nil {
		return nil, err
	}
	table := in.TableInput
	if _, supplied := table.Parameters["metadata_location"]; supplied {
		return nil, unsupported("S3 Tables CreateTable cannot adopt an existing metadata_location. Supply format ICEBERG and schema columns without a location.")
	}
	if in.TransactionId != nil || in.OpenTableFormatInput != nil || len(in.PartitionIndexes) > 0 || (in.Name != nil && !strings.EqualFold(value(in.Name), value(table.Name))) {
		return nil, unsupported("S3 Tables native creation requires TableInput schema columns, without Glue transactions, open-format input or partition indexes.")
	}
	if table.Parameters["format"] != "ICEBERG" {
		return nil, failure("InvalidInputException", "S3 Tables native creation requires TableInput.Parameters.format to be ICEBERG.")
	}
	if len(table.Parameters) != 1 || len(table.PartitionKeys) > 0 || table.TargetTable != nil || table.ViewDefinition != nil || table.ViewExpandedText != nil || table.ViewOriginalText != nil || table.Description != nil || table.LastAccessTime != nil || table.LastAnalyzedTime != nil || table.Owner != nil || (table.Retention != nil && *table.Retention != 0) || (table.TableType != nil && value(table.TableType) != "EXTERNAL_TABLE") {
		return nil, unsupported("S3 Tables native creation does not support these Glue table properties, Hive partitions, resource links or views.")
	}
	columns := api.ColumnList{}
	if descriptor := table.StorageDescriptor; descriptor != nil {
		if descriptor.Location != nil {
			return nil, unsupported("S3 Tables assigns the table warehouse; a caller-supplied Location is not supported.")
		}
		// Smithy defaults are materialized by public request binding even when
		// the SDK omits these members. Accept only their modeled zero values,
		// then compare the complete descriptor to reject real Hive features.
		allowed := &api.StorageDescriptor{Columns: descriptor.Columns}
		if descriptor.Compressed != nil && !bool(*descriptor.Compressed) {
			allowed.Compressed = descriptor.Compressed
		}
		if descriptor.NumberOfBuckets != nil && *descriptor.NumberOfBuckets == 0 {
			allowed.NumberOfBuckets = descriptor.NumberOfBuckets
		}
		if descriptor.StoredAsSubDirectories != nil && !bool(*descriptor.StoredAsSubDirectories) {
			allowed.StoredAsSubDirectories = descriptor.StoredAsSubDirectories
		}
		if !reflect.DeepEqual(descriptor, allowed) {
			return nil, unsupported("S3 Tables native creation accepts only StorageDescriptor.Columns, not Hive storage configuration.")
		}
		columns = descriptor.Columns
	}
	schema := &tables.IcebergSchemaV2{Type: new(tables.SchemaV2FieldTypeSTRUCT), Fields: tables.SchemaV2FieldList{}}
	for index, column := range columns {
		if value(column.Name) == "" {
			return nil, failure("InvalidInputException", "Each S3 Tables schema column requires a name.")
		}
		typ, err := federatedCreateColumnType(value(column.Type))
		if err != nil {
			return nil, err
		}
		required := false
		for key, flag := range column.Parameters {
			if key != "required" || (flag != "true" && flag != "false") {
				return nil, unsupported("S3 Tables schema columns accept only the required parameter with value true or false.")
			}
			required = flag == "true"
		}
		field := tables.SchemaV2Field{Id: new(tables.Integer(index + 1)), Name: new(tables.String(value(column.Name))), Type: typ, Required: new(tables.Boolean(required))}
		if column.Comment != nil {
			field.Doc = new(tables.String(value(column.Comment)))
		}
		schema.Fields = append(schema.Fields, field)
	}
	return &tables.CreateTableInput{TableBucketARN: new(tables.TableBucketARN(bucket)), Namespace: new(tables.NamespaceName(db.Name)), Name: new(tables.TableName(strings.ToLower(value(table.Name)))), Format: new(tables.OpenTableFormatICEBERG), Metadata: &tables.TableMetadata{Iceberg: &tables.IcebergMetadata{SchemaV2: schema}}}, nil
}

func federatedCreateColumnType(name string) (string, error) {
	// These exact primitive types have a lossless Hive-to-Iceberg mapping.
	// Nested and parameterized Hive types require a native type parser; do not
	// approximate them with punctuation matching or convert them to strings.
	switch name {
	case "boolean", "int", "float", "double", "date", "timestamp", "string", "binary":
		return name, nil
	case "bigint":
		return "long", nil
	default:
		return "", unsupported("This Hive column type is not supported by S3 Tables native provisioning; use typed S3 Tables metadata or Iceberg REST.")
	}
}
