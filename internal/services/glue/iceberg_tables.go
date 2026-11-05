package glue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue/icebergmeta"
)

type icebergTableResponse struct {
	MetadataLocation string               `json:"metadata-location"`
	Metadata         icebergmeta.Metadata `json:"metadata"`
	Config           map[string]string    `json:"config"`
}

type icebergTableList struct {
	Identifiers   []icebergmeta.Identifier `json:"identifiers"`
	NextPageToken string                   `json:"next-page-token,omitempty"`
}

func (s *Service) icebergListTables(r *http.Request, key DatabaseKey) (any, error) {
	binding := catalogPageBinding("IcebergListTables", key.ARN())
	after, limit, err := icebergPage(r, binding)
	if err != nil {
		return nil, err
	}
	out := icebergTableList{Identifiers: []icebergmeta.Identifier{}}
	in := &api.GetTablesInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name))}
	err = s.icebergTransaction(r.Context(), key.CatalogKey, "GetTables", in, func(ctx context.Context, tx Transaction) error {
		if err := s.authorizeDatabase(ctx, tx, "GetTables", key); err != nil {
			return err
		}
		if _, err := tx.Database(key); errors.Is(err, ErrNotFound) {
			return icebergError(404, "NoSuchNamespaceException", "Namespace does not exist.")
		} else if err != nil {
			return err
		}
		rows, err := tx.Tables(key)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Key.TableName <= after || !isIcebergTable(row.Table) {
				continue
			}
			if err := s.authorizeTable(ctx, tx, "GetTables", row.Key); err != nil {
				if wireError(err).Code == "AccessDeniedException" {
					continue
				}
				return err
			}
			if len(out.Identifiers) == limit {
				out.NextPageToken = string(*catalogNextToken(binding, out.Identifiers[len(out.Identifiers)-1].Name))
				break
			}
			out.Identifiers = append(out.Identifiers, icebergmeta.Identifier{Namespace: []string{key.Name}, Name: row.Key.TableName})
		}
		return nil
	})
	return out, err
}

func isIcebergTable(table api.Table) bool {
	return strings.EqualFold(string(table.Parameters["table_type"]), "ICEBERG") && table.Parameters["metadata_location"] != ""
}

func (s *Service) icebergReadTable(ctx context.Context, key TableKey, action string) (TableRecord, error) {
	var record TableRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorizeCatalog(ctx, tx, "GetCatalog", key.CatalogKey); err != nil {
			return err
		}
		if err := s.requireOrdinaryIcebergCatalog(ctx, tx, key.CatalogKey); err != nil {
			return err
		}
		if err := s.authorizeTable(ctx, tx, action, key); err != nil {
			return err
		}
		var err error
		record, err = tx.Table(key)
		if errors.Is(err, ErrNotFound) {
			return icebergError(404, "NoSuchTableException", "Table does not exist.")
		}
		if err != nil {
			return err
		}
		if !isIcebergTable(record.Table) {
			return icebergError(404, "NoSuchIcebergTableException", "Table is not an Iceberg table.")
		}
		return nil
	})
	return record, err
}

func (s *Service) icebergReadMetadata(ctx context.Context, record TableRecord) (icebergmeta.Metadata, error) {
	if s.icebergObjects == nil {
		return icebergmeta.Metadata{}, icebergError(503, "ServiceUnavailableException", "Iceberg metadata storage is unavailable.")
	}
	data, err := s.icebergObjects.Read(ctx, string(record.Table.Parameters["metadata_location"]))
	if err != nil {
		return icebergmeta.Metadata{}, err
	}
	var metadata icebergmeta.Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return metadata, icebergError(500, "InvalidMetadataException", "Stored Iceberg metadata is invalid.")
	}
	return metadata, nil
}

func (s *Service) icebergLoadTable(ctx context.Context, key TableKey) (any, error) {
	record, err := s.icebergReadTable(ctx, key, "GetTable")
	if err != nil {
		return nil, err
	}
	metadata, err := s.icebergReadMetadata(ctx, record)
	if err != nil {
		return nil, err
	}
	in := &api.GetTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), Name: new(api.NameString(key.TableName))}
	// Recheck current authority after external S3 work, and retain the API event
	// in the same transaction domain as ordinary Glue reads.
	err = s.icebergTransaction(ctx, key.CatalogKey, "GetTable", in, func(ctx context.Context, tx Transaction) error {
		return s.authorizeTable(ctx, tx, "GetTable", key)
	})
	return icebergTableResponse{MetadataLocation: string(record.Table.Parameters["metadata_location"]), Metadata: metadata, Config: map[string]string{}}, err
}

func (s *Service) icebergTableExists(ctx context.Context, key TableKey) error {
	in := &api.GetTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), Name: new(api.NameString(key.TableName))}
	return s.icebergTransaction(ctx, key.CatalogKey, "GetTable", in, func(ctx context.Context, tx Transaction) error {
		if err := s.authorizeTable(ctx, tx, "GetTable", key); err != nil {
			return err
		}
		record, err := tx.Table(key)
		if errors.Is(err, ErrNotFound) {
			return icebergError(404, "NoSuchTableException", "Table does not exist.")
		}
		if err == nil && !isIcebergTable(record.Table) {
			return icebergError(404, "NoSuchIcebergTableException", "Table is not an Iceberg table.")
		}
		return err
	})
}

func icebergStorageLocation(location string) error {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "s3" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return icebergError(400, "BadRequestException", "Table location must be an S3 URI.")
	}
	return nil
}

func (s *Service) icebergWriteMetadata(ctx context.Context, metadata icebergmeta.Metadata, version int64) (string, error) {
	if s.icebergObjects == nil {
		return "", icebergError(503, "ServiceUnavailableException", "Iceberg metadata storage is unavailable.")
	}
	if err := icebergStorageLocation(metadata.Location); err != nil {
		return "", err
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	location, err := icebergMetadataFileLocation(metadata.Location, version)
	if err != nil {
		return "", err
	}
	if err := s.icebergObjects.Write(ctx, location, data); err != nil {
		return "", err
	}
	return location, nil
}

func icebergMetadataFileLocation(tableLocation string, version int64) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(tableLocation, "/") + fmt.Sprintf("/metadata/%05d-%s.metadata.json", version, id), nil
}

func icebergTableInput(key TableKey, metadata icebergmeta.Metadata, location string, previous *api.Table) (*api.TableInput, error) {
	input := &api.TableInput{Name: new(api.NameString(key.TableName)), TableType: new(api.TableTypeString("EXTERNAL_TABLE")), Parameters: api.ParametersMap{}, PartitionKeys: api.ColumnList{}, StorageDescriptor: &api.StorageDescriptor{}}
	if previous != nil {
		input.Description, input.Owner, input.Retention = previous.Description, previous.Owner, previous.Retention
		input.Parameters = api.CloneParametersMap(previous.Parameters)
		if input.Parameters == nil {
			input.Parameters = api.ParametersMap{}
		}
		if previous.StorageDescriptor != nil {
			input.StorageDescriptor = new(api.CloneStorageDescriptor(*previous.StorageDescriptor))
		}
	}
	input.Parameters["table_type"] = "ICEBERG"
	input.Parameters["metadata_location"] = api.ParametersMapValue(location)
	if previous != nil {
		input.Parameters["previous_metadata_location"] = previous.Parameters["metadata_location"]
	}
	input.StorageDescriptor.Location = new(api.LocationString(metadata.Location))
	columns, err := icebergmeta.Columns(metadata)
	if err != nil {
		return nil, err
	}
	input.StorageDescriptor.Columns = make(api.ColumnList, 0, len(columns))
	for _, column := range columns {
		c := api.Column{Name: new(api.NameString(column.Name)), Type: new(api.ColumnTypeString(column.Type))}
		if column.Comment != "" {
			c.Comment = new(api.CommentString(column.Comment))
		}
		input.StorageDescriptor.Columns = append(input.StorageDescriptor.Columns, c)
	}
	return input, nil
}

func (s *Service) icebergCreateTable(ctx context.Context, database DatabaseKey, request icebergmeta.CreateRequest) (any, error) {
	if !validIcebergName(request.Name) {
		return nil, icebergError(400, "BadRequestException", "Invalid Glue table name.")
	}
	// AWS Glue supports create followed by insert, not stage-create.
	// https://docs.aws.amazon.com/glue/latest/dg/iceberg-rest-apis.html#create-table
	if request.StageCreate {
		return nil, icebergError(400, "UnsupportedOperationException", "Staged table creation is not supported.")
	}
	key := TableKey{DatabaseKey: database, TableName: request.Name}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorizeCatalog(ctx, tx, "GetCatalog", key.CatalogKey); err != nil {
			return err
		}
		if err := s.authorizeTable(ctx, tx, "CreateTable", key); err != nil {
			return err
		}
		if err := s.requireOrdinaryIcebergCatalog(ctx, tx, key.CatalogKey); err != nil {
			return err
		}
		db, err := tx.Database(database)
		if errors.Is(err, ErrNotFound) {
			return icebergError(404, "NoSuchNamespaceException", "Namespace does not exist.")
		}
		if err != nil {
			return err
		}
		if db.Database.TargetDatabase != nil || db.Database.FederatedDatabase != nil {
			return icebergError(400, "UnsupportedOperationException", "REST writes to resource links or federated databases are not supported.")
		}
		if _, err := tx.Table(key); err == nil {
			return icebergError(409, "AlreadyExistsException", "Table already exists.")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		if request.Location == "" && db.Database.LocationUri != nil {
			request.Location = strings.TrimRight(string(*db.Database.LocationUri), "/") + "/" + key.TableName
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if request.Location == "" {
		return nil, icebergError(400, "BadRequestException", "Table or namespace S3 location is required; warehouse identifies the Glue account, not S3 storage.")
	}
	if err := icebergStorageLocation(request.Location); err != nil {
		return nil, err
	}
	metadata, err := icebergmeta.New(request, s.clock.Now())
	if err != nil {
		return nil, err
	}
	location, err := s.icebergWriteMetadata(ctx, metadata, 0)
	if err != nil {
		return nil, err
	}
	input, err := icebergTableInput(key, metadata, location, nil)
	if err != nil {
		return nil, err
	}
	in := &api.CreateTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), TableInput: input}
	err = s.icebergTransaction(ctx, key.CatalogKey, "CreateTable", in, func(ctx context.Context, tx Transaction) error {
		_, err := s.createTable(ctx, tx, in)
		return err
	})
	return icebergTableResponse{MetadataLocation: location, Metadata: metadata, Config: map[string]string{}}, err
}

func (s *Service) icebergCommitTable(ctx context.Context, key TableKey, request icebergmeta.CommitRequest) (any, error) {
	if request.Identifier != nil && (len(request.Identifier.Namespace) != 1 || request.Identifier.Namespace[0] != key.Name || request.Identifier.Name != key.TableName) {
		return nil, icebergError(400, "BadRequestException", "Commit identifier does not match the REST path.")
	}
	record, err := s.icebergReadTable(ctx, key, "UpdateTable")
	if err != nil {
		return nil, err
	}
	current, err := s.icebergReadMetadata(ctx, record)
	if err != nil {
		return nil, err
	}
	metadata, err := icebergmeta.Apply(current, request, s.clock.Now())
	if err != nil {
		return nil, err
	}
	metadata.MetadataLog = append(metadata.MetadataLog, icebergmeta.MetadataLogEntry{TimestampMS: current.LastUpdatedMS, MetadataFile: string(record.Table.Parameters["metadata_location"])})
	keep := 100
	if value, ok := metadata.Properties["write.metadata.previous-versions-max"]; ok {
		keep, err = strconv.Atoi(value)
		if err != nil || keep < 0 {
			return nil, icebergError(400, "BadRequestException", "write.metadata.previous-versions-max must be nonnegative.")
		}
	}
	if len(metadata.MetadataLog) > keep {
		metadata.MetadataLog = metadata.MetadataLog[len(metadata.MetadataLog)-keep:]
	}
	location, err := s.icebergWriteMetadata(ctx, metadata, record.Version+1)
	if err != nil {
		return nil, err
	}
	input, err := icebergTableInput(key, metadata, location, &record.Table)
	if err != nil {
		return nil, err
	}
	in := &api.UpdateTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), TableInput: input, VersionId: new(api.VersionString(strconv.FormatInt(record.Version, 10)))}
	err = s.icebergTransaction(ctx, key.CatalogKey, "UpdateTable", in, func(ctx context.Context, tx Transaction) error {
		if err := s.authorizeTable(ctx, tx, "UpdateTable", key); err != nil {
			return err
		}
		latest, err := tx.Table(key)
		if err != nil {
			return err
		}
		// CAS the native Glue version AND metadata pointer, so REST writers
		// conflict correctly with both REST and ordinary Glue/Trino writers.
		if latest.Version != record.Version || latest.Table.Parameters["metadata_location"] != record.Table.Parameters["metadata_location"] || latest.Table.CreateTime == nil || record.Table.CreateTime == nil || !latest.Table.CreateTime.Equal(*record.Table.CreateTime) {
			return icebergError(409, "CommitFailedException", "Table metadata changed while committing; reload and retry.")
		}
		if err := icebergmeta.ValidateRequirements(&current, request.Requirements); err != nil {
			return err
		}
		_, err = s.updateTable(ctx, tx, in)
		return err
	})
	// Losing writers may leave an unreferenced immutable metadata file, as in
	// native Iceberg catalogs. It can never become the table's authoritative head.
	return icebergTableResponse{MetadataLocation: location, Metadata: metadata, Config: map[string]string{}}, err
}

func (s *Service) icebergDropTable(r *http.Request, key TableKey) error {
	// AWS Glue does not support purging data through this REST endpoint.
	// https://docs.aws.amazon.com/glue/latest/dg/iceberg-rest-apis.html#delete-table
	if purge := r.URL.Query().Get("purgeRequested"); purge != "" && !strings.EqualFold(purge, "false") {
		return icebergError(400, "UnsupportedOperationException", "Purging Iceberg table data is not supported.")
	}
	in := &api.DeleteTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), Name: new(api.NameString(key.TableName))}
	return s.icebergTransaction(r.Context(), key.CatalogKey, "DeleteTable", in, func(ctx context.Context, tx Transaction) error {
		if err := s.authorizeTable(ctx, tx, "DeleteTable", key); err != nil {
			return err
		}
		record, err := tx.Table(key)
		if err != nil {
			return err
		}
		if !isIcebergTable(record.Table) {
			return icebergError(404, "NoSuchIcebergTableException", "Table is not an Iceberg table.")
		}
		_, err = s.deleteTable(ctx, tx, in)
		return err
	})
}
