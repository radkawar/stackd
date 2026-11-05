package glue

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
	"stackd/internal/awswire"
	"stackd/internal/services/glue/icebergmeta"
)

// icebergFederation resolves the current mounted owner before dispatch. The
// integration parent is recognized but never becomes an ordinary Glue warehouse.
func (s *Service) icebergFederation(ctx context.Context, key CatalogKey) (bucket string, managed bool, err error) {
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if e := s.authorizeCatalog(ctx, tx, "GetCatalog", key); e != nil {
			return e
		}
		var e error
		bucket, managed, e = s.mountedBucket(ctx, tx, key)
		if e != nil || managed {
			return e
		}
		row, e := tx.Catalog(key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		managed = row.Catalog.FederatedCatalog != nil
		return nil
	})
	return
}

func (s *Service) requireOrdinaryIcebergCatalog(ctx context.Context, r Reader, key CatalogKey) error {
	if parentID, _, child := splitCatalogChild(key.CatalogID); child {
		parent := key
		parent.CatalogID = parentID
		row, e := r.Catalog(parent)
		if e == nil && row.Catalog.FederatedCatalog != nil {
			return icebergError(400, "BadRequestException", "Mounted S3 Tables catalogs require their authoritative managed REST owner.")
		}
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
	}
	if row, e := r.Catalog(key); e == nil && row.Catalog.FederatedCatalog != nil {
		return icebergError(400, "BadRequestException", "Select a mounted S3 table bucket child catalog.")
	} else if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	return s.requireCatalog(r, key)
}

func (s *Service) federatedIcebergTransaction(ctx context.Context, key CatalogKey, bucket, action string, input any, fn func(context.Context, Transaction) error) error {
	ctx, e := apievents.Reserve(ctx)
	if e != nil {
		return e
	}
	e = s.repository.Attempt(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if e := s.authorizeCatalog(ctx, tx, "GetCatalog", key); e != nil {
			return e
		}
		current, mounted, e := s.mountedBucket(ctx, tx, key)
		if e != nil {
			return e
		}
		if !mounted || current != bucket {
			return icebergError(409, "CommitFailedException", "The mounted table bucket changed.")
		}
		if e = fn(ctx, tx); e != nil {
			return e
		}
		if e = s.publishCatalogCall(ctx, action, input); e != nil {
			return e
		}
		return s.recordCall(ctx, action, input, nil, nil)
	})
	if e != nil {
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		rejected := wireError(e)
		var native *icebergmeta.Error
		if errors.As(e, &native) {
			rejected = &awswire.Error{Code: native.Type, Message: native.Message, StatusCode: native.Code}
		}
		if recorded := s.recordCall(completion, action, input, nil, rejected); recorded != nil {
			return recorded
		}
	}
	return e
}

func (s *Service) serveFederatedIceberg(r *http.Request, key CatalogKey, bucket string, route icebergRoute) (any, int, error) {
	if route.resource == "config" {
		endpoints := []string{"GET /v1/{prefix}/namespaces", "POST /v1/{prefix}/namespaces", "GET /v1/{prefix}/namespaces/{namespace}", "HEAD /v1/{prefix}/namespaces/{namespace}", "DELETE /v1/{prefix}/namespaces/{namespace}", "GET /v1/{prefix}/namespaces/{namespace}/tables", "POST /v1/{prefix}/namespaces/{namespace}/tables", "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}", "HEAD /v1/{prefix}/namespaces/{namespace}/tables/{table}", "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}", "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}"}
		if r.Method != http.MethodGet {
			return nil, 0, icebergMethodError()
		}
		if _, rejected := runCommand(s, r.Context(), "GetCatalog", &api.GetCatalogInput{CatalogId: new(api.CatalogIdString(key.CatalogID))}, s.getCatalog); rejected != nil {
			return nil, 0, rejected
		}
		return struct {
			Defaults  map[string]string `json:"defaults"`
			Overrides map[string]string `json:"overrides"`
			Endpoints []string          `json:"endpoints"`
		}{map[string]string{}, map[string]string{"prefix": "catalogs/" + url.PathEscape(key.CatalogID)}, endpoints}, http.StatusOK, nil
	}
	if bucket == "" {
		return nil, 0, icebergError(400, "BadRequestException", "Select a mounted S3 table bucket child catalog.")
	}
	switch route.resource {
	case "namespaces", "namespace", "properties":
		return s.federatedIcebergNamespace(r, key, bucket, route)
	case "tables":
		db := DatabaseKey{CatalogKey: key, Name: route.namespace}
		if r.Method == http.MethodGet {
			out, e := s.federatedIcebergListTables(r, db, bucket)
			return out, http.StatusOK, e
		}
		if r.Method == http.MethodPost {
			var in icebergmeta.CreateRequest
			if e := decodeIceberg(r, &in); e != nil {
				return nil, 0, e
			}
			out, e := s.federatedIcebergCreate(r.Context(), db, bucket, in)
			return out, http.StatusOK, e
		}
	case "table":
		table := TableKey{DatabaseKey: DatabaseKey{CatalogKey: key, Name: route.namespace}, TableName: route.table}
		switch r.Method {
		case http.MethodGet:
			out, e := s.federatedIcebergLoad(r.Context(), table, bucket)
			return out, http.StatusOK, e
		case http.MethodHead:
			_, e := runCommand(s, r.Context(), "GetTable", &api.GetTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(table.Name)), Name: new(api.NameString(table.TableName))}, s.getTable)
			return nil, http.StatusNoContent, federationError(e)
		case http.MethodPost:
			var in icebergmeta.CommitRequest
			if e := decodeIceberg(r, &in); e != nil {
				return nil, 0, e
			}
			out, e := s.federatedIcebergCommit(r.Context(), table, bucket, in)
			return out, http.StatusOK, e
		case http.MethodDelete:
			if !strings.EqualFold(r.URL.Query().Get("purgeRequested"), "true") {
				return nil, 0, icebergError(400, "UnsupportedOperationException", "S3 Tables requires purgeRequested=true when dropping a managed table.")
			}
			_, e := runCommand(s, r.Context(), "DeleteTable", &api.DeleteTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(table.Name)), Name: new(api.NameString(table.TableName))}, s.deleteTable)
			return nil, http.StatusNoContent, federationError(e)
		}
	}
	return nil, 0, icebergMethodError()
}

func (s *Service) federatedIcebergNamespace(r *http.Request, key CatalogKey, bucket string, route icebergRoute) (any, int, error) {
	ctx := r.Context()
	id := new(api.CatalogIdString(key.CatalogID))
	name := new(api.NameString(route.namespace))
	switch {
	case route.resource == "namespaces" && r.Method == http.MethodGet:
		if parent := r.URL.Query().Get("parent"); parent != "" {
			if !validIcebergName(parent) {
				return nil, 0, icebergError(400, "BadRequestException", "S3 Tables supports single-level namespaces.")
			}
			_, e := runCommand(s, ctx, "GetDatabase", &api.GetDatabaseInput{CatalogId: id, Name: new(api.NameString(parent))}, s.getDatabase)
			return icebergNamespaceList{Namespaces: [][]string{}}, http.StatusOK, federatedNamespaceError(e)
		}
		binding := catalogPageBinding("IcebergListNamespaces", key.ARN(), "")
		after, limit, e := icebergPage(r, binding)
		if e != nil {
			return nil, 0, e
		}
		out := icebergNamespaceList{Namespaces: [][]string{}}
		in := &api.GetDatabasesInput{CatalogId: id}
		for {
			page, rejected := runCommand(s, ctx, "GetDatabases", in, s.getDatabases)
			if rejected != nil {
				return nil, 0, rejected
			}
			for _, db := range page.DatabaseList {
				n := value(db.Name)
				if n <= after {
					continue
				}
				if len(out.Namespaces) == limit {
					out.NextPageToken = string(*catalogNextToken(binding, out.Namespaces[len(out.Namespaces)-1][0]))
					return out, http.StatusOK, nil
				}
				out.Namespaces = append(out.Namespaces, []string{n})
			}
			in.NextToken = page.NextToken
			if in.NextToken == nil {
				break
			}
		}
		return out, http.StatusOK, nil
	case route.resource == "namespaces" && r.Method == http.MethodPost:
		var in icebergNamespaceRequest
		if e := decodeIceberg(r, &in); e != nil {
			return nil, 0, e
		}
		if len(in.Namespace) != 1 || !validIcebergName(in.Namespace[0]) {
			return nil, 0, icebergError(400, "BadRequestException", "S3 Tables requires one lowercase namespace name.")
		}
		if len(in.Properties) > 0 {
			return nil, 0, icebergError(400, "UnsupportedOperationException", "S3 Tables namespace properties are managed by the table bucket owner.")
		}
		_, e := runCommand(s, ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: id, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString(in.Namespace[0]))}}, s.createDatabase)
		return icebergNamespaceResponse{Namespace: in.Namespace, Properties: map[string]string{}}, http.StatusOK, federationError(e)
	case route.resource == "namespace" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		_, e := runCommand(s, ctx, "GetDatabase", &api.GetDatabaseInput{CatalogId: id, Name: name}, s.getDatabase)
		status := http.StatusOK
		if r.Method == http.MethodHead {
			status = http.StatusNoContent
			return nil, status, federatedNamespaceError(e)
		}
		return icebergNamespaceResponse{Namespace: []string{route.namespace}, Properties: map[string]string{}}, status, federatedNamespaceError(e)
	case route.resource == "namespace" && r.Method == http.MethodDelete:
		_, e := runCommand(s, ctx, "DeleteDatabase", &api.DeleteDatabaseInput{CatalogId: id, Name: name}, s.deleteDatabase)
		return nil, http.StatusNoContent, federatedNamespaceError(e)
	default:
		return nil, 0, icebergMethodError()
	}
}

func (s *Service) federatedIcebergListTables(r *http.Request, key DatabaseKey, bucket string) (any, error) {
	if _, rejected := runCommand(s, r.Context(), "GetDatabase", &api.GetDatabaseInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), Name: new(api.NameString(key.Name))}, s.getDatabase); rejected != nil {
		return nil, federatedNamespaceError(rejected)
	}
	binding := catalogPageBinding("IcebergListTables", key.ARN())
	after, limit, e := icebergPage(r, binding)
	if e != nil {
		return nil, e
	}
	out := icebergTableList{Identifiers: []icebergmeta.Identifier{}}
	in := &api.GetTablesInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name))}
	for {
		page, rejected := runCommand(s, r.Context(), "GetTables", in, s.getTables)
		if rejected != nil {
			return nil, rejected
		}
		for _, table := range page.TableList {
			n := value(table.Name)
			if n <= after {
				continue
			}
			if len(out.Identifiers) == limit {
				out.NextPageToken = string(*catalogNextToken(binding, out.Identifiers[len(out.Identifiers)-1].Name))
				return out, nil
			}
			out.Identifiers = append(out.Identifiers, icebergmeta.Identifier{Namespace: []string{key.Name}, Name: n})
		}
		in.NextToken = page.NextToken
		if in.NextToken == nil {
			break
		}
	}
	return out, nil
}

func (s *Service) federatedIcebergSnapshot(ctx context.Context, key TableKey) (*api.Table, error) {
	out, e := runCommand(s, ctx, "GetTable", &api.GetTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), Name: new(api.NameString(key.TableName))}, s.getTable)
	if e != nil {
		return nil, e
	}
	if out == nil || out.Table == nil {
		return nil, ErrNotFound
	}
	return out.Table, nil
}
func (s *Service) federatedIcebergMetadata(ctx context.Context, table *api.Table) (icebergmeta.Metadata, error) {
	var metadata icebergmeta.Metadata
	data, e := s.s3Tables.Read(ctx, string(table.Parameters["metadata_location"]))
	if e != nil {
		return metadata, e
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return metadata, icebergError(500, "InvalidMetadataException", "Stored Iceberg metadata compression is invalid.")
		}
		data, e = io.ReadAll(io.LimitReader(reader, (50<<20)+1))
		closeErr := reader.Close()
		if e != nil {
			return metadata, e
		}
		if closeErr != nil {
			return metadata, closeErr
		}
		if len(data) > 50<<20 {
			return metadata, icebergError(400, "BadRequestException", "Iceberg metadata exceeds 50 MiB.")
		}
	}
	if e = json.Unmarshal(data, &metadata); e != nil {
		return metadata, icebergError(500, "InvalidMetadataException", "Stored Iceberg metadata is invalid.")
	}
	return metadata, nil
}
func (s *Service) federatedIcebergLoad(ctx context.Context, key TableKey, bucket string) (any, error) {
	table, e := s.federatedIcebergSnapshot(ctx, key)
	if e != nil {
		return nil, e
	}
	metadata, e := s.federatedIcebergMetadata(ctx, table)
	if e != nil {
		return nil, e
	}
	e = s.federatedIcebergTransaction(ctx, key.CatalogKey, bucket, "GetTable", &api.GetTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), Name: new(api.NameString(key.TableName))}, func(ctx context.Context, tx Transaction) error {
		if e := s.authorizeTable(ctx, tx, "GetTable", key); e != nil {
			return e
		}
		current, rejected := s.s3Tables.GetTable(ctx, &tables.GetTableInput{TableBucketARN: new(tables.TableBucketARN(bucket)), Namespace: new(tables.NamespaceName(key.Name)), Name: new(tables.TableName(key.TableName))})
		if rejected != nil {
			return federationError(rejected)
		}
		if value(current.WarehouseLocation) != metadata.Location {
			return icebergError(409, "CommitFailedException", "The managed table incarnation changed while reading metadata.")
		}
		return nil
	})
	return icebergTableResponse{MetadataLocation: string(table.Parameters["metadata_location"]), Metadata: metadata, Config: map[string]string{}}, e
}

func (s *Service) federatedIcebergCreate(ctx context.Context, key DatabaseKey, bucket string, request icebergmeta.CreateRequest) (any, error) {
	if request.StageCreate {
		return nil, icebergError(400, "UnsupportedOperationException", "Staged table creation is not supported.")
	}
	if !validIcebergName(request.Name) || request.Location != "" {
		return nil, icebergError(400, "BadRequestException", "S3 Tables assigns the managed table location; specify a valid table name without location.")
	}
	in := &tables.CreateTableInput{TableBucketARN: new(tables.TableBucketARN(bucket)), Namespace: new(tables.NamespaceName(key.Name)), Name: new(tables.TableName(request.Name)), Format: new(tables.OpenTableFormatICEBERG), Metadata: &tables.TableMetadata{Iceberg: &tables.IcebergMetadata{SchemaV2: &tables.IcebergSchemaV2{}, Properties: tables.TableProperties{}}}}
	convert := func(source, target any) error {
		data, e := json.Marshal(source)
		if e != nil {
			return e
		}
		return json.Unmarshal(data, target)
	}
	if e := convert(request.Schema, in.Metadata.Iceberg.SchemaV2); e != nil {
		return nil, e
	}
	if request.PartitionSpec != nil {
		in.Metadata.Iceberg.PartitionSpec = &tables.IcebergPartitionSpec{}
		if e := convert(request.PartitionSpec, in.Metadata.Iceberg.PartitionSpec); e != nil {
			return nil, e
		}
	}
	if request.WriteOrder != nil {
		in.Metadata.Iceberg.WriteOrder = &tables.IcebergSortOrder{}
		if e := convert(request.WriteOrder, in.Metadata.Iceberg.WriteOrder); e != nil {
			return nil, e
		}
	}
	for k, v := range request.Properties {
		in.Metadata.Iceberg.Properties[tables.String(k)] = tables.String(v)
	}
	table := TableKey{DatabaseKey: key, TableName: request.Name}
	glueInput := &api.CreateTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), TableInput: &api.TableInput{Name: new(api.NameString(request.Name))}}
	if e := s.repository.Attempt(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if e := s.authorizeCatalog(ctx, tx, "GetCatalog", key.CatalogKey); e != nil {
			return e
		}
		mounted, found, e := s.mountedBucket(ctx, tx, key.CatalogKey)
		if e != nil {
			return e
		}
		if !found || mounted != bucket {
			return icebergError(409, "CommitFailedException", "The mounted table bucket changed.")
		}
		return s.authorizeTable(ctx, tx, "CreateTable", table)
	}); e != nil {
		return nil, e
	}
	prepared, rejected := s.s3Tables.PrepareTableCreate(ctx, in)
	if rejected != nil {
		return nil, federationError(rejected)
	}
	e := s.federatedIcebergTransaction(ctx, key.CatalogKey, bucket, "CreateTable", glueInput, func(ctx context.Context, tx Transaction) error {
		if e := s.authorizeTable(ctx, tx, "CreateTable", table); e != nil {
			return e
		}
		_, rejected := s.s3Tables.PublishTableCreate(ctx, in, prepared)
		return federationError(rejected)
	})
	if e != nil {
		if cleanup := s.s3Tables.DiscardTableCreate(ctx, prepared); cleanup != nil {
			return nil, fmt.Errorf("%w; discard uncommitted table metadata: %v", e, cleanup)
		}
		return nil, e
	}
	return s.federatedIcebergLoad(ctx, table, bucket)
}

func (s *Service) federatedIcebergCommit(ctx context.Context, key TableKey, bucket string, request icebergmeta.CommitRequest) (any, error) {
	if request.Identifier != nil && (len(request.Identifier.Namespace) != 1 || request.Identifier.Namespace[0] != key.Name || request.Identifier.Name != key.TableName) {
		return nil, icebergError(400, "BadRequestException", "Commit identifier does not match the REST path.")
	}
	table, e := s.federatedIcebergSnapshot(ctx, key)
	if e != nil {
		return nil, e
	}
	current, e := s.federatedIcebergMetadata(ctx, table)
	if e != nil {
		return nil, e
	}
	metadata, e := icebergmeta.Apply(current, request, s.clock.Now())
	if e != nil {
		return nil, e
	}
	if metadata.Location != current.Location {
		return nil, icebergError(400, "BadRequestException", "S3 Tables cannot move a table outside its managed warehouse.")
	}
	metadata.MetadataLog = append(metadata.MetadataLog, icebergmeta.MetadataLogEntry{TimestampMS: current.LastUpdatedMS, MetadataFile: string(table.Parameters["metadata_location"])})
	keep := 100
	if raw, ok := metadata.Properties["write.metadata.previous-versions-max"]; ok {
		keep, e = strconv.Atoi(raw)
		if e != nil || keep < 0 {
			return nil, icebergError(400, "BadRequestException", "write.metadata.previous-versions-max must be nonnegative.")
		}
	}
	if len(metadata.MetadataLog) > keep {
		metadata.MetadataLog = metadata.MetadataLog[len(metadata.MetadataLog)-keep:]
	}
	data, e := json.Marshal(metadata)
	if e != nil {
		return nil, e
	}
	version, e := icebergNextMetadataVersion(string(table.Parameters["metadata_location"]))
	if e != nil {
		return nil, e
	}
	location, e := icebergMetadataFileLocation(metadata.Location, version)
	if e != nil {
		return nil, e
	}
	// Writes go to the managed owner, never ordinary S3. Immutable losing files
	// may remain unreferenced, but cannot replace an authoritative metadata head.
	if e = s.s3Tables.Write(ctx, location, data); e != nil {
		return nil, e
	}
	in := &tables.UpdateTableMetadataLocationInput{TableBucketARN: new(tables.TableBucketARN(bucket)), Namespace: new(tables.NamespaceName(key.Name)), Name: new(tables.TableName(key.TableName)), VersionToken: new(tables.VersionToken(value(table.VersionId))), MetadataLocation: new(tables.MetadataLocation(location))}
	prepared, rejected := s.s3Tables.PrepareTableMetadataUpdate(ctx, in)
	if rejected != nil {
		return nil, federationError(rejected)
	}
	glueInput, e := icebergTableInput(key, metadata, location, table)
	if e != nil {
		return nil, e
	}
	e = s.federatedIcebergTransaction(ctx, key.CatalogKey, bucket, "UpdateTable", &api.UpdateTableInput{CatalogId: new(api.CatalogIdString(key.CatalogID)), DatabaseName: new(api.NameString(key.Name)), TableInput: glueInput, VersionId: table.VersionId}, func(ctx context.Context, tx Transaction) error {
		if e := s.authorizeTable(ctx, tx, "UpdateTable", key); e != nil {
			return e
		}
		if e := icebergmeta.ValidateRequirements(&current, request.Requirements); e != nil {
			return e
		}
		_, rejected := s.s3Tables.PublishTableMetadataUpdate(ctx, in, prepared)
		return federationError(rejected)
	})
	return icebergTableResponse{MetadataLocation: location, Metadata: metadata, Config: map[string]string{}}, e
}

// Iceberg's BaseMetastoreTableOperations starts at version zero when a previous
// filename has no numeric catalog version. Follow its versioned UUID convention
// so the native Glue connector can read REST commits and continue writing them.
// https://github.com/apache/iceberg/blob/main/core/src/main/java/org/apache/iceberg/BaseMetastoreTableOperations.java
func icebergNextMetadataVersion(location string) (int64, error) {
	filename := location[strings.LastIndexByte(location, '/')+1:]
	prefix, _, found := strings.Cut(filename, "-")
	if !found {
		return 0, nil
	}
	version, err := strconv.ParseInt(prefix, 10, 32)
	if err != nil || version < 0 {
		return 0, nil
	}
	if version == (1<<31)-1 {
		return 0, icebergError(400, "BadRequestException", "Metadata filename version exceeds the native catalog limit.")
	}
	return version + 1, nil
}

func federatedNamespaceError(err *awswire.Error) error {
	if err == nil {
		return nil
	}
	switch err.Code {
	case "EntityNotFoundException":
		return icebergError(404, "NoSuchNamespaceException", "The managed namespace does not exist.")
	case "ConcurrentModificationException":
		return icebergError(409, "NamespaceNotEmptyException", "The managed namespace still contains tables.")
	default:
		return err
	}
}
