package s3tables

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"

	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awswire"
	"stackd/internal/services/glue/icebergmeta"
)

// PreparedTableMetadataUpdate contains only the typed projection and its exact
// owner/CAS binding. It is prepared before entering a shared resource transaction.
// Its fields are private so callers cannot substitute unparsed schema columns.
type PreparedTableMetadataUpdate struct {
	scope                                         Scope
	bucket, namespace, name, arn, token, location string
	columns                                       []Column
}

// TableColumns reads the accepted projection under current GetTable authority.
// It never reads warehouse objects, including when joining a Glue transaction.
func (s *Service) TableColumns(ctx context.Context, bucket, namespace, name string) ([]Column, *awswire.Error) {
	var columns []Column
	err := s.repository.View(ctx, func(r Reader) error {
		table, err := s.table(r.Context(), r, "GetTable", bucket, namespace, name)
		if err != nil {
			return err
		}
		columns, err = r.TableColumns(table.Scope, table.ARN)
		return err
	})
	return columns, wireError(err)
}

func metadataColumns(metadata icebergmeta.Metadata) ([]Column, error) {
	projection, err := icebergmeta.Columns(metadata)
	if err != nil {
		return nil, invalid(err.Error())
	}
	return projection, nil
}

func parseMetadataColumns(data []byte) ([]Column, error) {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, invalid("Invalid compressed Iceberg metadata: " + err.Error())
		}
		data, err = io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil {
			return nil, invalid("Invalid compressed Iceberg metadata: " + err.Error())
		}
		if closeErr != nil {
			return nil, invalid("Invalid compressed Iceberg metadata: " + closeErr.Error())
		}
	}
	var metadata icebergmeta.Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, invalid("Invalid Iceberg metadata: " + err.Error())
	}
	return metadataColumns(metadata)
}

func metadataUpdateKey(v Table, in *api.UpdateTableMetadataLocationInput) (string, error) {
	if value(in.VersionToken) == "" {
		return "", invalid("versionToken is required")
	}
	if value(in.VersionToken) != v.VersionToken {
		return "", conflict("The table version token is stale")
	}
	location := value(in.MetadataLocation)
	key, err := warehouseKey(v.Warehouse, location)
	if err != nil {
		return "", err
	}
	return key, nil
}

// PrepareTableMetadataUpdate performs authorized external metadata IO after its
// repository view has closed. Callers must invoke it outside resource transactions.
// Publication always repeats current IAM and the version-token comparison.
func (s *Service) PrepareTableMetadataUpdate(ctx context.Context, in *api.UpdateTableMetadataLocationInput) (*PreparedTableMetadataUpdate, *awswire.Error) {
	var table Table
	var key string
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		table, err = s.table(r.Context(), r, "UpdateTableMetadataLocation", value(in.TableBucketARN), value(in.Namespace), value(in.Name))
		if err != nil {
			return err
		}
		key, err = metadataUpdateKey(table, in)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	if s.objects == nil {
		return nil, failure("InternalServerErrorException", "Table warehouse storage is unavailable", 503)
	}
	// The warehouse lock excludes object deletion while metadata is read and
	// current table authority is rechecked. It never escapes preparation.
	lock := s.warehouseLock(table.Warehouse)
	lock.Lock()
	defer lock.Unlock()
	data, err := s.objects.Read(ctx, table.Warehouse, key)
	if err != nil {
		return nil, wireError(err)
	}
	columns, err := parseMetadataColumns(data)
	if err != nil {
		return nil, wireError(err)
	}
	err = s.repository.View(ctx, func(r Reader) error {
		current, err := s.table(r.Context(), r, "UpdateTableMetadataLocation", table.BucketARN, table.Namespace, table.Name)
		if err != nil {
			return err
		}
		if current.ARN != table.ARN {
			return conflict("The table incarnation has changed")
		}
		_, err = metadataUpdateKey(current, in)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &PreparedTableMetadataUpdate{scope: table.Scope, bucket: table.BucketARN, namespace: table.Namespace, name: table.Name, arn: table.ARN, token: table.VersionToken, location: value(in.MetadataLocation), columns: columns}, nil
}

// PublishTableMetadataUpdate joins an existing resource transaction if present.
// It atomically publishes the prepared schema, pointer, token and accepted event.
func (s *Service) PublishTableMetadataUpdate(ctx context.Context, in *api.UpdateTableMetadataLocationInput, prepared *PreparedTableMetadataUpdate) (*api.UpdateTableMetadataLocationOutput, *awswire.Error) {
	return command(s, ctx, "UpdateTableMetadataLocation", in, func(ctx context.Context, tx Transaction, in *api.UpdateTableMetadataLocationInput) (*api.UpdateTableMetadataLocationOutput, error) {
		return s.updateTableMetadataLocation(ctx, tx, in, prepared)
	})
}
