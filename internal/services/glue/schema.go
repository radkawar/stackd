package glue

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/glue"
)

func registryCompatibility(mode string) error {
	switch mode {
	case "NONE", "DISABLED", "BACKWARD", "BACKWARD_ALL", "FORWARD", "FORWARD_ALL", "FULL", "FULL_ALL":
		return nil
	default:
		return failure("InvalidInputException", "Invalid schema compatibility mode")
	}
}
func (s *Service) createSchema(ctx context.Context, tx Transaction, in *api.CreateSchemaInput) (*api.CreateSchemaResponse, error) {
	rk, err := registryKey(scopeFor(ctx), in.RegistryId, true)
	if err != nil {
		return nil, err
	}
	key := SchemaKey{Scope: rk.Scope, Registry: rk.Name, Name: value(in.SchemaName)}
	if !registryNamePattern.MatchString(key.Name) {
		return nil, failure("InvalidInputException", "Invalid schema name")
	}
	tags, err := registryTags(in.Tags)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, tx, "CreateSchema", key.Scope, key.ARN(), tags); err != nil {
		return nil, err
	}
	registry, registryErr := tx.Registry(rk)
	if registryErr != nil && !errors.Is(registryErr, ErrNotFound) {
		return nil, registryErr
	}
	if err := s.authorizeWithConditions(ctx, tx, "CreateSchema", key.Scope, rk.ARN("registry"), registry.Tags, requestTagConditions(tags)); err != nil {
		return nil, err
	}
	if _, err := tx.Schema(key); err == nil {
		return nil, failure("AlreadyExistsException", "Schema already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	mode := value(in.Compatibility)
	if err := registryCompatibility(mode); err != nil {
		return nil, err
	}
	format := value(in.DataFormat)
	if format != "AVRO" && format != "JSON" && format != "PROTOBUF" {
		return nil, failure("InvalidInputException", "DataFormat must be AVRO, JSON or PROTOBUF")
	}
	parsed, err := parseRegistrySchema(ctx, format, value(in.SchemaDefinition))
	if err != nil {
		return nil, failure("InvalidInputException", err.Error())
	}
	now := s.clock.Now().UTC()
	if errors.Is(registryErr, ErrNotFound) && in.RegistryId == nil {
		registry = RegistryRecord{Key: rk, Status: "AVAILABLE", Created: now, Updated: now}
		if err := tx.PutRegistry(registry); err != nil {
			return nil, err
		}
	} else if registryErr != nil {
		return nil, registryErr
	}
	if err := registryAvailable(registry.Status); err != nil {
		return nil, err
	}
	v := SchemaRecord{Key: key, Description: registryDescription(in.Description), DataFormat: format, Compatibility: mode, Status: "AVAILABLE", Checkpoint: 1, LatestVersion: 1, NextVersion: 2, Created: now, Updated: now, Tags: tags}
	version := SchemaVersionRecord{Key: SchemaVersionKey{Schema: key, Number: 1}, ID: uuid.NewString(), Definition: value(in.SchemaDefinition), Canonical: parsed.canonical, Status: "AVAILABLE", Created: now}
	if err := tx.PutSchema(v); err != nil {
		return nil, err
	}
	if err := tx.PutSchemaVersion(version); err != nil {
		return nil, err
	}
	return &api.CreateSchemaResponse{RegistryArn: new(api.GlueResourceArn(rk.ARN("registry"))), RegistryName: new(api.SchemaRegistryNameString(key.Registry)), SchemaArn: new(api.GlueResourceArn(key.ARN())), SchemaName: new(api.SchemaRegistryNameString(key.Name)), Description: registryDescriptionOutput(v.Description), DataFormat: new(api.DataFormat(format)), Compatibility: new(api.Compatibility(mode)), SchemaStatus: new(api.SchemaStatus(v.Status)), SchemaCheckpoint: new(api.SchemaCheckpointNumber(v.Checkpoint)), LatestSchemaVersion: new(api.VersionLongNumber(v.LatestVersion)), NextSchemaVersion: new(api.VersionLongNumber(v.NextVersion)), Tags: registryTagsOutput(tags), SchemaVersionId: new(api.SchemaVersionIdString(version.ID)), SchemaVersionStatus: new(api.SchemaVersionStatus(version.Status))}, nil
}
func schemaOutput(v SchemaRecord) *api.GetSchemaResponse {
	rk := ResourceKey{Scope: v.Key.Scope, Name: v.Key.Registry}
	return &api.GetSchemaResponse{RegistryArn: new(api.GlueResourceArn(rk.ARN("registry"))), RegistryName: new(api.SchemaRegistryNameString(v.Key.Registry)), SchemaArn: new(api.GlueResourceArn(v.Key.ARN())), SchemaName: new(api.SchemaRegistryNameString(v.Key.Name)), Description: registryDescriptionOutput(v.Description), DataFormat: new(api.DataFormat(v.DataFormat)), Compatibility: new(api.Compatibility(v.Compatibility)), SchemaStatus: new(api.SchemaStatus(v.Status)), SchemaCheckpoint: new(api.SchemaCheckpointNumber(v.Checkpoint)), LatestSchemaVersion: new(api.VersionLongNumber(v.LatestVersion)), NextSchemaVersion: new(api.VersionLongNumber(v.NextVersion)), CreatedTime: registryCreated(v.Created), UpdatedTime: registryUpdated(v.Updated)}
}
func (s *Service) getSchema(ctx context.Context, tx Transaction, in *api.GetSchemaInput) (*api.GetSchemaResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	v, err := s.loadSchema(ctx, tx, "GetSchema", key)
	if err != nil {
		return nil, err
	}
	return schemaOutput(v), nil
}
func (s *Service) updateSchema(ctx context.Context, tx Transaction, in *api.UpdateSchemaInput) (*api.UpdateSchemaResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	v, err := s.loadSchema(ctx, tx, "UpdateSchema", key)
	if err != nil {
		return nil, err
	}
	if err := s.schemaWritable(tx, v); err != nil {
		return nil, err
	}
	if in.Compatibility != nil && in.SchemaVersionNumber == nil {
		return nil, failure("InvalidInputException", "SchemaVersionNumber is required when updating Compatibility")
	}
	if in.Compatibility == nil && in.SchemaVersionNumber == nil && in.Description == nil {
		return nil, failure("InvalidInputException", "No schema update was provided")
	}
	if in.Compatibility != nil {
		if err := registryCompatibility(value(in.Compatibility)); err != nil {
			return nil, err
		}
		v.Compatibility = value(in.Compatibility)
	}
	if in.SchemaVersionNumber != nil {
		number, err := registryVersionNumber(tx, v, in.SchemaVersionNumber)
		if err != nil {
			return nil, err
		}
		version, err := tx.SchemaVersion(SchemaVersionKey{Schema: key, Number: number})
		if err != nil {
			return nil, err
		}
		if version.Status != "AVAILABLE" {
			return nil, failure("InvalidInputException", "Checkpoint must refer to an AVAILABLE version")
		}
		v.Checkpoint = number
	}
	if in.Description != nil {
		v.Description = registryDescription(in.Description)
	}
	v.Updated = s.clock.Now().UTC()
	if err := tx.PutSchema(v); err != nil {
		return nil, err
	}
	return &api.UpdateSchemaResponse{RegistryName: new(api.SchemaRegistryNameString(key.Registry)), SchemaArn: new(api.GlueResourceArn(key.ARN())), SchemaName: new(api.SchemaRegistryNameString(key.Name))}, nil
}
func (s *Service) deleteSchema(ctx context.Context, tx Transaction, in *api.DeleteSchemaInput) (*api.DeleteSchemaResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	v, err := s.loadSchema(ctx, tx, "DeleteSchema", key)
	if err != nil {
		return nil, err
	}
	if err := s.schemaWritable(tx, v); err != nil {
		return nil, err
	}
	v.Status = "DELETING"
	v.Updated = s.clock.Now().UTC()
	v.Due = v.Updated.Add(time.Second)
	if err := tx.PutSchema(v); err != nil {
		return nil, err
	}
	return &api.DeleteSchemaResponse{SchemaArn: new(api.GlueResourceArn(key.ARN())), SchemaName: new(api.SchemaRegistryNameString(key.Name)), Status: new(api.SchemaStatusDELETING)}, nil
}
func (s *Service) listSchemas(ctx context.Context, tx Transaction, in *api.ListSchemasInput) (*api.ListSchemasResponse, error) {
	scope := scopeFor(ctx)
	registry := ""
	if in.RegistryId != nil {
		key, err := registryKey(scope, in.RegistryId, false)
		if err != nil {
			return nil, err
		}
		registry = key.Name
		if _, err := s.loadRegistry(ctx, tx, "ListSchemas", key); err != nil {
			return nil, err
		}
	} else if err := s.authorize(ctx, tx, "ListSchemas", scope, "*", nil); err != nil {
		return nil, err
	}
	collection := "ListSchemas:" + (ResourceKey{Scope: scope, Name: registry}).ARN("registry")
	after, err := registryPageAfter(in.NextToken, collection)
	if err != nil {
		return nil, err
	}
	limit, err := registryPageSize(in.MaxResults, 100)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Schemas(scope, registry)
	if err != nil {
		return nil, err
	}
	out := &api.ListSchemasResponse{Schemas: api.SchemaListDefinition{}}
	last := ""
	for _, v := range rows {
		position := v.Key.Registry + "/" + v.Key.Name
		if v.Status == "DELETING" || position <= after {
			continue
		}
		if len(out.Schemas) == limit {
			out.NextToken = registryPageToken(collection, last)
			break
		}
		last = position
		out.Schemas = append(out.Schemas, api.SchemaListItem{RegistryName: new(api.SchemaRegistryNameString(v.Key.Registry)), SchemaName: new(api.SchemaRegistryNameString(v.Key.Name)), SchemaArn: new(api.GlueResourceArn(v.Key.ARN())), SchemaStatus: new(api.SchemaStatus(v.Status)), Description: registryDescriptionOutput(v.Description), CreatedTime: registryCreated(v.Created), UpdatedTime: registryUpdated(v.Updated)})
	}
	return out, nil
}

func registryVersionNumber(tx Reader, schema SchemaRecord, selector *api.SchemaVersionNumber) (int64, error) {
	if selector == nil {
		return 0, failure("InvalidInputException", "SchemaVersionNumber is required")
	}
	latest := selector.LatestVersion != nil && bool(*selector.LatestVersion)
	if latest && selector.VersionNumber != nil {
		return 0, failure("InvalidInputException", "Specify VersionNumber or LatestVersion, not both")
	}
	if latest {
		versions, err := tx.SchemaVersions(schema.Key)
		if err != nil {
			return 0, err
		}
		for _, version := range versions {
			if version.Status == "AVAILABLE" {
				return version.Key.Number, nil
			}
		}
		return 0, ErrNotFound
	}
	if selector.VersionNumber == nil || *selector.VersionNumber < 1 || *selector.VersionNumber > 100000 {
		return 0, failure("InvalidInputException", "A valid VersionNumber or LatestVersion is required")
	}
	return int64(*selector.VersionNumber), nil
}
func (s *Service) registryVersion(ctx context.Context, tx Reader, action string, id *api.SchemaId, versionID *api.SchemaVersionIdString, selector *api.SchemaVersionNumber) (SchemaRecord, SchemaVersionRecord, error) {
	var schema SchemaRecord
	var version SchemaVersionRecord
	if value(versionID) != "" {
		if id != nil || selector != nil {
			return schema, version, failure("InvalidInputException", "Specify SchemaVersionId or SchemaId with SchemaVersionNumber")
		}
		v, err := tx.SchemaVersionByID(scopeFor(ctx), value(versionID))
		if err != nil {
			if denied := s.authorize(ctx, tx, action, scopeFor(ctx), "*", nil); denied != nil {
				return schema, version, denied
			}
			return schema, version, err
		}
		schema, err = s.loadSchema(ctx, tx, action, v.Key.Schema)
		return schema, v, err
	}
	key, err := schemaKey(scopeFor(ctx), id)
	if err != nil {
		return schema, version, err
	}
	schema, err = s.loadSchema(ctx, tx, action, key)
	if err != nil {
		return schema, version, err
	}
	number, err := registryVersionNumber(tx, schema, selector)
	if err != nil {
		return schema, version, err
	}
	version, err = tx.SchemaVersion(SchemaVersionKey{Schema: key, Number: number})
	return schema, version, err
}
func registryAllMode(mode string) bool { return strings.HasSuffix(mode, "_ALL") }
