package glue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/glue"
)

var registryNamePattern = regexp.MustCompile(`^[A-Za-z0-9_$#-]{1,255}$`)

func registerRegistry(s *Service) {
	registerControl(s, "CreateRegistry", s.createRegistry)
	registerControl(s, "GetRegistry", s.getRegistry)
	registerControl(s, "UpdateRegistry", s.updateRegistry)
	registerControl(s, "DeleteRegistry", s.deleteRegistry)
	registerControl(s, "ListRegistries", s.listRegistries)
	registerControl(s, "CreateSchema", s.createSchema)
	registerControl(s, "GetSchema", s.getSchema)
	registerControl(s, "UpdateSchema", s.updateSchema)
	registerControl(s, "DeleteSchema", s.deleteSchema)
	registerControl(s, "ListSchemas", s.listSchemas)
	registerControl(s, "RegisterSchemaVersion", s.registerSchemaVersion)
	registerControl(s, "GetSchemaVersion", s.getSchemaVersion)
	registerControl(s, "GetSchemaByDefinition", s.getSchemaByDefinition)
	registerControl(s, "ListSchemaVersions", s.listSchemaVersions)
	registerControl(s, "DeleteSchemaVersions", s.deleteSchemaVersions)
	registerControl(s, "CheckSchemaVersionValidity", s.checkSchemaVersionValidity)
	registerControl(s, "GetSchemaVersionsDiff", s.getSchemaVersionsDiff)
	registerControl(s, "PutSchemaVersionMetadata", s.putSchemaVersionMetadata)
	registerControl(s, "RemoveSchemaVersionMetadata", s.removeSchemaVersionMetadata)
	registerControl(s, "QuerySchemaVersionMetadata", s.querySchemaVersionMetadata)
}

func registryARNName(scope Scope, raw, kind string) (string, error) {
	parsed, err := arn.Parse(raw)
	if err != nil || parsed.Service != "glue" || !strings.HasPrefix(parsed.Resource, kind+"/") {
		return "", failure("InvalidInputException", "Invalid Glue "+kind+" ARN")
	}
	if parsed.Partition != scope.Partition || parsed.AccountID != scope.AccountID || parsed.Region != scope.Region {
		return "", failure("EntityNotFoundException", "The requested Glue resource does not exist in this scope")
	}
	return strings.TrimPrefix(parsed.Resource, kind+"/"), nil
}
func registryKey(scope Scope, id *api.RegistryId, defaultAllowed bool) (ResourceKey, error) {
	key := ResourceKey{Scope: scope}
	if id == nil {
		if defaultAllowed {
			key.Name = "default-registry"
			return key, nil
		}
		return key, failure("InvalidInputException", "RegistryId is required")
	}
	key.Name = value(id.RegistryName)
	if raw := value(id.RegistryArn); raw != "" {
		name, err := registryARNName(scope, raw, "registry")
		if err != nil {
			return key, err
		}
		if key.Name != "" && key.Name != name {
			return key, failure("InvalidInputException", "Registry ARN and name do not match")
		}
		key.Name = name
	}
	if !registryNamePattern.MatchString(key.Name) {
		return key, failure("InvalidInputException", "A valid RegistryName or RegistryArn is required")
	}
	return key, nil
}
func schemaKey(scope Scope, id *api.SchemaId) (SchemaKey, error) {
	key := SchemaKey{Scope: scope}
	if id == nil {
		return key, failure("InvalidInputException", "SchemaId is required")
	}
	key.Registry, key.Name = value(id.RegistryName), value(id.SchemaName)
	if raw := value(id.SchemaArn); raw != "" {
		name, err := registryARNName(scope, raw, "schema")
		if err != nil {
			return key, err
		}
		registry, schema, ok := strings.Cut(name, "/")
		if !ok || key.Registry != "" && key.Registry != registry || key.Name != "" && key.Name != schema {
			return key, failure("InvalidInputException", "Schema ARN and names do not match")
		}
		key.Registry, key.Name = registry, schema
	}
	if key.Registry == "" {
		key.Registry = "default-registry"
	}
	if !registryNamePattern.MatchString(key.Registry) || !registryNamePattern.MatchString(key.Name) {
		return key, failure("InvalidInputException", "A valid SchemaName or SchemaArn is required")
	}
	return key, nil
}
func registryDescription(v *api.DescriptionString) *string {
	if v == nil {
		return nil
	}
	return new(string(*v))
}
func registryDescriptionOutput(v *string) *api.DescriptionString {
	if v == nil {
		return nil
	}
	return new(api.DescriptionString(*v))
}
func registryTags(tags api.TagsMap) (map[string]string, error) {
	if len(tags) > 50 {
		return nil, failure("InvalidInputException", "A resource cannot have more than 50 tags")
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		if len(k) == 0 || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return nil, failure("InvalidInputException", "Invalid resource tag")
		}
		out[string(k)] = string(v)
	}
	return out, nil
}
func registryTagsOutput(tags map[string]string) api.TagsMap {
	out := make(api.TagsMap, len(tags))
	for k, v := range tags {
		out[api.TagKey(k)] = api.TagValue(v)
	}
	return out
}
func registryCreated(t time.Time) *api.CreatedTimestamp {
	return new(api.CreatedTimestamp(t.UTC().Format(time.RFC3339Nano)))
}
func registryUpdated(t time.Time) *api.UpdatedTimestamp {
	return new(api.UpdatedTimestamp(t.UTC().Format(time.RFC3339Nano)))
}

func (s *Service) loadRegistry(ctx context.Context, tx Reader, action string, key ResourceKey) (RegistryRecord, error) {
	v, err := tx.Registry(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if rejected := s.authorize(ctx, tx, action, key.Scope, key.ARN("registry"), v.Tags); rejected != nil {
		return v, rejected
	}
	return v, err
}
func (s *Service) loadSchema(ctx context.Context, tx Reader, action string, key SchemaKey) (SchemaRecord, error) {
	v, err := tx.Schema(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if _, parentErr := s.loadRegistry(ctx, tx, action, ResourceKey{Scope: key.Scope, Name: key.Registry}); parentErr != nil {
		return v, parentErr
	}
	if rejected := s.authorize(ctx, tx, action, key.Scope, key.ARN(), v.Tags); rejected != nil {
		return v, rejected
	}
	return v, err
}
func registryAvailable(status string) error {
	if status != "AVAILABLE" {
		return failure("ConcurrentModificationException", "Resource is not AVAILABLE")
	}
	return nil
}
func (s *Service) schemaWritable(tx Reader, v SchemaRecord) error {
	if err := registryAvailable(v.Status); err != nil {
		return err
	}
	r, err := tx.Registry(ResourceKey{Scope: v.Key.Scope, Name: v.Key.Registry})
	if err != nil {
		return err
	}
	return registryAvailable(r.Status)
}
func (s *Service) createRegistry(ctx context.Context, tx Transaction, in *api.CreateRegistryInput) (*api.CreateRegistryResponse, error) {
	key := ResourceKey{Scope: scopeFor(ctx), Name: value(in.RegistryName)}
	if !registryNamePattern.MatchString(key.Name) {
		return nil, failure("InvalidInputException", "Invalid registry name")
	}
	tags, err := registryTags(in.Tags)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, tx, "CreateRegistry", key.Scope, key.ARN("registry"), tags); err != nil {
		return nil, err
	}
	if _, err := tx.Registry(key); err == nil {
		return nil, failure("AlreadyExistsException", "Registry already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	rows, err := tx.Registries(key.Scope)
	if err != nil {
		return nil, err
	}
	if len(rows) >= 100 {
		return nil, failure("ResourceNumberLimitExceededException", "Registry limit exceeded")
	}
	now := s.clock.Now().UTC()
	v := RegistryRecord{Key: key, Description: registryDescription(in.Description), Status: "AVAILABLE", Created: now, Updated: now, Tags: tags}
	if err := tx.PutRegistry(v); err != nil {
		return nil, err
	}
	return &api.CreateRegistryResponse{RegistryArn: new(api.GlueResourceArn(key.ARN("registry"))), RegistryName: new(api.SchemaRegistryNameString(key.Name)), Description: registryDescriptionOutput(v.Description), Tags: registryTagsOutput(tags)}, nil
}
func (s *Service) getRegistry(ctx context.Context, tx Transaction, in *api.GetRegistryInput) (*api.GetRegistryResponse, error) {
	key, err := registryKey(scopeFor(ctx), in.RegistryId, false)
	if err != nil {
		return nil, err
	}
	v, err := s.loadRegistry(ctx, tx, "GetRegistry", key)
	if err != nil {
		return nil, err
	}
	return &api.GetRegistryResponse{RegistryArn: new(api.GlueResourceArn(key.ARN("registry"))), RegistryName: new(api.SchemaRegistryNameString(key.Name)), Description: registryDescriptionOutput(v.Description), Status: new(api.RegistryStatus(v.Status)), CreatedTime: registryCreated(v.Created), UpdatedTime: registryUpdated(v.Updated)}, nil
}
func (s *Service) updateRegistry(ctx context.Context, tx Transaction, in *api.UpdateRegistryInput) (*api.UpdateRegistryResponse, error) {
	key, err := registryKey(scopeFor(ctx), in.RegistryId, false)
	if err != nil {
		return nil, err
	}
	v, err := s.loadRegistry(ctx, tx, "UpdateRegistry", key)
	if err != nil {
		return nil, err
	}
	if err := registryAvailable(v.Status); err != nil {
		return nil, err
	}
	v.Description = registryDescription(in.Description)
	v.Updated = s.clock.Now().UTC()
	if err := tx.PutRegistry(v); err != nil {
		return nil, err
	}
	return &api.UpdateRegistryResponse{RegistryArn: new(api.GlueResourceArn(key.ARN("registry"))), RegistryName: new(api.SchemaRegistryNameString(key.Name))}, nil
}
func (s *Service) deleteRegistry(ctx context.Context, tx Transaction, in *api.DeleteRegistryInput) (*api.DeleteRegistryResponse, error) {
	key, err := registryKey(scopeFor(ctx), in.RegistryId, false)
	if err != nil {
		return nil, err
	}
	v, err := s.loadRegistry(ctx, tx, "DeleteRegistry", key)
	if err != nil {
		return nil, err
	}
	if err := registryAvailable(v.Status); err != nil {
		return nil, err
	}
	v.Status = "DELETING"
	v.Updated = s.clock.Now().UTC()
	v.Due = v.Updated.Add(time.Second)
	if err := tx.PutRegistry(v); err != nil {
		return nil, err
	}
	return &api.DeleteRegistryResponse{RegistryArn: new(api.GlueResourceArn(key.ARN("registry"))), RegistryName: new(api.SchemaRegistryNameString(key.Name)), Status: new(api.RegistryStatusDELETING)}, nil
}

type registryCursor struct{ Collection, After string }

func registryPageToken(collection, after string) *api.SchemaRegistryTokenString {
	data, _ := json.Marshal(registryCursor{collection, after})
	return new(api.SchemaRegistryTokenString(base64.RawURLEncoding.EncodeToString(data)))
}
func registryPageAfter(token *api.SchemaRegistryTokenString, collection string) (string, error) {
	if token == nil {
		return "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value(token))
	var cursor registryCursor
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Collection != collection || cursor.After == "" {
		return "", failure("InvalidInputException", "Invalid NextToken")
	}
	return cursor.After, nil
}
func registryPageSize[T ~int32](v *T, max int) (int, error) {
	if v == nil {
		return 25, nil
	}
	n := int(*v)
	if n < 1 || n > max {
		return 0, failure("InvalidInputException", "Invalid MaxResults")
	}
	return n, nil
}
func (s *Service) listRegistries(ctx context.Context, tx Transaction, in *api.ListRegistriesInput) (*api.ListRegistriesResponse, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "ListRegistries", scope, "*", nil); err != nil {
		return nil, err
	}
	collection := "ListRegistries:" + (ResourceKey{Scope: scope}).ARN("registry")
	after, err := registryPageAfter(in.NextToken, collection)
	if err != nil {
		return nil, err
	}
	limit, err := registryPageSize(in.MaxResults, 100)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Registries(scope)
	if err != nil {
		return nil, err
	}
	out := &api.ListRegistriesResponse{Registries: api.RegistryListDefinition{}}
	for _, v := range rows {
		if v.Status == "DELETING" || v.Key.Name <= after {
			continue
		}
		if len(out.Registries) == limit {
			out.NextToken = registryPageToken(collection, string(*out.Registries[len(out.Registries)-1].RegistryName))
			break
		}
		out.Registries = append(out.Registries, api.RegistryListItem{RegistryArn: new(api.GlueResourceArn(v.Key.ARN("registry"))), RegistryName: new(api.SchemaRegistryNameString(v.Key.Name)), Description: registryDescriptionOutput(v.Description), Status: new(api.RegistryStatus(v.Status)), CreatedTime: registryCreated(v.Created), UpdatedTime: registryUpdated(v.Updated)})
	}
	return out, nil
}
func registryResourceTags(tx Reader, scope Scope, resourceARN string) (map[string]string, error) {
	if strings.Contains(resourceARN, ":registry/") {
		key, err := registryKey(scope, &api.RegistryId{RegistryArn: new(api.GlueResourceArn(resourceARN))}, false)
		if err != nil {
			return nil, err
		}
		v, err := tx.Registry(key)
		return v.Tags, err
	}
	key, err := schemaKey(scope, &api.SchemaId{SchemaArn: new(api.GlueResourceArn(resourceARN))})
	if err != nil {
		return nil, err
	}
	v, err := tx.Schema(key)
	return v.Tags, err
}
func tagRegistryResource(tx Transaction, scope Scope, resourceARN string, tags map[string]string) error {
	if strings.Contains(resourceARN, ":registry/") {
		key, err := registryKey(scope, &api.RegistryId{RegistryArn: new(api.GlueResourceArn(resourceARN))}, false)
		if err != nil {
			return err
		}
		v, err := tx.Registry(key)
		if err != nil {
			return err
		}
		if err := registryAvailable(v.Status); err != nil {
			return err
		}
		v.Tags = maps.Clone(tags)
		return tx.PutRegistry(v)
	}
	key, err := schemaKey(scope, &api.SchemaId{SchemaArn: new(api.GlueResourceArn(resourceARN))})
	if err != nil {
		return err
	}
	v, err := tx.Schema(key)
	if err != nil {
		return err
	}
	if err := registryAvailable(v.Status); err != nil {
		return err
	}
	v.Tags = maps.Clone(tags)
	return tx.PutSchema(v)
}
