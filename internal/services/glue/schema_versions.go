package glue

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
)

func (s *Service) registerSchemaVersion(ctx context.Context, tx Transaction, in *api.RegisterSchemaVersionInput) (*api.RegisterSchemaVersionResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	schema, err := s.loadSchema(ctx, tx, "RegisterSchemaVersion", key)
	if err != nil {
		return nil, err
	}
	if err := s.schemaWritable(tx, schema); err != nil {
		return nil, err
	}
	parsed, err := parseRegistrySchema(ctx, schema.DataFormat, value(in.SchemaDefinition))
	if err != nil {
		return nil, failure("InvalidInputException", err.Error())
	}
	versions, err := tx.SchemaVersions(key)
	if err != nil {
		return nil, err
	}
	for _, v := range versions {
		if v.Canonical == parsed.canonical && v.Status != "DELETING" {
			return registryVersionRegistered(v), nil
		}
	}
	if schema.Compatibility == "DISABLED" && len(versions) > 0 {
		return nil, failure("InvalidInputException", "Schema versioning is disabled")
	}
	if schema.NextVersion > 100000 {
		return nil, failure("ResourceNumberLimitExceededException", "Schema version limit exceeded")
	}
	status := "AVAILABLE"
	if schema.Compatibility != "NONE" && schema.Compatibility != "DISABLED" {
		for _, old := range versions {
			if old.Status != "AVAILABLE" || old.Key.Number < schema.Checkpoint {
				continue
			}
			previous, err := parseRegistrySchema(ctx, schema.DataFormat, old.Definition)
			if err != nil {
				return nil, err
			}
			var incompatible error
			if strings.HasPrefix(schema.Compatibility, "BACKWARD") || strings.HasPrefix(schema.Compatibility, "FULL") {
				incompatible = registryCompatible(parsed, previous, schema.DataFormat)
			}
			if incompatible == nil && (strings.HasPrefix(schema.Compatibility, "FORWARD") || strings.HasPrefix(schema.Compatibility, "FULL")) {
				incompatible = registryCompatible(previous, parsed, schema.DataFormat)
			}
			if incompatible != nil {
				var blocked *awswire.Error
				if errors.As(incompatible, &blocked) {
					return nil, blocked
				}
				status = "FAILURE"
				break
			}
			if !registryAllMode(schema.Compatibility) {
				break
			}
		}
	}
	v := SchemaVersionRecord{Key: SchemaVersionKey{Schema: key, Number: schema.NextVersion}, ID: uuid.NewString(), Definition: value(in.SchemaDefinition), Canonical: parsed.canonical, Status: status, Created: s.clock.Now().UTC()}
	if err := tx.PutSchemaVersion(v); err != nil {
		return nil, err
	}
	schema.LatestVersion = v.Key.Number
	schema.NextVersion++
	schema.Updated = v.Created
	if err := tx.PutSchema(schema); err != nil {
		return nil, err
	}
	return registryVersionRegistered(v), nil
}
func registryVersionRegistered(v SchemaVersionRecord) *api.RegisterSchemaVersionResponse {
	return &api.RegisterSchemaVersionResponse{SchemaVersionId: new(api.SchemaVersionIdString(v.ID)), VersionNumber: new(api.VersionLongNumber(v.Key.Number)), Status: new(api.SchemaVersionStatus(v.Status))}
}
func (s *Service) getSchemaVersion(ctx context.Context, tx Transaction, in *api.GetSchemaVersionInput) (*api.GetSchemaVersionResponse, error) {
	schema, v, err := s.registryVersion(ctx, tx, "GetSchemaVersion", in.SchemaId, in.SchemaVersionId, in.SchemaVersionNumber)
	if err != nil {
		return nil, err
	}
	return &api.GetSchemaVersionResponse{SchemaArn: new(api.GlueResourceArn(schema.Key.ARN())), SchemaVersionId: new(api.SchemaVersionIdString(v.ID)), SchemaDefinition: new(api.SchemaDefinitionString(v.Definition)), DataFormat: new(api.DataFormat(schema.DataFormat)), VersionNumber: new(api.VersionLongNumber(v.Key.Number)), Status: new(api.SchemaVersionStatus(v.Status)), CreatedTime: registryCreated(v.Created)}, nil
}
func (s *Service) getSchemaByDefinition(ctx context.Context, tx Transaction, in *api.GetSchemaByDefinitionInput) (*api.GetSchemaByDefinitionResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	schema, err := s.loadSchema(ctx, tx, "GetSchemaByDefinition", key)
	if err != nil {
		return nil, err
	}
	if err := s.schemaWritable(tx, schema); err != nil {
		return nil, err
	}
	parsed, err := parseRegistrySchema(ctx, schema.DataFormat, value(in.SchemaDefinition))
	if err != nil {
		return nil, failure("InvalidInputException", err.Error())
	}
	versions, err := tx.SchemaVersions(key)
	if err != nil {
		return nil, err
	}
	for _, v := range versions {
		if v.Canonical == parsed.canonical && v.Status != "DELETING" {
			return &api.GetSchemaByDefinitionResponse{SchemaArn: new(api.GlueResourceArn(key.ARN())), SchemaVersionId: new(api.SchemaVersionIdString(v.ID)), DataFormat: new(api.DataFormat(schema.DataFormat)), Status: new(api.SchemaVersionStatus(v.Status)), CreatedTime: registryCreated(v.Created)}, nil
		}
	}
	return nil, ErrNotFound
}
func (s *Service) listSchemaVersions(ctx context.Context, tx Transaction, in *api.ListSchemaVersionsInput) (*api.ListSchemaVersionsResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	if _, err := s.loadSchema(ctx, tx, "ListSchemaVersions", key); err != nil {
		return nil, err
	}
	first, err := tx.SchemaVersion(SchemaVersionKey{Schema: key, Number: 1})
	if err != nil {
		return nil, err
	}
	collection := "ListSchemaVersions:" + key.ARN() + ":" + first.ID
	after, err := registryPageAfter(in.NextToken, collection)
	if err != nil {
		return nil, err
	}
	limit, err := registryPageSize(in.MaxResults, 100)
	if err != nil {
		return nil, err
	}
	versions, err := tx.SchemaVersions(key)
	if err != nil {
		return nil, err
	}
	out := &api.ListSchemaVersionsResponse{Schemas: api.SchemaVersionList{}}
	slices.SortFunc(versions, func(a, b SchemaVersionRecord) int {
		return cmp.Or(strings.Compare(a.Status, b.Status), cmp.Compare(b.Key.Number, a.Key.Number))
	})
	last := ""
	for _, v := range versions {
		position := registryVersionPosition(v)
		if position <= after {
			continue
		}
		if len(out.Schemas) == limit {
			out.NextToken = registryPageToken(collection, last)
			break
		}
		last = position
		out.Schemas = append(out.Schemas, api.SchemaVersionListItem{SchemaArn: new(api.GlueResourceArn(key.ARN())), SchemaVersionId: new(api.SchemaVersionIdString(v.ID)), VersionNumber: new(api.VersionLongNumber(v.Key.Number)), Status: new(api.SchemaVersionStatus(v.Status)), CreatedTime: registryCreated(v.Created)})
	}
	return out, nil
}
func registryVersionPosition(v SchemaVersionRecord) string {
	return v.Status + "/" + fmt.Sprintf("%06d", 100001-v.Key.Number)
}
func registryVersionRange(raw string) (int64, int64, error) {
	parts := strings.Split(raw, "-")
	if len(parts) > 2 {
		return 0, 0, failure("InvalidInputException", "Versions must be a number or an inclusive range")
	}
	first, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || first < 1 || first > 100000 {
		return 0, 0, failure("InvalidInputException", "Invalid schema version range")
	}
	last := first
	if len(parts) == 2 {
		last, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil || last < first || last > 100000 {
			return 0, 0, failure("InvalidInputException", "Invalid schema version range")
		}
	}
	return first, last, nil
}
func (s *Service) deleteSchemaVersions(ctx context.Context, tx Transaction, in *api.DeleteSchemaVersionsInput) (*api.DeleteSchemaVersionsResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	schema, err := s.loadSchema(ctx, tx, "DeleteSchemaVersions", key)
	if err != nil {
		return nil, err
	}
	if err := s.schemaWritable(tx, schema); err != nil {
		return nil, err
	}
	first, last, err := registryVersionRange(value(in.Versions))
	if err != nil {
		return nil, err
	}
	if first <= schema.Checkpoint && schema.Checkpoint <= last {
		return nil, failure("InvalidInputException", "Cannot delete a checkpoint schema version")
	}
	if first == 1 {
		return nil, failure("InvalidInputException", "The first schema version can only be deleted with DeleteSchema")
	}
	out := &api.DeleteSchemaVersionsResponse{SchemaVersionErrors: api.SchemaVersionErrorList{}}
	for number := first; number <= last; number++ {
		v, err := tx.SchemaVersion(SchemaVersionKey{Schema: key, Number: number})
		if errors.Is(err, ErrNotFound) {
			out.SchemaVersionErrors = append(out.SchemaVersionErrors, api.SchemaVersionErrorItem{VersionNumber: new(api.VersionLongNumber(number)), ErrorDetails: &api.ErrorDetails{ErrorCode: new(api.ErrorCodeString("ResourceNotFoundException")), ErrorMessage: new(api.ErrorMessageString("Schema version does not exist"))}})
			continue
		}
		if err != nil {
			return nil, err
		}
		if v.Status == "DELETING" {
			out.SchemaVersionErrors = append(out.SchemaVersionErrors, api.SchemaVersionErrorItem{VersionNumber: new(api.VersionLongNumber(number)), ErrorDetails: &api.ErrorDetails{ErrorCode: new(api.ErrorCodeString("ConcurrentModificationException")), ErrorMessage: new(api.ErrorMessageString("Schema version is deleting"))}})
			continue
		}
		v.Status = "DELETING"
		v.Due = s.clock.Now().UTC().Add(time.Second)
		if err := tx.PutSchemaVersion(v); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) checkSchemaVersionValidity(ctx context.Context, tx Transaction, in *api.CheckSchemaVersionValidityInput) (*api.CheckSchemaVersionValidityResponse, error) {
	if err := s.authorize(ctx, tx, "CheckSchemaVersionValidity", scopeFor(ctx), "*", nil); err != nil {
		return nil, err
	}
	format := value(in.DataFormat)
	if format != "AVRO" && format != "JSON" && format != "PROTOBUF" {
		return nil, failure("InvalidInputException", "DataFormat must be AVRO, JSON or PROTOBUF")
	}
	_, err := parseRegistrySchema(ctx, format, value(in.SchemaDefinition))
	out := &api.CheckSchemaVersionValidityResponse{Valid: new(api.IsVersionValid(err == nil))}
	if err != nil {
		message := err.Error()
		if len(message) > 5000 {
			message = message[:5000]
		}
		out.Error = new(api.SchemaValidationError(message))
	}
	return out, nil
}

type registryPatch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value *any   `json:"value,omitempty"`
}

func registryJSONPatch(first, second any, path string, out *[]registryPatch) {
	if registryJSONEqual(first, second) {
		return
	}
	a, aok := first.(map[string]any)
	b, bok := second.(map[string]any)
	if aok && bok {
		keys := make([]string, 0, len(a)+len(b))
		for k := range a {
			keys = append(keys, k)
		}
		for k := range b {
			if _, ok := a[k]; !ok {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, key := range keys {
			p := path + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
			av, ain := a[key]
			bv, bin := b[key]
			switch {
			case !bin:
				*out = append(*out, registryPatch{Op: "remove", Path: p})
			case !ain:
				*out = append(*out, registryPatch{Op: "add", Path: p, Value: new(bv)})
			default:
				registryJSONPatch(av, bv, p, out)
			}
		}
		return
	}
	aa, aok := first.([]any)
	bb, bok := second.([]any)
	if aok && bok {
		for i := range min(len(aa), len(bb)) {
			registryJSONPatch(aa[i], bb[i], path+"/"+strconv.Itoa(i), out)
		}
		for i := len(aa) - 1; i >= len(bb); i-- {
			*out = append(*out, registryPatch{Op: "remove", Path: path + "/" + strconv.Itoa(i)})
		}
		for i := len(aa); i < len(bb); i++ {
			*out = append(*out, registryPatch{Op: "add", Path: path + "/" + strconv.Itoa(i), Value: new(bb[i])})
		}
		return
	}
	*out = append(*out, registryPatch{Op: "replace", Path: path, Value: new(second)})
}
func (s *Service) getSchemaVersionsDiff(ctx context.Context, tx Transaction, in *api.GetSchemaVersionsDiffInput) (*api.GetSchemaVersionsDiffResponse, error) {
	key, err := schemaKey(scopeFor(ctx), in.SchemaId)
	if err != nil {
		return nil, err
	}
	schema, err := s.loadSchema(ctx, tx, "GetSchemaVersionsDiff", key)
	if err != nil {
		return nil, err
	}
	if value(in.SchemaDiffType) != "SYNTAX_DIFF" {
		return nil, failure("InvalidInputException", "Only SYNTAX_DIFF is supported")
	}
	first, err := registryVersionNumber(tx, schema, in.FirstSchemaVersionNumber)
	if err != nil {
		return nil, err
	}
	second, err := registryVersionNumber(tx, schema, in.SecondSchemaVersionNumber)
	if err != nil {
		return nil, err
	}
	a, err := tx.SchemaVersion(SchemaVersionKey{Schema: key, Number: first})
	if err != nil {
		return nil, err
	}
	b, err := tx.SchemaVersion(SchemaVersionKey{Schema: key, Number: second})
	if err != nil {
		return nil, err
	}
	if schema.DataFormat == "PROTOBUF" {
		// TODO: Comeback implement the native Protobuf SYNTAX_DIFF document representation; descriptor JSON is not the public syntax contract.
		return nil, failure("InvalidInputException", "Protobuf schema syntax diffs are not implemented")
	}
	firstJSON, err := decodeRegistryJSON(a.Definition)
	if err != nil {
		return nil, err
	}
	secondJSON, err := decodeRegistryJSON(b.Definition)
	if err != nil {
		return nil, err
	}
	patch := []registryPatch{}
	registryJSONPatch(firstJSON, secondJSON, "", &patch)
	data, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("encode schema diff: %w", err)
	}
	return &api.GetSchemaVersionsDiffResponse{Diff: new(api.SchemaDefinitionDiff(data))}, nil
}
