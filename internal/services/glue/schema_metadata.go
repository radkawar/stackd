package glue

import (
	"context"
	"encoding/json"
	"slices"

	api "stackd/internal/awsapi/glue"
)

func registryMetadataPair(pair *api.MetadataKeyValuePair) (string, string, error) {
	if pair == nil || len(value(pair.MetadataKey)) < 1 || len(value(pair.MetadataKey)) > 128 || len(value(pair.MetadataValue)) < 1 || len(value(pair.MetadataValue)) > 256 {
		return "", "", failure("InvalidInputException", "MetadataKey and MetadataValue are required and must fit their length limits")
	}
	return value(pair.MetadataKey), value(pair.MetadataValue), nil
}
func (s *Service) putSchemaVersionMetadata(ctx context.Context, tx Transaction, in *api.PutSchemaVersionMetadataInput) (*api.PutSchemaVersionMetadataResponse, error) {
	schema, version, err := s.registryVersion(ctx, tx, "PutSchemaVersionMetadata", in.SchemaId, in.SchemaVersionId, in.SchemaVersionNumber)
	if err != nil {
		return nil, err
	}
	if err := s.schemaWritable(tx, schema); err != nil {
		return nil, err
	}
	if err := registryAvailable(version.Status); err != nil {
		return nil, err
	}
	key, v, err := registryMetadataPair(in.MetadataKeyValue)
	if err != nil {
		return nil, err
	}
	rows, err := tx.SchemaMetadata(version.ID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Key == key && row.Value == v {
			return nil, failure("AlreadyExistsException", "Metadata key and value already exist")
		}
	}
	if len(rows) >= 10 {
		return nil, failure("ResourceNumberLimitExceededException", "Schema version metadata is limited to 10 pairs")
	}
	var ordinal int64
	for _, row := range rows {
		ordinal = max(ordinal, row.Ordinal)
	}
	if err := tx.PutSchemaMetadata(SchemaMetadataRecord{VersionID: version.ID, Key: key, Value: v, Created: s.clock.Now().UTC(), Ordinal: ordinal + 1}); err != nil {
		return nil, err
	}
	if in.SchemaVersionId != nil {
		return &api.PutSchemaVersionMetadataResponse{SchemaVersionId: new(api.SchemaVersionIdString(version.ID)), VersionNumber: new(api.VersionLongNumber(0)), LatestVersion: new(api.LatestSchemaVersionBoolean(false)), MetadataKey: new(api.MetadataKeyString(key)), MetadataValue: new(api.MetadataValueString(v))}, nil
	}
	return &api.PutSchemaVersionMetadataResponse{RegistryName: new(api.SchemaRegistryNameString(schema.Key.Registry)), SchemaName: new(api.SchemaRegistryNameString(schema.Key.Name)), SchemaArn: new(api.GlueResourceArn(schema.Key.ARN())), SchemaVersionId: new(api.SchemaVersionIdString(version.ID)), VersionNumber: new(api.VersionLongNumber(version.Key.Number)), LatestVersion: new(api.LatestSchemaVersionBoolean(version.Key.Number == schema.LatestVersion)), MetadataKey: new(api.MetadataKeyString(key)), MetadataValue: new(api.MetadataValueString(v))}, nil
}
func (s *Service) removeSchemaVersionMetadata(ctx context.Context, tx Transaction, in *api.RemoveSchemaVersionMetadataInput) (*api.RemoveSchemaVersionMetadataResponse, error) {
	schema, version, err := s.registryVersion(ctx, tx, "RemoveSchemaVersionMetadata", in.SchemaId, in.SchemaVersionId, in.SchemaVersionNumber)
	if err != nil {
		return nil, err
	}
	if err := s.schemaWritable(tx, schema); err != nil {
		return nil, err
	}
	if err := registryAvailable(version.Status); err != nil {
		return nil, err
	}
	key, v, err := registryMetadataPair(in.MetadataKeyValue)
	if err != nil {
		return nil, err
	}
	rows, err := tx.SchemaMetadata(version.ID)
	if err != nil {
		return nil, err
	}
	found := false
	for _, row := range rows {
		if row.Key == key && row.Value == v {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	if err := tx.DeleteSchemaMetadata(version.ID, key, v); err != nil {
		return nil, err
	}
	if in.SchemaVersionId != nil {
		return &api.RemoveSchemaVersionMetadataResponse{SchemaVersionId: new(api.SchemaVersionIdString(version.ID)), VersionNumber: new(api.VersionLongNumber(0)), LatestVersion: new(api.LatestSchemaVersionBoolean(false)), MetadataKey: new(api.MetadataKeyString(key)), MetadataValue: new(api.MetadataValueString(v))}, nil
	}
	return &api.RemoveSchemaVersionMetadataResponse{RegistryName: new(api.SchemaRegistryNameString(schema.Key.Registry)), SchemaName: new(api.SchemaRegistryNameString(schema.Key.Name)), SchemaArn: new(api.GlueResourceArn(schema.Key.ARN())), SchemaVersionId: new(api.SchemaVersionIdString(version.ID)), VersionNumber: new(api.VersionLongNumber(version.Key.Number)), LatestVersion: new(api.LatestSchemaVersionBoolean(version.Key.Number == schema.LatestVersion)), MetadataKey: new(api.MetadataKeyString(key)), MetadataValue: new(api.MetadataValueString(v))}, nil
}
func (s *Service) querySchemaVersionMetadata(ctx context.Context, tx Transaction, in *api.QuerySchemaVersionMetadataInput) (*api.QuerySchemaVersionMetadataResponse, error) {
	_, version, err := s.registryVersion(ctx, tx, "QuerySchemaVersionMetadata", in.SchemaId, in.SchemaVersionId, in.SchemaVersionNumber)
	if err != nil {
		return nil, err
	}
	filter, err := json.Marshal(in.MetadataList)
	if err != nil {
		return nil, err
	}
	collection := "QuerySchemaVersionMetadata:" + version.ID + ":" + string(filter)
	after, err := registryPageAfter(in.NextToken, collection)
	if err != nil {
		return nil, err
	}
	limit, err := registryPageSize(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	for _, pair := range in.MetadataList {
		if pair.MetadataKey == nil && pair.MetadataValue == nil {
			return nil, failure("InvalidInputException", "A metadata filter must specify a key or value")
		}
	}
	rows, err := tx.SchemaMetadata(version.ID)
	if err != nil {
		return nil, err
	}
	groups := map[string][]SchemaMetadataRecord{}
	for _, row := range rows {
		match := len(in.MetadataList) == 0
		for _, pair := range in.MetadataList {
			if (pair.MetadataKey == nil || value(pair.MetadataKey) == row.Key) && (pair.MetadataValue == nil || value(pair.MetadataValue) == row.Value) {
				match = true
				break
			}
		}
		if match && row.Key > after {
			groups[row.Key] = append(groups[row.Key], row)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := &api.QuerySchemaVersionMetadataResponse{SchemaVersionId: new(api.SchemaVersionIdString(version.ID)), MetadataInfoMap: api.MetadataInfoMap{}}
	for i, key := range keys {
		if i == limit {
			out.NextToken = registryPageToken(collection, keys[i-1])
			break
		}
		values := groups[key]
		slices.Reverse(values)
		first := values[0]
		info := api.MetadataInfo{MetadataValue: new(api.MetadataValueString(first.Value)), CreatedTime: registryCreated(first.Created), OtherMetadataValueList: api.OtherMetadataValueList{}}
		for _, row := range values[1:] {
			info.OtherMetadataValueList = append(info.OtherMetadataValueList, api.OtherMetadataValueListItem{MetadataValue: new(api.MetadataValueString(row.Value)), CreatedTime: registryCreated(row.Created)})
		}
		out.MetadataInfoMap[api.MetadataKeyString(key)] = info
	}
	return out, nil
}
