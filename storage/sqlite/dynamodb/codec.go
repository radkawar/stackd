package dynamodb

import (
	api "stackd/internal/awsapi/dynamodb"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

// Public scalars remain SQL columns. Each JSON field is a single generated nested
// configuration; generated omitzero list tags retain nonnil empty nested lists.
func tableData(row sqlcgen.DynamodbTable) (api.TableDescription, error) {
	d := api.TableDescription{
		CreationDateTime:                   timePointer(row.CreationDateTime),
		DeletionProtectionEnabled:          boolPointer[api.DeletionProtectionEnabled](row.DeletionProtectionEnabled),
		GlobalTableSettingsReplicationMode: stringPointer[api.GlobalTableSettingsReplicationMode](row.GlobalTableSettingsReplicationMode),
		GlobalTableVersion:                 stringPointer[api.String](row.GlobalTableVersion),
		ItemCount:                          integerPointer[api.LongObject](row.ItemCount),
		LatestStreamArn:                    stringPointer[api.StreamArn](row.LatestStreamArn),
		LatestStreamLabel:                  stringPointer[api.String](row.LatestStreamLabel),
		MultiRegionConsistency:             stringPointer[api.MultiRegionConsistency](row.MultiRegionConsistency),
		TableArn:                           stringPointer[api.String](row.TableArn),
		TableId:                            stringPointer[api.TableId](row.TableID),
		TableName:                          stringPointer[api.TableName](row.TableName),
		TableSizeBytes:                     integerPointer[api.LongObject](row.TableSizeBytes),
		TableStatus:                        stringPointer[api.TableStatus](row.TableStatus),
	}
	err := unmarshalFields(
		jsonReadField{row.ArchivalSummary, &d.ArchivalSummary},
		jsonReadField{row.AttributeDefinitions, &d.AttributeDefinitions},
		jsonReadField{row.BillingModeSummary, &d.BillingModeSummary},
		jsonReadField{row.GlobalSecondaryIndexes, &d.GlobalSecondaryIndexes},
		jsonReadField{row.GlobalTableWitnesses, &d.GlobalTableWitnesses},
		jsonReadField{row.KeySchema, &d.KeySchema},
		jsonReadField{row.LocalSecondaryIndexes, &d.LocalSecondaryIndexes},
		jsonReadField{row.OnDemandThroughput, &d.OnDemandThroughput},
		jsonReadField{row.ProvisionedThroughput, &d.ProvisionedThroughput},
		jsonReadField{row.Replicas, &d.Replicas},
		jsonReadField{row.RestoreSummary, &d.RestoreSummary},
		jsonReadField{row.SseDescription, &d.SSEDescription},
		jsonReadField{row.StreamSpecification, &d.StreamSpecification},
		jsonReadField{row.TableClassSummary, &d.TableClassSummary},
		jsonReadField{row.VectorIndexes, &d.VectorIndexes},
		jsonReadField{row.WarmThroughput, &d.WarmThroughput},
	)
	return d, err
}

func tableParams(k domain.TableKey, d *api.TableDescription) (sqlcgen.PutTableParams, error) {
	params := sqlcgen.PutTableParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		CreationDateTime:                   nullableTime(d.CreationDateTime),
		DeletionProtectionEnabled:          nullableBool(d.DeletionProtectionEnabled),
		GlobalTableSettingsReplicationMode: nullableString(d.GlobalTableSettingsReplicationMode),
		GlobalTableVersion:                 nullableString(d.GlobalTableVersion),
		ItemCount:                          nullableInteger(d.ItemCount),
		LatestStreamArn:                    nullableString(d.LatestStreamArn),
		LatestStreamLabel:                  nullableString(d.LatestStreamLabel),
		MultiRegionConsistency:             nullableString(d.MultiRegionConsistency),
		TableArn:                           nullableString(d.TableArn),
		TableID:                            nullableString(d.TableId),
		TableName:                          nullableString(d.TableName),
		TableSizeBytes:                     nullableInteger(d.TableSizeBytes),
		TableStatus:                        nullableString(d.TableStatus),
	}
	err := marshalFields(
		jsonWriteField{&params.ArchivalSummary, d.ArchivalSummary},
		jsonWriteField{&params.AttributeDefinitions, d.AttributeDefinitions},
		jsonWriteField{&params.BillingModeSummary, d.BillingModeSummary},
		jsonWriteField{&params.GlobalSecondaryIndexes, d.GlobalSecondaryIndexes},
		jsonWriteField{&params.GlobalTableWitnesses, d.GlobalTableWitnesses},
		jsonWriteField{&params.KeySchema, d.KeySchema},
		jsonWriteField{&params.LocalSecondaryIndexes, d.LocalSecondaryIndexes},
		jsonWriteField{&params.OnDemandThroughput, d.OnDemandThroughput},
		jsonWriteField{&params.ProvisionedThroughput, d.ProvisionedThroughput},
		jsonWriteField{&params.Replicas, d.Replicas},
		jsonWriteField{&params.RestoreSummary, d.RestoreSummary},
		jsonWriteField{&params.SseDescription, d.SSEDescription},
		jsonWriteField{&params.StreamSpecification, d.StreamSpecification},
		jsonWriteField{&params.TableClassSummary, d.TableClassSummary},
		jsonWriteField{&params.VectorIndexes, d.VectorIndexes},
		jsonWriteField{&params.WarmThroughput, d.WarmThroughput},
	)
	return params, err
}

func pendingCreateData(row sqlcgen.DynamodbPendingCreate) (api.CreateTableInput, error) {
	d := api.CreateTableInput{
		BillingMode:                        stringPointer[api.BillingMode](row.BillingMode),
		DeletionProtectionEnabled:          boolPointer[api.DeletionProtectionEnabled](row.DeletionProtectionEnabled),
		GlobalTableSettingsReplicationMode: stringPointer[api.GlobalTableSettingsReplicationMode](row.GlobalTableSettingsReplicationMode),
		GlobalTableSourceArn:               stringPointer[api.TableArn](row.GlobalTableSourceArn),
		ResourcePolicy:                     stringPointer[api.ResourcePolicy](row.ResourcePolicy),
		TableClass:                         stringPointer[api.TableClass](row.TableClass),
		TableName:                          stringPointer[api.TableArn](row.TableName),
	}
	err := unmarshalFields(
		jsonReadField{row.AttributeDefinitions, &d.AttributeDefinitions},
		jsonReadField{row.GlobalSecondaryIndexes, &d.GlobalSecondaryIndexes},
		jsonReadField{row.KeySchema, &d.KeySchema},
		jsonReadField{row.LocalSecondaryIndexes, &d.LocalSecondaryIndexes},
		jsonReadField{row.OnDemandThroughput, &d.OnDemandThroughput},
		jsonReadField{row.ProvisionedThroughput, &d.ProvisionedThroughput},
		jsonReadField{row.SseSpecification, &d.SSESpecification},
		jsonReadField{row.StreamSpecification, &d.StreamSpecification},
		jsonReadField{row.VectorIndexes, &d.VectorIndexes},
		jsonReadField{row.WarmThroughput, &d.WarmThroughput},
	)
	return d, err
}

func pendingCreateParams(k domain.TableKey, d *api.CreateTableInput) (sqlcgen.PutPendingCreateParams, error) {
	params := sqlcgen.PutPendingCreateParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		BillingMode:                        nullableString(d.BillingMode),
		DeletionProtectionEnabled:          nullableBool(d.DeletionProtectionEnabled),
		GlobalTableSettingsReplicationMode: nullableString(d.GlobalTableSettingsReplicationMode),
		GlobalTableSourceArn:               nullableString(d.GlobalTableSourceArn),
		ResourcePolicy:                     nullableString(d.ResourcePolicy),
		TableClass:                         nullableString(d.TableClass),
		TableName:                          nullableString(d.TableName),
		TagsPresent:                        d.Tags != nil,
	}
	err := marshalFields(
		jsonWriteField{&params.AttributeDefinitions, d.AttributeDefinitions},
		jsonWriteField{&params.GlobalSecondaryIndexes, d.GlobalSecondaryIndexes},
		jsonWriteField{&params.KeySchema, d.KeySchema},
		jsonWriteField{&params.LocalSecondaryIndexes, d.LocalSecondaryIndexes},
		jsonWriteField{&params.OnDemandThroughput, d.OnDemandThroughput},
		jsonWriteField{&params.ProvisionedThroughput, d.ProvisionedThroughput},
		jsonWriteField{&params.SseSpecification, d.SSESpecification},
		jsonWriteField{&params.StreamSpecification, d.StreamSpecification},
		jsonWriteField{&params.VectorIndexes, d.VectorIndexes},
		jsonWriteField{&params.WarmThroughput, d.WarmThroughput},
	)
	return params, err
}

func pendingUpdateData(row sqlcgen.DynamodbPendingUpdate) (api.UpdateTableInput, error) {
	d := api.UpdateTableInput{
		BillingMode:                        stringPointer[api.BillingMode](row.BillingMode),
		DeletionProtectionEnabled:          boolPointer[api.DeletionProtectionEnabled](row.DeletionProtectionEnabled),
		GlobalTableSettingsReplicationMode: stringPointer[api.GlobalTableSettingsReplicationMode](row.GlobalTableSettingsReplicationMode),
		MultiRegionConsistency:             stringPointer[api.MultiRegionConsistency](row.MultiRegionConsistency),
		TableClass:                         stringPointer[api.TableClass](row.TableClass),
		TableName:                          stringPointer[api.TableArn](row.TableName),
	}
	err := unmarshalFields(
		jsonReadField{row.AttributeDefinitions, &d.AttributeDefinitions},
		jsonReadField{row.GlobalSecondaryIndexUpdates, &d.GlobalSecondaryIndexUpdates},
		jsonReadField{row.GlobalTableWitnessUpdates, &d.GlobalTableWitnessUpdates},
		jsonReadField{row.OnDemandThroughput, &d.OnDemandThroughput},
		jsonReadField{row.ProvisionedThroughput, &d.ProvisionedThroughput},
		jsonReadField{row.ReplicaUpdates, &d.ReplicaUpdates},
		jsonReadField{row.SseSpecification, &d.SSESpecification},
		jsonReadField{row.StreamSpecification, &d.StreamSpecification},
		jsonReadField{row.VectorIndexUpdates, &d.VectorIndexUpdates},
		jsonReadField{row.WarmThroughput, &d.WarmThroughput},
	)
	return d, err
}

func pendingUpdateParams(k domain.TableKey, d *api.UpdateTableInput) (sqlcgen.PutPendingUpdateParams, error) {
	params := sqlcgen.PutPendingUpdateParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		BillingMode:                        nullableString(d.BillingMode),
		DeletionProtectionEnabled:          nullableBool(d.DeletionProtectionEnabled),
		GlobalTableSettingsReplicationMode: nullableString(d.GlobalTableSettingsReplicationMode),
		MultiRegionConsistency:             nullableString(d.MultiRegionConsistency),
		TableClass:                         nullableString(d.TableClass),
		TableName:                          nullableString(d.TableName),
	}
	err := marshalFields(
		jsonWriteField{&params.AttributeDefinitions, d.AttributeDefinitions},
		jsonWriteField{&params.GlobalSecondaryIndexUpdates, d.GlobalSecondaryIndexUpdates},
		jsonWriteField{&params.GlobalTableWitnessUpdates, d.GlobalTableWitnessUpdates},
		jsonWriteField{&params.OnDemandThroughput, d.OnDemandThroughput},
		jsonWriteField{&params.ProvisionedThroughput, d.ProvisionedThroughput},
		jsonWriteField{&params.ReplicaUpdates, d.ReplicaUpdates},
		jsonWriteField{&params.SseSpecification, d.SSESpecification},
		jsonWriteField{&params.StreamSpecification, d.StreamSpecification},
		jsonWriteField{&params.VectorIndexUpdates, d.VectorIndexUpdates},
		jsonWriteField{&params.WarmThroughput, d.WarmThroughput},
	)
	return params, err
}
