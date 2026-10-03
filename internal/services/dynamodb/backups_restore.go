package dynamodb

import (
	"context"
	"slices"
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

func (s *Service) restoreTableFromBackup(ctx context.Context, tx Transaction, in *api.RestoreTableFromBackupInput) (*api.RestoreTableFromBackupOutput, error) {
	key, err := parseBackupKey(scopeFor(ctx), value(in.BackupArn))
	if err != nil {
		return nil, err
	}
	// Native restore compares the ARN region literally here, although backup ARN
	// syntax accepts differently cased known region names.
	if key.Region != scopeFor(ctx).Region {
		if in.SSESpecificationOverride == nil {
			return nil, failure("ValidationException", "Invalid Request: sseSpecificationOverride must be provided for cross-region restores")
		}
		// TODO: Comeback implement cross-region restore with the KMS encryption
		// dependency, rather than copying unencrypted data across region scopes.
		return nil, unsupported("Cross-region DynamoDB backup restore is not implemented.")
	}
	backup, err := s.controlBackup(ctx, tx, key, "RestoreTableFromBackup")
	if err != nil {
		return nil, err
	}
	if value(backup.Description.BackupDetails.BackupStatus) != "AVAILABLE" {
		return nil, failure("BackupInUseException", "Backup is being created")
	}
	create := api.CreateTableInput{
		TableName: new(api.TableArn(*in.TargetTableName)), BillingMode: in.BillingModeOverride,
		ProvisionedThroughput: in.ProvisionedThroughputOverride, OnDemandThroughput: in.OnDemandThroughputOverride,
		GlobalSecondaryIndexes: in.GlobalSecondaryIndexOverride, LocalSecondaryIndexes: in.LocalSecondaryIndexOverride,
		SSESpecification: in.SSESpecificationOverride, VectorIndexes: in.VectorIndexOverride,
	}
	if err := restoreCreateInput(&backup, &create); err != nil {
		return nil, err
	}
	restore := &admittedRestore{Summary: &api.RestoreSummary{
		RestoreInProgress: new(api.RestoreInProgress(true)), RestoreDateTime: backup.Description.BackupDetails.BackupCreationDateTime,
		SourceBackupArn: backup.Description.BackupDetails.BackupArn, SourceTableArn: backup.Description.SourceTableDetails.TableArn,
	}}
	table, err := s.admitTable(ctx, tx, &create, restore)
	if err != nil {
		return nil, err
	}
	return &api.RestoreTableFromBackupOutput{TableDescription: &table.Data}, nil
}

// restoreCreateInput applies source schema and capacity to explicit restore
// overrides. PITR supplies current table metadata; backup restore supplies its
// captured metadata. Neither inherits streams, TTL, policies, tags or PITR.
func restoreCreateInput(backup *BackupRecord, create *api.CreateTableInput) error {
	globalOverrides, localOverrides := create.GlobalSecondaryIndexes, create.LocalSecondaryIndexes
	source, features := backup.Description.SourceTableDetails, backup.Description.SourceTableFeatureDetails
	provisionedOverride := value(create.BillingMode) == "PROVISIONED"
	if create.BillingMode == nil {
		create.BillingMode = source.BillingMode
	}
	mode := create.BillingMode
	create.KeySchema = source.KeySchema
	if value(mode) == "PROVISIONED" && create.ProvisionedThroughput == nil {
		if provisionedOverride {
			return failure("ValidationException", "Invalid Request: Must override ProvisionedThroughput if BillingMode is overridden to PROVISIONED")
		}
		create.ProvisionedThroughput = source.ProvisionedThroughput
	}
	if value(mode) == "PAY_PER_REQUEST" && create.OnDemandThroughput == nil {
		create.OnDemandThroughput = source.OnDemandThroughput
	}
	if create.GlobalSecondaryIndexes == nil {
		for _, index := range features.GlobalSecondaryIndexes {
			if provisionedOverride {
				return failure("ValidationException", "Invalid Request: Must override ProvisionedThroughput if BillingMode is overridden to PROVISIONED for index "+value(index.IndexName))
			}
			restored := api.GlobalSecondaryIndex{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection}
			if value(mode) == "PROVISIONED" {
				restored.ProvisionedThroughput = index.ProvisionedThroughput
			} else {
				restored.OnDemandThroughput = index.OnDemandThroughput
			}
			create.GlobalSecondaryIndexes = append(create.GlobalSecondaryIndexes, restored)
		}
	}
	if create.LocalSecondaryIndexes == nil {
		for _, index := range features.LocalSecondaryIndexes {
			create.LocalSecondaryIndexes = append(create.LocalSecondaryIndexes, api.LocalSecondaryIndex(index))
		}
	}
	for _, index := range globalOverrides {
		if !slices.ContainsFunc(features.GlobalSecondaryIndexes, func(source api.GlobalSecondaryIndexInfo) bool {
			return restoreIndexMatches(index.KeySchema, index.Projection, source.KeySchema, source.Projection)
		}) {
			return failure("ValidationException", "Invalid Request: Index "+value(index.IndexName)+" does not match a secondary index that existed in the source table and cannot be created during the restore operation")
		}
	}
	for _, index := range localOverrides {
		if !slices.ContainsFunc(features.LocalSecondaryIndexes, func(source api.LocalSecondaryIndexInfo) bool {
			return restoreIndexMatches(index.KeySchema, index.Projection, source.KeySchema, source.Projection)
		}) {
			return failure("ValidationException", "Invalid Request: Index "+value(index.IndexName)+" does not match a secondary index that existed in the source table and cannot be created during the restore operation")
		}
	}
	// Restore's explicit [] chooses exclusion. Native CreateTable expresses
	// that result by omitting the collection, not by sending an empty index list.
	if len(create.GlobalSecondaryIndexes) == 0 {
		create.GlobalSecondaryIndexes = nil
	}
	if len(create.LocalSecondaryIndexes) == 0 {
		create.LocalSecondaryIndexes = nil
	}
	create.AttributeDefinitions = selectedKeyDefinitions(backup.AttributeDefinitions, create)
	return nil
}

// Names and capacity may change; keys and projected attributes must already exist
// in a source index. Inputs and captured source definitions are already validated.
func restoreIndexMatches(keys api.KeySchema, projection *api.Projection, sourceKeys api.KeySchema, sourceProjection *api.Projection) bool {
	if !slices.EqualFunc(keys, sourceKeys, func(a, b api.KeySchemaElement) bool {
		return value(a.AttributeName) == value(b.AttributeName) && value(a.KeyType) == value(b.KeyType)
	}) || value(projection.ProjectionType) != value(sourceProjection.ProjectionType) ||
		len(projection.NonKeyAttributes) != len(sourceProjection.NonKeyAttributes) {
		return false
	}
	for _, name := range projection.NonKeyAttributes {
		if !slices.Contains(sourceProjection.NonKeyAttributes, name) {
			return false
		}
	}
	return true
}

// The pending table owns the backup reference until data is copied and ACTIVE
// commits. DeleteBackup rejects that reference, including across process restart.
func (s *Service) restoreTableData(ctx context.Context, table *TableRecord) error {
	return s.withMutation(ctx, table, func() error {
		if table.RestoreRecoveryID != "" {
			return s.restoreRecoveryData(ctx, table)
		}
		key, err := parseBackupKey(table.Key.Scope, value(table.Data.RestoreSummary.SourceBackupArn))
		if err != nil {
			return err
		}
		var backup BackupRecord
		if err := s.repository.View(ctx, func(r Reader) error {
			var err error
			backup, err = r.Backup(key)
			return err
		}); err != nil {
			return err
		}
		db, err := s.engines.database(ctx, tableSpecification(table))
		if err != nil {
			return err
		}
		return copyNativeTable(ctx, db, db, backup.PhysicalName, table.PhysicalName)
	})
}

func finishRestoreHistory(table *api.TableDescription, now time.Time) {
	provisioned := table.BillingModeSummary == nil || value(table.BillingModeSummary.BillingMode) == "PROVISIONED"
	if provisioned {
		table.BillingModeSummary = nil
	} else {
		table.BillingModeSummary.LastUpdateToPayPerRequestDateTime = &now
		table.ProvisionedThroughput.NumberOfDecreasesToday = new(api.PositiveLongObject(0))
	}
	// AWS restore settles with a decrease on each GSI and provisioned base.
	if provisioned {
		finishRestoreCapacity(table.ProvisionedThroughput, &now)
	}
	for i := range table.GlobalSecondaryIndexes {
		finishRestoreCapacity(table.GlobalSecondaryIndexes[i].ProvisionedThroughput, &now)
	}
	table.RestoreSummary = nil
}

func finishRestoreCapacity(capacity *api.ProvisionedThroughputDescription, now *time.Time) {
	capacity.NumberOfDecreasesToday = new(api.PositiveLongObject(1))
	capacity.LastDecreaseDateTime = now
	// Native table/GSI captures put the restore increase boundary at four read units.
	if *capacity.ReadCapacityUnits > 3 {
		capacity.LastIncreaseDateTime = now
	}
}
