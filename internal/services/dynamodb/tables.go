package dynamodb

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	engine "stackd/engine/dynamodb"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

func registerControls(s *Service) {
	registerControl(s, "CreateTable", s.createTable)
	registerControl(s, "DescribeTable", s.describeTable)
	registerControl(s, "DescribeTableReplicaAutoScaling", s.describeTableReplicaAutoScaling)
	registerExternal(s, "UpdateTableReplicaAutoScaling", s.updateTableReplicaAutoScaling)
	registerControl(s, "ListTables", s.listTables)
	registerControl(s, "CreateGlobalTable", s.createGlobalTable)
	registerControl(s, "DescribeGlobalTable", s.describeGlobalTable)
	registerControl(s, "ListGlobalTables", s.listGlobalTables)
	registerControl(s, "UpdateGlobalTable", s.updateGlobalTable)
	registerOperation(s, "UpdateTable", s.UpdateTable)
	registerOperation(s, "DeleteTable", s.deleteTableCommand)
	registerControl(s, "DescribeTimeToLive", s.describeTimeToLive)
	registerControl(s, "UpdateTimeToLive", s.updateTimeToLive)
	registerControl(s, "TagResource", s.tagResource)
	registerControl(s, "UntagResource", s.untagResource)
	registerControl(s, "ListTagsOfResource", s.listTagsOfResource)
	registerControl(s, "GetResourcePolicy", s.getResourcePolicy)
	registerControl(s, "PutResourcePolicy", s.putResourcePolicy)
	registerControl(s, "DeleteResourcePolicy", s.deleteResourcePolicy)
	registerControl(s, "DescribeLimits", s.describeLimits)
	registerBackups(s)
	registerRecovery(s)
	registerOperation(s, "RestoreTableToPointInTime", s.restoreTableToPointInTimeCommand)
	registerEndpoints(s)
}

func (s *Service) controlTable(ctx context.Context, r Reader, selector, action string, conditions map[string][]string) (TableRecord, error) {
	key, err := parseTableKey(ctx, selector)
	if err != nil {
		return TableRecord{}, err
	}
	if err = s.authorizeTable(ctx, r, key, action, "", conditions); err != nil {
		return TableRecord{}, err
	}
	table, err := r.Table(key)
	if errors.Is(err, ErrNotFound) {
		return TableRecord{}, failure("ResourceNotFoundException", "Requested resource not found: Table: "+key.Name+" not found")
	}
	return table, err
}

func (s *Service) createTable(ctx context.Context, tx Transaction, in *api.CreateTableInput) (*api.CreateTableOutput, error) {
	table, err := s.admitTable(ctx, tx, in, nil)
	if err != nil {
		return nil, err
	}
	return &api.CreateTableOutput{TableDescription: &table.Data}, nil
}

// admittedRestore binds the public source selection to the history interval
// and sequence retained for the target. Backup restores instead pin their ARN.
type admittedRestore struct {
	Summary          *api.RestoreSummary
	RecoveryID       string
	RecoverySequence int64
}

// admitTable owns creation validation and resource allocation for both table
// creation and restore; restore requires its own IAM action, not CreateTable.
func (s *Service) admitTable(ctx context.Context, tx Transaction, in *api.CreateTableInput, restore *admittedRestore) (*TableRecord, error) {
	key, err := parseTableKey(ctx, value(in.TableName))
	if err != nil {
		return nil, err
	}
	name := key.Name
	if !tableNamePattern.MatchString(name) {
		return nil, failure("ValidationException", "Invalid table name: "+name)
	}
	if key.Scope != scopeFor(ctx) {
		return nil, failure("AccessDeniedException", "Access is denied")
	}
	conditions, err := tagConditions(in.Tags)
	if err != nil {
		return nil, err
	}
	action := "CreateTable"
	if restore != nil {
		action = "RestoreTableFromBackup"
		if restore.RecoveryID != "" {
			action = "RestoreTableToPointInTime"
		}
	}
	if err = s.authorize(ctx, action, key.ARN(), conditions); err != nil {
		return nil, err
	}
	if len(in.Tags) > 0 {
		if err = s.authorize(ctx, "TagResource", key.ARN(), conditions); err != nil {
			return nil, err
		}
	}
	if existing, lookupErr := tx.Table(key); lookupErr == nil {
		code := "ResourceInUseException"
		if restore != nil {
			if pending := existing.Data.RestoreSummary; pending != nil {
				return nil, failure("TableInUseException", "Table: "+name+" is already being restored from backup: "+value(pending.SourceBackupArn))
			}
			code = "TableAlreadyExistsException"
		}
		return nil, failure(code, "Table already exists: "+name)
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return nil, lookupErr
	}
	if err = validateCreate(in); err != nil {
		return nil, err
	}
	if err = validateAccountCapacity(tx, key, in); err != nil {
		return nil, err
	}
	if restore != nil {
		pending, err := tx.PendingTables()
		if err != nil {
			return nil, err
		}
		concurrent := 0
		for _, table := range pending {
			if table.Key.Scope == key.Scope && table.Data.RestoreSummary != nil {
				concurrent++
				if source := value(restore.Summary.SourceBackupArn); source != "" && value(table.Data.RestoreSummary.SourceBackupArn) == source {
					return nil, failure("BackupInUseException", "Backup is being used to restore another table: "+source)
				}
			}
		}
		if concurrent >= 50 {
			return nil, failure("LimitExceededException", "Concurrent restore limit of 50 tables exceeded")
		}
	}
	var policy *PolicyRecord
	if in.ResourcePolicy != nil {
		if err = s.authorize(ctx, "PutResourcePolicy", key.ARN(), nil); err != nil {
			return nil, err
		}
		bound, bindErr := s.bindPolicy(ctx, tx, key, key.ARN(), value(in.ResourcePolicy), false)
		if bindErr != nil {
			return nil, bindErr
		}
		policy = &PolicyRecord{Key: PolicyKey{Scope: key.Scope, ResourceARN: key.ARN()}, Policy: bound, Revision: uuid.NewString()}
	}
	db, err := tx.Database(key.Scope)
	if errors.Is(err, ErrNotFound) || err == nil && db.Retiring {
		db = DatabaseRecord{Spec: engine.Specification{ID: uuid.NewString(), Partition: key.Partition, AccountID: key.AccountID, Region: key.Region}}
		if err = tx.PutDatabase(db); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	pending := api.CloneCreateTableInput(*in)
	id := uuid.NewString()
	data := api.TableDescription{
		TableName: new(api.TableName(name)), TableArn: new(api.String(key.ARN())), TableId: new(api.TableId(id)),
		TableStatus: new(api.TableStatusCREATING), CreationDateTime: new(api.Date(s.clock.Now())),
		AttributeDefinitions: api.CloneAttributeDefinitions(in.AttributeDefinitions), KeySchema: api.CloneKeySchema(in.KeySchema),
		ProvisionedThroughput: throughputDescription(in.ProvisionedThroughput),
		OnDemandThroughput:    mergeOnDemand(nil, in.OnDemandThroughput),
		TableSizeBytes:        new(api.LongObject(0)), ItemCount: new(api.LongObject(0)), DeletionProtectionEnabled: new(api.DeletionProtectionEnabled(false)),
	}
	if restore != nil {
		data.RestoreSummary = restore.Summary
		if value(in.BillingMode) == "PAY_PER_REQUEST" {
			data.ProvisionedThroughput.NumberOfDecreasesToday = nil
		}
	}
	slices.SortFunc(data.AttributeDefinitions, func(a, b api.AttributeDefinition) int {
		return strings.Compare(value(a.AttributeName), value(b.AttributeName))
	})
	if in.DeletionProtectionEnabled != nil {
		data.DeletionProtectionEnabled = new(*in.DeletionProtectionEnabled)
	}
	if value(in.BillingMode) == "PAY_PER_REQUEST" || restore != nil {
		data.BillingModeSummary = &api.BillingModeSummary{BillingMode: in.BillingMode}
	}
	if in.TableClass != nil {
		data.TableClassSummary = &api.TableClassSummary{TableClass: new(*in.TableClass)}
	}
	if in.StreamSpecification != nil {
		data.StreamSpecification = new(api.CloneStreamSpecification(*in.StreamSpecification))
	}
	for _, index := range in.LocalSecondaryIndexes {
		data.LocalSecondaryIndexes = append(data.LocalSecondaryIndexes, api.LocalSecondaryIndexDescription{IndexName: new(*index.IndexName), IndexArn: new(api.String(key.ARN() + "/index/" + value(index.IndexName))), KeySchema: api.CloneKeySchema(index.KeySchema), Projection: new(api.CloneProjection(*index.Projection)), IndexSizeBytes: new(api.LongObject(0)), ItemCount: new(api.LongObject(0))})
	}
	for _, index := range in.GlobalSecondaryIndexes {
		data.GlobalSecondaryIndexes = append(data.GlobalSecondaryIndexes, newIndexDescription(key, index))
		if restore != nil {
			created := &data.GlobalSecondaryIndexes[len(data.GlobalSecondaryIndexes)-1]
			created.IndexStatus = nil
			if value(in.BillingMode) == "PAY_PER_REQUEST" {
				created.ProvisionedThroughput.NumberOfDecreasesToday = nil
			}
		}
	}
	table := TableRecord{Key: key, Data: data, DatabaseID: db.Spec.ID, PhysicalName: "table_" + strings.ReplaceAll(id, "-", ""), PendingCreate: &pending, TTL: api.TimeToLiveDescription{TimeToLiveStatus: new(api.TimeToLiveStatusDISABLED)}}
	if restore != nil {
		table.RestoreRecoveryID = restore.RecoveryID
		table.RestoreRecoverySequence = restore.RecoverySequence
	}
	if in.StreamSpecification != nil && bool(*in.StreamSpecification.StreamEnabled) {
		if err = s.assignStreamIdentity(tx, &table); err != nil {
			return nil, err
		}
	}
	if err = tx.PutTable(table); err != nil {
		return nil, err
	}
	if len(in.Tags) > 0 {
		if err = tx.PutTags(TagRecord{Key: key, Tags: api.CloneTagList(in.Tags)}); err != nil {
			return nil, err
		}
	}
	if policy != nil {
		if err = tx.PutPolicy(*policy); err != nil {
			return nil, err
		}
	}
	return &table, nil
}

func throughputDescription(in *api.ProvisionedThroughput) *api.ProvisionedThroughputDescription {
	out := &api.ProvisionedThroughputDescription{NumberOfDecreasesToday: new(api.PositiveLongObject(0)), ReadCapacityUnits: new(api.NonNegativeLongObject(0)), WriteCapacityUnits: new(api.NonNegativeLongObject(0))}
	if in != nil {
		out.ReadCapacityUnits = new(api.NonNegativeLongObject(*in.ReadCapacityUnits))
		out.WriteCapacityUnits = new(api.NonNegativeLongObject(*in.WriteCapacityUnits))
	}
	return out
}

func newIndexDescription(key TableKey, in api.GlobalSecondaryIndex) api.GlobalSecondaryIndexDescription {
	return api.GlobalSecondaryIndexDescription{IndexName: new(*in.IndexName), IndexArn: new(api.String(key.ARN() + "/index/" + value(in.IndexName))), KeySchema: api.CloneKeySchema(in.KeySchema), Projection: new(api.CloneProjection(*in.Projection)), ProvisionedThroughput: throughputDescription(in.ProvisionedThroughput), OnDemandThroughput: mergeOnDemand(nil, in.OnDemandThroughput), IndexSizeBytes: new(api.LongObject(0)), ItemCount: new(api.LongObject(0)), IndexStatus: new(api.IndexStatusCREATING)}
}

func (s *Service) tableDescription(r Reader, table *TableRecord) (*api.TableDescription, error) {
	out := new(api.CloneTableDescription(table.Data))
	now := s.clock.Now()
	refreshDecreaseCount(out.ProvisionedThroughput, now)
	for i := range out.GlobalSecondaryIndexes {
		refreshDecreaseCount(out.GlobalSecondaryIndexes[i].ProvisionedThroughput, now)
	}
	if pending := table.PendingUpdate; pending != nil {
		changingMode := pending.BillingMode != nil && (value(pending.BillingMode) == "PROVISIONED") != provisionedTable(table)
		if pending.BillingMode != nil {
			if out.BillingModeSummary == nil {
				out.BillingModeSummary = &api.BillingModeSummary{}
			}
			out.BillingModeSummary.BillingMode = pending.BillingMode
		}
		stageThroughput(out.ProvisionedThroughput, pending.ProvisionedThroughput, &table.UpdateAcceptedAt, changingMode)
		for i := range out.GlobalSecondaryIndexes {
			index := &out.GlobalSecondaryIndexes[i]
			var wanted *api.ProvisionedThroughput
			for _, change := range pending.GlobalSecondaryIndexUpdates {
				if change.Update != nil && value(change.Update.IndexName) == value(index.IndexName) {
					wanted = change.Update.ProvisionedThroughput
					break
				}
			}
			var at *api.Date
			if !changingMode {
				at = &table.UpdateAcceptedAt
			}
			stageThroughput(index.ProvisionedThroughput, wanted, at, changingMode)
		}
	}
	if err := s.describeReplicas(r, table, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) describeTable(ctx context.Context, tx Transaction, in *api.DescribeTableInput) (*api.DescribeTableOutput, error) {
	table, err := s.controlTable(ctx, tx, value(in.TableName), "DescribeTable", nil)
	if err != nil {
		return nil, err
	}
	description, err := s.tableDescription(tx, &table)
	if err != nil {
		return nil, err
	}
	return &api.DescribeTableOutput{Table: description}, nil
}

func (s *Service) listTables(ctx context.Context, tx Transaction, in *api.ListTablesInput) (*api.ListTablesOutput, error) {
	if err := s.authorize(ctx, "ListTables", "*", nil); err != nil {
		return nil, err
	}
	limit := 100
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 || limit > 100 {
		return nil, failure("ValidationException", "Limit must be between 1 and 100")
	}
	rows, err := tx.Tables(TableQuery{Scope: scopeFor(ctx), After: value(in.ExclusiveStartTableName), Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListTablesOutput{TableNames: api.TableNameList{}}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	for _, row := range rows {
		out.TableNames = append(out.TableNames, api.TableName(row.Key.Name))
	}
	if more {
		out.LastEvaluatedTableName = new(api.TableName(rows[len(rows)-1].Key.Name))
	}
	return out, nil
}

func transitionAvailable(table TableRecord) error {
	if table.PendingCreate != nil || table.PendingUpdate != nil || value(table.Data.TableStatus) != "ACTIVE" {
		return failure("ResourceInUseException", "Attempt to change a resource which is still in use: Table: "+table.Key.Name)
	}
	return nil
}

func (s *Service) deleteTableCommand(ctx context.Context, in *api.DeleteTableInput) (*api.DeleteTableOutput, *awswire.Error) {
	key, planErr := parseTableKey(ctx, value(in.TableName))
	var planned TableRecord
	if planErr == nil {
		planErr = s.repository.View(ctx, func(r Reader) error {
			var err error
			planned, err = r.Table(key)
			return err
		})
	}
	if planErr == nil {
		var release func()
		release, planErr = s.engines.lockData(ctx, planned.DatabaseID)
		if release != nil {
			defer release()
		}
	}
	return runCommand(s, ctx, "DeleteTable", in, func(ctx context.Context, tx Transaction, in *api.DeleteTableInput) (*api.DeleteTableOutput, error) {
		table, err := s.controlTable(ctx, tx, value(in.TableName), "DeleteTable", nil)
		if err != nil {
			return nil, err
		}
		if value(table.Data.TableStatus) == "DELETING" {
			return nil, failure("ResourceInUseException", "Attempt to change a resource which is still in use: Table is being deleted: "+table.Key.Name)
		}
		if err = replicaDeletable(&table, s.clock.Now()); err != nil {
			return nil, err
		}
		if planErr != nil {
			return nil, planErr
		}
		if table.DatabaseID != planned.DatabaseID || table.PhysicalName != planned.PhysicalName {
			return nil, failure("ResourceInUseException", "Attempt to change a resource which is still in use: Table: "+table.Key.Name)
		}
		old := table.Data
		table.Data.TableStatus = new(api.TableStatusDELETING)
		description := api.TableDescription{TableName: old.TableName, TableArn: old.TableArn, TableId: old.TableId, TableStatus: table.Data.TableStatus, TableSizeBytes: old.TableSizeBytes, ItemCount: old.ItemCount, BillingModeSummary: old.BillingModeSummary, TableClassSummary: old.TableClassSummary, DeletionProtectionEnabled: old.DeletionProtectionEnabled, StreamSpecification: old.StreamSpecification, LatestStreamArn: old.LatestStreamArn, LatestStreamLabel: old.LatestStreamLabel}
		if old.ProvisionedThroughput != nil {
			description.ProvisionedThroughput = &api.ProvisionedThroughputDescription{ReadCapacityUnits: old.ProvisionedThroughput.ReadCapacityUnits, WriteCapacityUnits: old.ProvisionedThroughput.WriteCapacityUnits, NumberOfDecreasesToday: new(api.PositiveLongObject(0))}
		}
		if err = tx.PutTable(table); err != nil {
			return nil, err
		}
		return &api.DeleteTableOutput{TableDescription: &description}, nil
	})
}
