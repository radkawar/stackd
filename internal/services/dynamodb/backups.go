package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

var backupIDPattern = regexp.MustCompile(`^[0-9]{14}-[0-9a-fA-F]{8}$`)

func registerBackups(s *Service) {
	registerOperation(s, "CreateBackup", s.createBackupCommand)
	registerControl(s, "DescribeBackup", s.describeBackup)
	registerControl(s, "ListBackups", s.listBackups)
	registerControl(s, "DeleteBackup", s.deleteBackup)
	registerControl(s, "RestoreTableFromBackup", s.restoreTableFromBackup)
}

// Admit the marker under the same gate as native mutations. A later mutation
// must resolve this pending snapshot before changing its source data.
func (s *Service) createBackupCommand(ctx context.Context, in *api.CreateBackupInput) (*api.CreateBackupOutput, *awswire.Error) {
	key, parseErr := parseTableKey(ctx, value(in.TableName))
	var planned TableRecord
	planErr := parseErr
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
	return runCommand(s, ctx, "CreateBackup", in, func(ctx context.Context, tx Transaction, in *api.CreateBackupInput) (*api.CreateBackupOutput, error) {
		if parseErr != nil {
			return nil, parseErr
		}
		if err := s.authorizeTable(ctx, tx, key, "CreateBackup", "", nil); err != nil {
			return nil, err
		}
		// Backups are native engine snapshots completed by the controller.
		if err := s.requireEngine(); err != nil {
			return nil, err
		}
		table, err := tx.Table(key)
		if errors.Is(err, ErrNotFound) {
			return nil, failure("TableNotFoundException", "Requested source table not found: "+key.Name)
		}
		if err != nil {
			return nil, err
		}
		if planErr != nil {
			return nil, planErr
		}
		if table.DatabaseID != planned.DatabaseID || table.PhysicalName != planned.PhysicalName || value(table.Data.TableStatus) != "ACTIVE" {
			return nil, failure("TableInUseException", "Source table is being created, changed or deleted")
		}
		backup, err := s.allocateBackup(tx, &table, in.BackupName, api.BackupTypeUSER, nil)
		if err != nil {
			return nil, err
		}
		return &api.CreateBackupOutput{BackupDetails: backup.Description.BackupDetails}, nil
	})
}

// allocateBackup commits an immutable snapshot marker before any later native
// mutation. Both on-demand admission and PITR source deletion hold lockData.
func (s *Service) allocateBackup(tx Transaction, table *TableRecord, name *api.BackupName, kind api.BackupType, retention *time.Duration) (BackupRecord, error) {
	now := s.clock.Now().Truncate(time.Millisecond)
	backup := backupFromTable(table)
	backup.Key = BackupKey{Scope: table.Key.Scope, TableName: table.Key.Name}
	prefix := fmt.Sprintf("%014d-", now.UnixMilli())
	var id string
	for {
		id = strings.ReplaceAll(uuid.NewString(), "-", "")
		backup.Key.ID = prefix + id[:8]
		if _, err := tx.Backup(backup.Key); errors.Is(err, ErrNotFound) {
			break
		} else if err != nil {
			return BackupRecord{}, err
		}
	}
	backup.DatabaseID, backup.SourcePhysicalName, backup.PhysicalName = table.DatabaseID, table.PhysicalName, "backup_"+id
	backup.Description.BackupDetails = &api.BackupDetails{
		BackupArn: new(api.BackupArn(backup.Key.ARN())), BackupName: name, BackupCreationDateTime: &now,
		BackupStatus: new(api.BackupStatusCREATING), BackupType: &kind, BackupSizeBytes: new(api.BackupSizeBytes(*table.Data.TableSizeBytes)),
	}
	if retention != nil {
		backup.Description.BackupDetails.BackupExpiryDateTime = new(now.Add(*retention))
	}
	return backup, tx.PutBackup(backup)
}

func backupFromTable(table *TableRecord) BackupRecord {
	data := &table.Data
	mode := api.BillingModePROVISIONED
	if data.BillingModeSummary != nil {
		mode = *data.BillingModeSummary.BillingMode
	}
	features := &api.SourceTableFeatureDetails{StreamDescription: data.StreamSpecification, TimeToLiveDescription: &table.TTL}
	for _, index := range data.GlobalSecondaryIndexes {
		features.GlobalSecondaryIndexes = append(features.GlobalSecondaryIndexes, api.GlobalSecondaryIndexInfo{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection, ProvisionedThroughput: capacityFromDescription(index.ProvisionedThroughput), OnDemandThroughput: index.OnDemandThroughput})
	}
	for _, index := range data.LocalSecondaryIndexes {
		features.LocalSecondaryIndexes = append(features.LocalSecondaryIndexes, api.LocalSecondaryIndexInfo{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection})
	}
	return BackupRecord{AttributeDefinitions: data.AttributeDefinitions, Description: api.BackupDescription{
		SourceTableDetails: &api.SourceTableDetails{
			TableName: data.TableName, TableArn: new(api.TableArn(table.Key.ARN())), TableId: data.TableId, TableCreationDateTime: data.CreationDateTime,
			BillingMode: &mode, KeySchema: data.KeySchema, ProvisionedThroughput: capacityFromDescription(data.ProvisionedThroughput), OnDemandThroughput: data.OnDemandThroughput,
			ItemCount: new(api.ItemCount(*data.ItemCount)), TableSizeBytes: data.TableSizeBytes,
		}, SourceTableFeatureDetails: features,
	}}
}

func parseBackupKey(scope Scope, text string) (BackupKey, error) {
	parsed, err := arn.Parse(text)
	if err != nil {
		return BackupKey{}, failure("ValidationException", "Invalid Request: BackupArn is not valid")
	}
	// Native rejects foreign accounts before validating the ARN components.
	if parsed.AccountID != scope.AccountID {
		return BackupKey{}, failure("AccessDeniedException", "Access is denied")
	}
	region := strings.ToLower(parsed.Region)
	if parsed.Service != "dynamodb" || parsed.Partition != scope.Partition || awscatalog.RegionPartition(region) != scope.Partition {
		return BackupKey{}, failure("ValidationException", "Invalid Request: BackupArn is not valid")
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) != 4 || parts[0] != "table" || parts[2] != "backup" || !backupIDPattern.MatchString(parts[3]) {
		return BackupKey{}, failure("ValidationException", "Invalid Request: BackupArn is not valid")
	}
	if !tableNamePattern.MatchString(parts[1]) {
		return BackupKey{}, failure("ValidationException", "Invalid Backup ARN")
	}
	scope.Region = parsed.Region
	return BackupKey{Scope: scope, TableName: parts[1], ID: parts[3]}, nil
}

func (s *Service) controlBackup(ctx context.Context, r Reader, key BackupKey, action string) (BackupRecord, error) {
	// Metadata lookup and authorization use the endpoint region. The request ARN
	// can name another region; Restore validates cross-region requests separately.
	key.Region = scopeFor(ctx).Region
	if err := s.authorize(ctx, action, key.ARN(), nil); err != nil {
		return BackupRecord{}, err
	}
	backup, err := r.Backup(key)
	if errors.Is(err, ErrNotFound) || err == nil && (value(backup.Description.BackupDetails.BackupStatus) == "DELETED" || backupExpired(&backup, s.clock.Now())) {
		return BackupRecord{}, failure("BackupNotFoundException", "Backup not found for the given BackupArn")
	}
	return backup, err
}

func (s *Service) describeBackup(ctx context.Context, tx Transaction, in *api.DescribeBackupInput) (*api.DescribeBackupOutput, error) {
	key, err := parseBackupKey(scopeFor(ctx), value(in.BackupArn))
	if err != nil {
		return nil, err
	}
	backup, err := s.controlBackup(ctx, tx, key, "DescribeBackup")
	if err != nil {
		return nil, err
	}
	backup.Description.BackupDetails.BackupArn = in.BackupArn
	return &api.DescribeBackupOutput{BackupDescription: &backup.Description}, nil
}

func (s *Service) listBackups(ctx context.Context, tx Transaction, in *api.ListBackupsInput) (*api.ListBackupsOutput, error) {
	if err := s.authorize(ctx, "ListBackups", "*", nil); err != nil {
		return nil, err
	}
	query := BackupQuery{Scope: scopeFor(ctx), After: value(in.ExclusiveStartBackupArn), At: s.clock.Now()}
	if in.TimeRangeLowerBound != nil {
		query.Lower = in.TimeRangeLowerBound.Round(time.Millisecond)
	}
	if in.TimeRangeUpperBound != nil {
		query.Upper = in.TimeRangeUpperBound.Round(time.Millisecond)
	}
	if in.TimeRangeLowerBound != nil && in.TimeRangeUpperBound != nil && query.Lower.After(query.Upper) {
		return nil, invalidTable("Time range lower bound must be less than or equal to upper bound")
	}
	out := &api.ListBackupsOutput{BackupSummaries: api.BackupSummaries{}}
	query.Type = value(in.BackupType)
	if query.Type == "ALL" {
		query.Type = ""
	}
	limit := 100
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	query.Limit = limit + 1
	if in.TableName != nil {
		key, err := parseTableKey(ctx, value(in.TableName))
		if err != nil {
			return nil, err
		}
		if key.Scope != query.Scope {
			return out, nil
		}
		query.TableName = key.Name
	}
	backups, err := tx.Backups(query)
	if err != nil {
		return nil, err
	}
	more := len(backups) > limit
	if more {
		backups = backups[:limit]
	}
	for _, backup := range backups {
		d, source := backup.Description.BackupDetails, backup.Description.SourceTableDetails
		out.BackupSummaries = append(out.BackupSummaries, api.BackupSummary{BackupArn: d.BackupArn, BackupCreationDateTime: d.BackupCreationDateTime, BackupExpiryDateTime: d.BackupExpiryDateTime, BackupName: d.BackupName, BackupSizeBytes: d.BackupSizeBytes, BackupStatus: d.BackupStatus, BackupType: d.BackupType, TableArn: source.TableArn, TableName: source.TableName, TableId: source.TableId})
	}
	if more {
		out.LastEvaluatedBackupArn = out.BackupSummaries[len(out.BackupSummaries)-1].BackupArn
	}
	return out, nil
}

func (s *Service) deleteBackup(ctx context.Context, tx Transaction, in *api.DeleteBackupInput) (*api.DeleteBackupOutput, error) {
	key, err := parseBackupKey(scopeFor(ctx), value(in.BackupArn))
	if err != nil {
		return nil, err
	}
	backup, err := s.controlBackup(ctx, tx, key, "DeleteBackup")
	if err != nil {
		return nil, err
	}
	if value(backup.Description.BackupDetails.BackupType) == "SYSTEM" {
		return nil, failure("ValidationException", "User is not allowed to delete the system backup; it will automatically expire on "+backup.Description.BackupDetails.BackupExpiryDateTime.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	if value(backup.Description.BackupDetails.BackupStatus) != "AVAILABLE" {
		return nil, failure("BackupInUseException", "Backup is being created")
	}
	tables, err := tx.PendingTables()
	if err != nil {
		return nil, err
	}
	backupARN := backup.Key.ARN()
	for _, table := range tables {
		if restore := table.Data.RestoreSummary; restore != nil && value(restore.SourceBackupArn) == backupARN {
			return nil, failure("BackupInUseException", "Backup is being restored")
		}
	}
	backup.Description.BackupDetails.BackupStatus = new(api.BackupStatusDELETED)
	if err := tx.PutBackup(backup); err != nil {
		return nil, err
	}
	backup.Description.BackupDetails.BackupArn = in.BackupArn
	return &api.DeleteBackupOutput{BackupDescription: &backup.Description}, nil
}

func backupExpired(backup *BackupRecord, at time.Time) bool {
	expiry := backup.Description.BackupDetails.BackupExpiryDateTime
	return expiry != nil && !expiry.After(at)
}
