package dynamodb

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// Admission shares the source mutation gate with capture and compaction. The
// target transaction pins both the interval and its highest retained sequence;
// subsequent writes at the same service time cannot leak into this restore.
func (s *Service) restoreTableToPointInTimeCommand(ctx context.Context, in *api.RestoreTableToPointInTimeInput) (*api.RestoreTableToPointInTimeOutput, *awswire.Error) {
	key, parseErr := pointInTimeSourceKey(ctx, in)
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
		if planErr == nil {
			// A recovered native commit must publish its images before the
			// sequence upper bound is selected. No engine I/O runs in the tx.
			planErr = s.prepareMutation(ctx, planned.DatabaseID)
		}
	}
	return runCommand(s, ctx, "RestoreTableToPointInTime", in, func(ctx context.Context, tx Transaction, in *api.RestoreTableToPointInTimeInput) (*api.RestoreTableToPointInTimeOutput, error) {
		if parseErr != nil {
			return nil, parseErr
		}
		now := s.clock.Now()
		table, _, err := s.recoveryControlTable(ctx, tx, key, "RestoreTableToPointInTime", now)
		if err != nil {
			return nil, err
		}
		if errors.Is(planErr, ErrNotFound) {
			return nil, failure("TableNotFoundException", "Table not found: "+key.Name)
		}
		if planErr != nil {
			return nil, planErr
		}
		if table.DatabaseID != planned.DatabaseID || table.PhysicalName != planned.PhysicalName {
			return nil, failure("TableNotFoundException", "Table not found: "+key.Name)
		}
		latestRequested := in.UseLatestRestorableTime != nil && bool(*in.UseLatestRestorableTime)
		if in.RestoreDateTime == nil && !latestRequested {
			return nil, failure("ValidationException", "Invalid Request: Either one of RestoreDateTime or UseLatestRestorableTime must be specified, but not both")
		}
		if in.RestoreDateTime != nil && latestRequested {
			return nil, failure("ValidationException", "Invalid Request: Both RestoreDateTime and UseLatestRestorableTime cannot be set for point-in-time restore request. Please specify either RestoreDateTime time or UseLatestRestorableTime")
		}
		if value(table.Data.TableStatus) != "ACTIVE" {
			return nil, failure("TableInUseException", "Source table is being created, changed or deleted")
		}
		if table.RecoveryID == "" {
			return nil, failure("PointInTimeRecoveryUnavailableException", "Point in time recovery is not enabled for the source table")
		}
		recovery, err := tx.Recovery(table.RecoveryID)
		if err != nil {
			return nil, err
		}
		if advanceRecoveryWindow(&recovery, now) {
			if err := tx.PutRecovery(recovery); err != nil {
				return nil, err
			}
		}
		latest := latestRecoveryTime(&recovery, now)
		at := latest
		if in.RestoreDateTime != nil {
			at = in.RestoreDateTime.Round(time.Millisecond)
		}
		// Native explicit points can be newer than the advertised latest bound;
		// the fresh-table capture accepts past points but rejects future ones.
		if at.Before(recovery.EarliestAt) || at.After(now.Round(time.Millisecond)) {
			return nil, failure("InvalidRestoreTimeException", "RestoreDateTime must be within EarliestRestorableDateTime and LatestRestorableDateTime for table "+key.Name)
		}
		sequence, err := tx.RecoverySequence(recovery.ID)
		if err != nil {
			return nil, err
		}
		// Restore metadata uses the current source settings, not the settings
		// at the historical data point. Operational features are not inherited.
		source := backupFromTable(&table)
		create := api.CreateTableInput{
			TableName: new(api.TableArn(*in.TargetTableName)), BillingMode: in.BillingModeOverride,
			ProvisionedThroughput: in.ProvisionedThroughputOverride, OnDemandThroughput: in.OnDemandThroughputOverride,
			GlobalSecondaryIndexes: in.GlobalSecondaryIndexOverride, LocalSecondaryIndexes: in.LocalSecondaryIndexOverride,
			SSESpecification: in.SSESpecificationOverride, VectorIndexes: in.VectorIndexOverride,
		}
		if err := restoreCreateInput(&source, &create); err != nil {
			return nil, err
		}
		restore := &admittedRestore{
			Summary: &api.RestoreSummary{
				RestoreInProgress: new(api.RestoreInProgress(true)), RestoreDateTime: &at,
				SourceTableArn: new(api.TableArn(key.ARN())),
			},
			RecoveryID: recovery.ID, RecoverySequence: sequence,
		}
		target, err := s.admitTable(ctx, tx, &create, restore)
		if err != nil {
			return nil, err
		}
		return &api.RestoreTableToPointInTimeOutput{TableDescription: &target.Data}, nil
	})
}

func pointInTimeSourceKey(ctx context.Context, in *api.RestoreTableToPointInTimeInput) (TableKey, error) {
	if (in.SourceTableName == nil) == (in.SourceTableArn == nil) {
		return TableKey{}, failure("ValidationException", "Specify either SourceTableName or SourceTableArn, but not both")
	}
	if in.SourceTableName != nil {
		return parseTableKey(ctx, value(in.SourceTableName))
	}
	text := value(in.SourceTableArn)
	parsed, err := arn.Parse(text)
	scope := scopeFor(ctx)
	if err != nil || parsed.Service != "dynamodb" || parsed.Partition != scope.Partition || awscatalog.RegionPartition(parsed.Region) != scope.Partition || !strings.HasPrefix(parsed.Resource, "table/") || !tableNamePattern.MatchString(strings.TrimPrefix(parsed.Resource, "table/")) {
		return TableKey{}, failure("ValidationException", "Invalid DynamoDB table ARN: "+text)
	}
	if parsed.AccountID != scope.AccountID {
		return TableKey{}, failure("AccessDeniedException", "Access is denied")
	}
	if parsed.Region != scope.Region {
		if in.SSESpecificationOverride == nil {
			return TableKey{}, failure("ValidationException", "Invalid Request: sseSpecificationOverride must be provided for cross-region restores")
		}
		// TODO: Comeback to cross-region recovery with its KMS dependency;
		// never silently copy unencrypted data across regional scopes.
		return TableKey{}, unsupported("Cross-region DynamoDB point-in-time restore is not implemented.")
	}
	return parseTableKey(ctx, text)
}
