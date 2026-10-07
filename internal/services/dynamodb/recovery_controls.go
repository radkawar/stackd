package dynamodb

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

// Backup registration uses service time; availability also waits for actual
// table creation or restore. This delay is not an AWS readiness deadline.
const continuousBackupsInitializationDelay = 5 * time.Second

func registerRecovery(s *Service) {
	registerControl(s, "DescribeContinuousBackups", s.describeContinuousBackups)
	registerOperation(s, "UpdateContinuousBackups", s.updateContinuousBackupsCommand)
}

func (s *Service) recoveryControlTable(ctx context.Context, r Reader, key TableKey, action string, now time.Time) (TableRecord, api.ContinuousBackupsStatus, error) {
	if err := s.authorizeTable(ctx, r, key, action, "", nil); err != nil {
		return TableRecord{}, "", err
	}
	table, err := r.Table(key)
	if errors.Is(err, ErrNotFound) {
		return TableRecord{}, "", failure("TableNotFoundException", "Table not found: "+key.Name)
	}
	if err != nil {
		return TableRecord{}, "", err
	}
	status := continuousBackupsStatus(&table, now)
	if status == "" {
		return TableRecord{}, "", failure("TableNotFoundException", "Table not found: "+key.Name)
	}
	return table, status, nil
}

func (s *Service) describeContinuousBackups(ctx context.Context, tx Transaction, in *api.DescribeContinuousBackupsInput) (*api.DescribeContinuousBackupsOutput, error) {
	key, err := parseTableKey(ctx, value(in.TableName))
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	table, status, err := s.recoveryControlTable(ctx, tx, key, "DescribeContinuousBackups", now)
	if err != nil {
		return nil, err
	}
	var recovery *RecoveryRecord
	if table.RecoveryID != "" {
		record, err := tx.Recovery(table.RecoveryID)
		if err != nil {
			return nil, err
		}
		advanceRecoveryWindow(&record, now)
		recovery = &record
	}
	return &api.DescribeContinuousBackupsOutput{ContinuousBackupsDescription: continuousBackupsDescription(status, recovery, now)}, nil
}

// Interval ownership changes share the native mutation gate. The engine must
// capture a pending baseline before allowing a later source mutation.
func (s *Service) updateContinuousBackupsCommand(ctx context.Context, in *api.UpdateContinuousBackupsInput) (*api.UpdateContinuousBackupsOutput, *awswire.Error) {
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
		var deleting bool
		if planErr == nil {
			planErr = s.repository.View(ctx, func(r Reader) error {
				current, err := r.Table(key)
				if err != nil {
					return err
				}
				if current.DatabaseID != planned.DatabaseID || current.PhysicalName != planned.PhysicalName {
					return ErrNotFound
				}
				deleting = value(current.Data.TableStatus) == "DELETING"
				return nil
			})
		}
		if planErr == nil && deleting {
			// Deletion can have committed natively before its response was lost.
			// Do not attach a new interval to a source that can no longer supply it.
			var out api.DescribeTableOutput
			planErr = s.callEngine(ctx, &planned, "DescribeTable", &api.DescribeTableInput{TableName: dataPhysical(&planned)}, &out)
			if engineCode(planErr, "ResourceNotFoundException") {
				planErr = ErrNotFound
			}
		}
		if planErr == nil {
			// Settle older native effects before retiring or replacing their
			// interval, including a TTL deletion carrying its original time.
			planErr = s.prepareMutation(ctx, planned.DatabaseID)
		}
	}
	return runCommand(s, ctx, "UpdateContinuousBackups", in, func(ctx context.Context, tx Transaction, in *api.UpdateContinuousBackupsInput) (*api.UpdateContinuousBackupsOutput, error) {
		if parseErr != nil {
			return nil, parseErr
		}
		now := s.clock.Now()
		table, status, err := s.recoveryControlTable(ctx, tx, key, "UpdateContinuousBackups", now)
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
		if status != api.ContinuousBackupsStatusENABLED {
			return nil, failure("ContinuousBackupsUnavailableException", "Backups are being enabled for the table. Please retry later.")
		}
		spec := in.PointInTimeRecoverySpecification
		if !bool(*spec.PointInTimeRecoveryEnabled) {
			if table.RecoveryID != "" {
				table.RecoveryID = ""
				if err := tx.PutTable(table); err != nil {
					return nil, err
				}
			}
			return &api.UpdateContinuousBackupsOutput{ContinuousBackupsDescription: continuousBackupsDescription(api.ContinuousBackupsStatusENABLED, nil, now)}, nil
		}
		// Restorable intervals are captured from the native engine.
		if err := s.requireEngine(); err != nil {
			return nil, err
		}
		var record RecoveryRecord
		changed := false
		if table.RecoveryID == "" {
			id := uuid.NewString()
			record = RecoveryRecord{
				ID: id, Table: table.Key,
				DatabaseID: table.DatabaseID, SourcePhysicalName: table.PhysicalName,
				PhysicalName:         "recovery_" + strings.ReplaceAll(id, "-", ""),
				KeySchema:            table.Data.KeySchema,
				AttributeDefinitions: selectedKeyDefinitions(table.Data.AttributeDefinitions, &api.CreateTableInput{KeySchema: table.Data.KeySchema}),
				RecoveryPeriodInDays: 35, EarliestAt: now.Truncate(time.Second),
			}
			changed = true
		} else {
			record, err = tx.Recovery(table.RecoveryID)
			if err != nil {
				return nil, err
			}
			// Apply the old retention first: increasing it cannot recover history
			// that already expired while this interval was not being described.
			changed = advanceRecoveryWindow(&record, now)
		}
		if spec.RecoveryPeriodInDays != nil && int(*spec.RecoveryPeriodInDays) != record.RecoveryPeriodInDays {
			record.RecoveryPeriodInDays = int(*spec.RecoveryPeriodInDays)
			advanceRecoveryWindow(&record, now)
			changed = true
		}
		if changed {
			if err := tx.PutRecovery(record); err != nil {
				return nil, err
			}
		}
		if table.RecoveryID == "" {
			table.RecoveryID = record.ID
			if err := tx.PutTable(table); err != nil {
				return nil, err
			}
		}
		return &api.UpdateContinuousBackupsOutput{ContinuousBackupsDescription: continuousBackupsDescription(api.ContinuousBackupsStatusENABLED, &record, now)}, nil
	})
}

// advanceRecoveryWindow never moves the retained lower bound backwards. Reads
// project it; settings changes persist it before increasing retention.
func advanceRecoveryWindow(record *RecoveryRecord, now time.Time) bool {
	earliest := now.Add(-time.Duration(record.RecoveryPeriodInDays) * 24 * time.Hour).Truncate(time.Second)
	if !earliest.After(record.EarliestAt) {
		return false
	}
	record.EarliestAt = earliest
	return true
}

func latestRecoveryTime(record *RecoveryRecord, now time.Time) time.Time {
	// Model the sampled native lag using service time, without assuming a
	// particular native snapshot algorithm or advancement cadence.
	latest := now.Add(-5 * time.Minute).Truncate(time.Millisecond)
	if latest.Before(record.EarliestAt) {
		return record.EarliestAt
	}
	return latest
}

func continuousBackupsStatus(table *TableRecord, now time.Time) api.ContinuousBackupsStatus {
	initializing := now.Before(time.Time(*table.Data.CreationDateTime).Add(continuousBackupsInitializationDelay))
	creating := value(table.Data.TableStatus) == "CREATING"
	if creating && initializing {
		return "" // The backup control plane has not registered the new table yet.
	}
	if creating || initializing {
		return api.ContinuousBackupsStatusDISABLED
	}
	return api.ContinuousBackupsStatusENABLED
}

func continuousBackupsDescription(status api.ContinuousBackupsStatus, record *RecoveryRecord, now time.Time) *api.ContinuousBackupsDescription {
	pitr := &api.PointInTimeRecoveryDescription{PointInTimeRecoveryStatus: new(api.PointInTimeRecoveryStatusDISABLED)}
	if record != nil {
		pitr.PointInTimeRecoveryStatus = new(api.PointInTimeRecoveryStatusENABLED)
		pitr.RecoveryPeriodInDays = new(api.RecoveryPeriodInDays(record.RecoveryPeriodInDays))
		pitr.EarliestRestorableDateTime = new(record.EarliestAt)
		pitr.LatestRestorableDateTime = new(latestRecoveryTime(record, now))
	}
	return &api.ContinuousBackupsDescription{ContinuousBackupsStatus: &status, PointInTimeRecoveryDescription: pitr}
}
