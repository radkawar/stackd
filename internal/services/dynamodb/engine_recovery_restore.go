package dynamodb

import "context"

// The database gate covers the baseline plus ordered image application. Pending
// targets pin their source baseline, so retrying an interrupted copy cannot lose
// the tombstones needed to remove items from a partially populated target.
func (s *Service) restoreRecoveryData(ctx context.Context, table *TableRecord) error {
	var record RecoveryRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		record, err = r.Recovery(table.RestoreRecoveryID)
		return err
	}); err != nil {
		return err
	}
	db, err := s.engines.database(ctx, tableSpecification(table))
	if err != nil {
		return err
	}
	if err := copyNativeTable(ctx, db, db, record.PhysicalName, table.PhysicalName); err != nil {
		return err
	}
	return s.applyRecoveryChanges(ctx, db, &record, table.PhysicalName, RecoveryChangeQuery{
		RecoveryID:      record.ID,
		Through:         *table.Data.RestoreSummary.RestoreDateTime,
		ThroughSequence: &table.RestoreRecoverySequence,
	})
}
