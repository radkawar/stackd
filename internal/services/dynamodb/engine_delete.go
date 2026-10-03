package dynamodb

import (
	"context"
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

// deleteTableData chooses the final PITR configuration under the native data
// gate. DeleteTable admission alone does not freeze that configuration: AWS
// accepts continuous-backup changes while the source is still DELETING.
func (s *Service) deleteTableData(ctx context.Context, table *TableRecord) error {
	return s.withMutation(ctx, table, func() error {
		// A lost delete response leaves metadata behind an absent native table.
		// In particular, do not recreate an expired SYSTEM snapshot on retry.
		var observed api.DescribeTableOutput
		if err := s.callEngine(ctx, table, "DescribeTable", &api.DescribeTableInput{TableName: dataPhysical(table)}, &observed); err != nil {
			return err
		}
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Table(table.Key)
			if err != nil {
				return err
			}
			previous, err := tx.Backups(BackupQuery{Scope: current.Key.Scope, TableName: current.Key.Name, Type: string(api.BackupTypeSYSTEM)})
			if err != nil {
				return err
			}
			// The physical source still exists, so a previous attempt did not
			// finish deletion. Replace its snapshot with the current final state;
			// admitted restores retain their old snapshot until they finish.
			for _, backup := range previous {
				if value(backup.Description.SourceTableDetails.TableId) != value(current.Data.TableId) {
					continue
				}
				backup.Description.BackupDetails.BackupStatus = new(api.BackupStatusDELETED)
				if err := tx.PutBackup(backup); err != nil {
					return err
				}
			}
			if current.RecoveryID == "" {
				return nil
			}
			recovery, err := tx.Recovery(current.RecoveryID)
			if err != nil {
				return err
			}
			retention := time.Duration(recovery.RecoveryPeriodInDays) * 24 * time.Hour
			_, err = s.allocateBackup(tx, &current, new(api.BackupName(current.Key.Name+"$DeletedTableBackup")), api.BackupTypeSYSTEM, &retention)
			return err
		}); err != nil {
			return err
		}
		if err := s.resolveBackups(ctx, table.DatabaseID); err != nil {
			return err
		}
		var out api.DeleteTableOutput
		return s.callEngine(ctx, table, "DeleteTable", &api.DeleteTableInput{TableName: dataPhysical(table)}, &out)
	})
}
