package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	engine "stackd/engine/dynamodb"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
)

func backupSpecification(backup *BackupRecord) engine.Specification {
	return engine.Specification{ID: backup.DatabaseID, Partition: backup.Key.Partition, AccountID: backup.Key.AccountID, Region: backup.Key.Region}
}

// prepareMutation runs with lockData held. Snapshot markers precede both new
// customer writes and completion of an outstanding TTL deletion.
func (s *Service) prepareMutation(ctx context.Context, databaseID string) error {
	if err := s.resolveBackups(ctx, databaseID); err != nil {
		return err
	}
	if err := s.resolveRecoveries(ctx, databaseID); err != nil {
		return err
	}
	return s.resolveTTLDeletion(ctx, databaseID)
}

func (s *Service) resolveBackups(ctx context.Context, databaseID string) error {
	var pending []BackupRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		pending, err = r.UncapturedBackups(databaseID)
		return err
	}); err != nil {
		return err
	}
	for i := range pending {
		again, err := s.captureBackup(ctx, &pending[i])
		if err != nil {
			return err
		}
		if again {
			return fmt.Errorf("native snapshot table for backup %s is not ready", pending[i].Key.ARN())
		}
	}
	return nil
}

func (s *Service) reconcileBackups(ctx context.Context) (time.Time, bool, error) {
	now := s.clock.Now()
	var pending []BackupRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		pending, err = r.PendingBackups(now)
		return err
	}); err != nil {
		return time.Time{}, true, err
	}
	var retry bool
	var combined error
	for _, backup := range pending {
		again, err := s.reconcileBackup(ctx, backup.Key, backup.DatabaseID)
		retry = retry || again || err != nil
		combined = errors.Join(combined, err)
		if ctx.Err() != nil {
			break
		}
	}
	var deadline time.Time
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		deadline, err = r.NextBackupExpiry(now)
		return err
	})
	return deadline, retry || err != nil, errors.Join(combined, err)
}

func (s *Service) reconcileBackup(ctx context.Context, key BackupKey, databaseID string) (bool, error) {
	release, err := s.engines.lockData(ctx, databaseID)
	if err != nil {
		return false, err
	}
	defer release()
	var current BackupRecord
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		current, err = r.Backup(key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if value(current.Description.BackupDetails.BackupStatus) == "CREATING" {
		again, err := s.captureBackup(ctx, &current)
		if again || err != nil {
			return again, err
		}
	}
	if value(current.Description.BackupDetails.BackupStatus) != "DELETED" && !backupExpired(&current, s.clock.Now()) {
		return false, nil
	}
	// Admission and retirement serialize in the repository. Expired backups
	// reject new restores, but an already accepted target retains the snapshot
	// until ACTIVE, including after restart.
	pinned := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		tables, err := tx.PendingTables()
		if err != nil {
			return err
		}
		for _, table := range tables {
			if restore := table.Data.RestoreSummary; restore != nil && value(restore.SourceBackupArn) == current.Key.ARN() {
				pinned = true
				return nil
			}
		}
		if value(current.Description.BackupDetails.BackupStatus) != "DELETED" {
			current.Description.BackupDetails.BackupStatus = new(api.BackupStatusDELETED)
			return tx.PutBackup(current)
		}
		return nil
	})
	if err != nil || pinned {
		return pinned, err
	}
	db, err := s.engines.database(ctx, backupSpecification(&current))
	if err != nil {
		return false, err
	}
	removed, err := deleteNativeTable(ctx, db, current.PhysicalName)
	if err != nil {
		return false, err
	}
	if !removed {
		return true, nil
	}
	return false, s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteBackup(key) })
}

// captureBackup holds the database mutation gate for the whole paginated copy.
// Strongly consistent Scan alone does not isolate pages from concurrent writes.
// Retrying an interrupted copy is safe because pending snapshots exclude later
// mutations, and every native Put replaces the same immutable source item.
func (s *Service) captureBackup(ctx context.Context, backup *BackupRecord) (bool, error) {
	db, err := s.engines.database(ctx, backupSpecification(backup))
	if err != nil {
		return false, err
	}
	in := api.CreateTableInput{TableName: new(api.TableArn(backup.PhysicalName)), BillingMode: new(api.BillingModePAY_PER_REQUEST), KeySchema: backup.Description.SourceTableDetails.KeySchema}
	in.AttributeDefinitions = selectedKeyDefinitions(backup.AttributeDefinitions, &in)
	ready, err := createNativeSnapshot(ctx, db, &in, backup.SourcePhysicalName)
	if err != nil {
		return false, err
	}
	if !ready {
		return true, nil
	}
	backup.Description.BackupDetails.BackupStatus = new(api.BackupStatusAVAILABLE)
	backup.SourcePhysicalName = ""
	return false, s.repository.Update(ctx, func(tx Transaction) error { return tx.PutBackup(*backup) })
}

// Each source page is at most the engine's Scan page size. Chunking that page
// into at most 25 puts respects BatchWriteItem's count and payload limits without
// copying the full table into the control plane or charging customer admission.
func copyNativeTable(ctx context.Context, sourceDB, targetDB engine.Database, source, target string) error {
	model, _ := awscatalog.LookupService("dynamodb")
	in := api.ScanInput{TableName: new(api.TableArn(source)), ConsistentRead: new(api.ConsistentRead(true))}
	for {
		var page api.ScanOutput
		if err := nativeCall(ctx, sourceDB, model, "Scan", &in, &page, nil); err != nil {
			return err
		}
		for offset := 0; offset < len(page.Items); offset += 25 {
			items := page.Items[offset:min(offset+25, len(page.Items))]
			writes := make(api.WriteRequests, len(items))
			for i, item := range items {
				writes[i].PutRequest = &api.PutRequest{Item: api.PutItemInputAttributeMap(item)}
			}
			batch := api.BatchWriteItemInput{RequestItems: api.BatchWriteItemRequestMap{api.TableArn(target): writes}}
			var out api.BatchWriteItemOutput
			if err := nativeCall(ctx, targetDB, model, "BatchWriteItem", &batch, &out, nil); err != nil {
				return err
			}
			for _, remaining := range out.UnprocessedItems {
				if len(remaining) != 0 {
					return errors.New("native snapshot copy left unprocessed items")
				}
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

// A backup preserves all original definitions, while a physical snapshot or
// index-excluding restore needs only those referenced by its requested keys.
func selectedKeyDefinitions(definitions api.AttributeDefinitions, in *api.CreateTableInput) api.AttributeDefinitions {
	used := make(map[api.KeySchemaAttributeName]bool)
	add := func(keys api.KeySchema) {
		for _, key := range keys {
			used[*key.AttributeName] = true
		}
	}
	add(in.KeySchema)
	for _, index := range in.GlobalSecondaryIndexes {
		add(index.KeySchema)
	}
	for _, index := range in.LocalSecondaryIndexes {
		add(index.KeySchema)
	}
	out := make(api.AttributeDefinitions, 0, len(used))
	for _, definition := range definitions {
		if used[*definition.AttributeName] {
			out = append(out, definition)
		}
	}
	return out
}
