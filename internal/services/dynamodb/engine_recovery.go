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

func recoverySpecification(record *RecoveryRecord) engine.Specification {
	return engine.Specification{ID: record.DatabaseID, Partition: record.Table.Partition, AccountID: record.Table.AccountID, Region: record.Table.Region}
}

// resolveRecoveries holds the database mutation gate. Baselines precede later
// source writes; retired intervals remain available to already admitted restores.
func (s *Service) resolveRecoveries(ctx context.Context, databaseID string) error {
	if err := s.resolveMutationCapture(ctx, databaseID); err != nil {
		return err
	}
	var records []RecoveryRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		records, err = r.UnsettledRecoveries(databaseID)
		return err
	}); err != nil {
		return err
	}
	for _, record := range records {
		if _, err := s.reconcileRecovery(ctx, record); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reconcileRecovery(ctx context.Context, record RecoveryRecord) (time.Time, error) {
	var active, pinned bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		record, err = r.Recovery(record.ID)
		if err != nil {
			return err
		}
		consumers, err := r.ActiveWriteConsumers(record.Table, record.SourcePhysicalName)
		if err != nil {
			return err
		}
		active = consumers.RecoveryID == record.ID
		pending, err := r.PendingTables()
		if err != nil {
			return err
		}
		for _, table := range pending {
			if table.RestoreRecoveryID == record.ID {
				pinned = true
				break
			}
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if active {
		advanceRecoveryWindow(&record, s.clock.Now())
	}
	db, err := s.engines.database(ctx, recoverySpecification(&record))
	if err != nil {
		return time.Time{}, err
	}
	if !active && !pinned {
		removed, err := deleteNativeTable(ctx, db, record.PhysicalName)
		if err != nil {
			return time.Time{}, err
		}
		if !removed {
			return time.Time{}, fmt.Errorf("native recovery baseline %s is still deleting", record.ID)
		}
		return time.Time{}, s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteRecovery(record.ID) })
	}
	if record.SnapshotAt == nil {
		in := &api.CreateTableInput{TableName: new(api.TableArn(record.PhysicalName)), BillingMode: new(api.BillingModePAY_PER_REQUEST), KeySchema: record.KeySchema, AttributeDefinitions: record.AttributeDefinitions}
		ready, err := createNativeSnapshot(ctx, db, in, record.SourcePhysicalName)
		if err != nil {
			return time.Time{}, err
		}
		if !ready {
			return time.Time{}, fmt.Errorf("native recovery baseline %s is not ready", record.ID)
		}
		record.SnapshotAt = new(record.EarliestAt)
		if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutRecovery(record) }); err != nil {
			return time.Time{}, err
		}
	}
	if pinned {
		// Retry needs the same baseline and its tombstones. Folding while a
		// partial target exists could otherwise leave items absent from the
		// new baseline but no longer removed by the retained history.
		return time.Time{}, nil
	}
	for {
		if record.CompactThrough == nil {
			var changes []RecoveryChange
			if err := s.repository.View(ctx, func(r Reader) error {
				var err error
				changes, err = r.RecoveryChanges(RecoveryChangeQuery{RecoveryID: record.ID, Limit: 1})
				return err
			}); err != nil {
				return time.Time{}, err
			}
			if len(changes) == 0 {
				return time.Time{}, nil
			}
			advanceRecoveryWindow(&record, s.clock.Now())
			if !changes[0].At.Before(record.EarliestAt) {
				// Keep the boundary instant in the log until it ages out.
				// Retention advances at whole-second service-time edges.
				due := changes[0].At.Truncate(time.Second).Add(time.Duration(record.RecoveryPeriodInDays)*24*time.Hour + time.Second)
				return due, nil
			}
			record.CompactThrough = new(record.EarliestAt)
			if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutRecovery(record) }); err != nil {
				return time.Time{}, err
			}
		}
		query := RecoveryChangeQuery{RecoveryID: record.ID, Through: *record.CompactThrough}
		if err := s.applyRecoveryChanges(ctx, db, &record, record.PhysicalName, query); err != nil {
			return time.Time{}, err
		}
		through := *record.CompactThrough
		record.SnapshotAt, record.CompactThrough = &through, nil
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			if err := tx.DeleteRecoveryChanges(record.ID, through); err != nil {
				return err
			}
			return tx.PutRecovery(record)
		}); err != nil {
			return time.Time{}, err
		}
	}
}

// Each page is bounded by the native write count. Equal-key images in a page
// collapse to their last state; BatchWriteItem rejects duplicate keys.
func (s *Service) applyRecoveryChanges(ctx context.Context, db engine.Database, record *RecoveryRecord, target string, query RecoveryChangeQuery) error {
	model, _ := awscatalog.LookupService("dynamodb")
	query.Limit = 25
	for {
		var changes []RecoveryChange
		if err := s.repository.View(ctx, func(r Reader) error {
			var err error
			changes, err = r.RecoveryChanges(query)
			return err
		}); err != nil {
			return err
		}
		if len(changes) == 0 {
			return nil
		}
		positions := make(map[capacityItemID]int, len(changes))
		writes := make(api.WriteRequests, 0, len(changes))
		for _, change := range changes {
			id := capacityKeyID(target, record.KeySchema, change.Key)
			position, found := positions[id]
			if !found {
				position = len(writes)
				positions[id] = position
				writes = append(writes, api.WriteRequest{})
			}
			if change.Item == nil {
				writes[position] = api.WriteRequest{DeleteRequest: &api.DeleteRequest{Key: change.Key}}
			} else {
				writes[position] = api.WriteRequest{PutRequest: &api.PutRequest{Item: api.PutItemInputAttributeMap(change.Item)}}
			}
		}
		var out api.BatchWriteItemOutput
		if err := nativeCall(ctx, db, model, "BatchWriteItem", &api.BatchWriteItemInput{RequestItems: api.BatchWriteItemRequestMap{api.TableArn(target): writes}}, &out, nil); err != nil {
			return err
		}
		for _, pending := range out.UnprocessedItems {
			if len(pending) != 0 {
				return errors.New("native recovery fold left unprocessed items")
			}
		}
		query.After = changes[len(changes)-1].Sequence
	}
}

func (s *Service) maintainRecoveries(ctx context.Context) (time.Time, bool, error) {
	var records []RecoveryRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		records, err = r.Recoveries("")
		return err
	}); err != nil {
		return time.Time{}, true, err
	}
	groups := make(map[string][]RecoveryRecord)
	var databases []string
	for _, record := range records {
		if len(groups[record.DatabaseID]) == 0 {
			databases = append(databases, record.DatabaseID)
		}
		groups[record.DatabaseID] = append(groups[record.DatabaseID], record)
	}
	var combined error
	var next time.Time
	for _, databaseID := range databases {
		release, err := s.engines.lockData(ctx, databaseID)
		if err != nil {
			return next, true, errors.Join(combined, err)
		}
		if err = s.resolveMutationCapture(ctx, databaseID); err == nil {
			for _, record := range groups[databaseID] {
				deadline, recordErr := s.reconcileRecovery(ctx, record)
				err = errors.Join(err, recordErr)
				if !deadline.IsZero() && (next.IsZero() || deadline.Before(next)) {
					next = deadline
				}
			}
		}
		release()
		combined = errors.Join(combined, err)
	}
	return next, combined != nil, combined
}
