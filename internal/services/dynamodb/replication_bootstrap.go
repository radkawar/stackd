package dynamodb

import (
	"context"
	"errors"
	"fmt"

	engine "stackd/engine/dynamodb"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
)

func replicaSnapshotSpecification(bootstrap *ReplicaBootstrap) engine.Specification {
	key := bootstrap.Source
	return engine.Specification{ID: bootstrap.SourceDatabaseID, Partition: key.Partition, AccountID: key.AccountID, Region: key.Region}
}

// prepareReplicaTable runs outside either database gate. The immutable source
// snapshot is the handoff between gates; a destination never locks its source.
func (s *Service) prepareReplicaTable(ctx context.Context, table *TableRecord) (bool, error) {
	var bootstrap ReplicaBootstrap
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		bootstrap, err = r.ReplicaBootstrap(table.Key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !bootstrap.Ready {
		ready, err := s.captureReplicaBootstrap(ctx, bootstrap)
		if err != nil || !ready {
			return false, err
		}
	}

	release, err := s.engines.lockData(ctx, table.DatabaseID)
	if err != nil {
		return false, err
	}
	defer release()
	var target TableRecord
	err = s.repository.View(ctx, func(r Reader) error {
		current, err := r.ReplicaBootstrap(table.Key)
		if err != nil {
			return err
		}
		if current.SnapshotPhysicalName != bootstrap.SnapshotPhysicalName {
			return ErrNotFound
		}
		bootstrap = current
		target, err = r.Table(table.Key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if target.PhysicalName != table.PhysicalName || target.Replica.GroupID == "" || value(target.Data.TableStatus) == "DELETING" || !bootstrap.Ready {
		return false, nil
	}
	if !bootstrap.Copied {
		// Public writes and replica delivery both exclude an uncopied target.
		// A lost native response can therefore replay this immutable baseline,
		// but must never rescan the now-changing source table.
		if value(target.Data.TableStatus) != "CREATING" {
			return false, fmt.Errorf("uncopied replica %s is not creating", target.Key.ARN())
		}
		access, err := s.replicaAccess(ctx, bootstrap.Source, &target, "PutItem")
		if err != nil {
			return false, err
		}
		sourceDB, err := s.engines.database(access, replicaSnapshotSpecification(&bootstrap))
		if err != nil {
			return false, err
		}
		targetDB, err := s.engines.database(access, tableSpecification(&target))
		if err != nil {
			return false, err
		}
		if err := copyNativeTable(access, sourceDB, targetDB, bootstrap.SnapshotPhysicalName, target.PhysicalName); err != nil {
			return false, err
		}
	}

	ready := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.ReplicaBootstrap(target.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.SnapshotPhysicalName != bootstrap.SnapshotPhysicalName || !current.Ready {
			return nil
		}
		member, err := tx.Table(target.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if member.PhysicalName != target.PhysicalName || member.Replica.GroupID != target.Replica.GroupID || value(member.Data.TableStatus) == "DELETING" {
			return nil
		}
		if !current.Copied {
			if err := tx.InstallReplicaVersions(member.Key, member.PhysicalName); err != nil {
				return err
			}
			member.Replica.Cursor = current.Cursor
			if err := tx.PutTable(member); err != nil {
				return err
			}
			current.Copied = true
			if err := tx.PutReplicaBootstrap(current); err != nil {
				return err
			}
		}
		tail, err := tx.ReplicaSequence(member.Replica.GroupID)
		if err != nil {
			return err
		}
		ready = member.Replica.Cursor >= tail
		return nil
	})
	return ready, err
}

// maintainReplicaBootstraps also owns cancelled snapshots. Their source database
// remains retained until native absence is observed, even after target deletion.
func (s *Service) maintainReplicaBootstraps(ctx context.Context) (bool, error) {
	var bootstraps []ReplicaBootstrap
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		bootstraps, err = r.ReplicaBootstraps("")
		return err
	}); err != nil {
		return true, err
	}
	var retry bool
	var combined error
	for _, bootstrap := range bootstraps {
		ready, err := s.captureReplicaBootstrap(ctx, bootstrap)
		retry = retry || !ready || err != nil
		combined = errors.Join(combined, err)
		if ctx.Err() != nil {
			break
		}
	}
	return retry, combined
}

// captureReplicaBootstrap serializes snapshot creation and retirement using only
// the source gate. The repository transaction pins versions and the source's
// consumed cursor at the same cut as the completed, strongly consistent copy.
func (s *Service) captureReplicaBootstrap(ctx context.Context, expected ReplicaBootstrap) (bool, error) {
	release, err := s.engines.lockData(ctx, expected.SourceDatabaseID)
	if err != nil {
		return false, err
	}
	defer release()
	var bootstrap ReplicaBootstrap
	var target TableRecord
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		bootstrap, err = r.ReplicaBootstrap(expected.Table)
		if err != nil {
			return err
		}
		if bootstrap.SnapshotPhysicalName != expected.SnapshotPhysicalName {
			return ErrNotFound
		}
		target, err = r.Table(bootstrap.Table)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	cancelled := target.PhysicalName == "" || target.Replica.GroupID == "" || value(target.Data.TableStatus) == "DELETING"
	if cancelled || (bootstrap.Copied && value(target.Data.TableStatus) == "ACTIVE") {
		db, err := s.engines.database(ctx, replicaSnapshotSpecification(&bootstrap))
		if err != nil {
			return false, err
		}
		removed, err := deleteNativeTable(ctx, db, bootstrap.SnapshotPhysicalName)
		if err != nil || !removed {
			return false, err
		}
		return true, s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.ReplicaBootstrap(bootstrap.Table)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if current.SnapshotPhysicalName != bootstrap.SnapshotPhysicalName {
				return nil
			}
			return tx.DeleteReplicaBootstrap(bootstrap.Table)
		})
	}
	if bootstrap.Ready {
		return true, nil
	}
	access, err := s.replicaAccess(ctx, bootstrap.Source, &target, "PutItem")
	if err != nil {
		return false, err
	}
	if err := s.prepareMutation(access, bootstrap.SourceDatabaseID); err != nil {
		return false, err
	}
	var source TableRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		source, err = r.Table(bootstrap.Source)
		return err
	}); err != nil {
		return false, err
	}
	if source.PhysicalName != bootstrap.SourcePhysicalName || source.DatabaseID != bootstrap.SourceDatabaseID || source.Replica.GroupID != target.Replica.GroupID || value(source.Data.TableStatus) == "DELETING" {
		return false, fmt.Errorf("replica snapshot source %s is no longer available", bootstrap.Source.ARN())
	}
	db, err := s.engines.database(access, replicaSnapshotSpecification(&bootstrap))
	if err != nil {
		return false, err
	}
	ready, err := resetReplicaSnapshot(access, db, &bootstrap)
	if err != nil || !ready {
		return false, err
	}
	if err := copyNativeTable(access, db, db, bootstrap.SourcePhysicalName, bootstrap.SnapshotPhysicalName); err != nil {
		return false, err
	}
	ready = false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.ReplicaBootstrap(bootstrap.Table)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.SnapshotPhysicalName != bootstrap.SnapshotPhysicalName {
			return nil
		}
		member, err := tx.Table(target.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if member.PhysicalName != target.PhysicalName || member.Replica.GroupID != source.Replica.GroupID || value(member.Data.TableStatus) == "DELETING" {
			return nil
		}
		currentSource, err := tx.Table(source.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if currentSource.PhysicalName != source.PhysicalName || currentSource.Replica.GroupID != source.Replica.GroupID || value(currentSource.Data.TableStatus) == "DELETING" {
			return nil
		}
		if err := tx.SnapshotReplicaVersions(current.Table, source.PhysicalName); err != nil {
			return err
		}
		current.Cursor = currentSource.Replica.Cursor
		current.Ready = true
		if err := tx.PutReplicaBootstrap(current); err != nil {
			return err
		}
		ready = true
		return nil
	})
	return ready, err
}

// Reset only the owned, unready private snapshot. Source writes may have resumed
// since an interrupted copy, so overwriting existing rows would retain deletes.
// Clearing rows rather than recreating the table also permits asynchronous native
// CreateTable to settle without restarting its lifecycle on every retry.
func resetReplicaSnapshot(ctx context.Context, db engine.Database, bootstrap *ReplicaBootstrap) (bool, error) {
	model, _ := awscatalog.LookupService("dynamodb")
	input := api.CreateTableInput{TableName: new(api.TableArn(bootstrap.SnapshotPhysicalName)), BillingMode: new(api.BillingModePAY_PER_REQUEST), KeySchema: bootstrap.KeySchema}
	input.AttributeDefinitions = selectedKeyDefinitions(bootstrap.AttributeDefinitions, &input)
	var created api.CreateTableOutput
	if err := nativeCall(ctx, db, model, "CreateTable", &input, &created, nil); err != nil && !engineCode(err, "ResourceInUseException") {
		return false, err
	}
	var observed api.DescribeTableOutput
	if err := nativeCall(ctx, db, model, "DescribeTable", &api.DescribeTableInput{TableName: input.TableName}, &observed, nil); err != nil {
		return false, err
	}
	if observed.Table == nil {
		return false, errors.New("native replica snapshot DescribeTable omitted table")
	}
	if value(observed.Table.TableStatus) != "ACTIVE" {
		return false, nil
	}
	scan := api.ScanInput{TableName: input.TableName, ConsistentRead: new(api.ConsistentRead(true))}
	for {
		var page api.ScanOutput
		if err := nativeCall(ctx, db, model, "Scan", &scan, &page, nil); err != nil {
			return false, err
		}
		for offset := 0; offset < len(page.Items); offset += 25 {
			items := page.Items[offset:min(offset+25, len(page.Items))]
			writes := make(api.WriteRequests, len(items))
			for i, item := range items {
				writes[i].DeleteRequest = &api.DeleteRequest{Key: capacityKey(bootstrap.KeySchema, api.AttributeMap(item))}
			}
			batch := api.BatchWriteItemInput{RequestItems: api.BatchWriteItemRequestMap{api.TableArn(bootstrap.SnapshotPhysicalName): writes}}
			var out api.BatchWriteItemOutput
			if err := nativeCall(ctx, db, model, "BatchWriteItem", &batch, &out, nil); err != nil {
				return false, err
			}
			for _, remaining := range out.UnprocessedItems {
				if len(remaining) != 0 {
					return false, errors.New("native replica snapshot reset left unprocessed items")
				}
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return true, nil
		}
		scan.ExclusiveStartKey = page.LastEvaluatedKey
	}
}
