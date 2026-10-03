package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

func engineCode(err error, code string) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && wire.Code == code
}

func (s *Service) reconcileTable(ctx context.Context, record *TableRecord) (bool, error) {
	physical := new(api.TableArn(record.PhysicalName))
	var observed api.DescribeTableOutput
	switch value(record.Data.TableStatus) {
	case "CREATING":
		if record.PendingCreate == nil {
			return false, fmt.Errorf("creating table %s has no admitted input", record.Key.ARN())
		}
		in := *record.PendingCreate
		in.TableName = physical
		in.Tags = nil
		in.ResourcePolicy = nil
		in.TableClass = nil
		in.DeletionProtectionEnabled = nil
		in.OnDemandThroughput = nil
		if slices.ContainsFunc(in.GlobalSecondaryIndexes, func(index api.GlobalSecondaryIndex) bool { return index.OnDemandThroughput != nil }) {
			in.GlobalSecondaryIndexes = slices.Clone(in.GlobalSecondaryIndexes)
			for i := range in.GlobalSecondaryIndexes {
				in.GlobalSecondaryIndexes[i].OnDemandThroughput = nil
			}
		}
		var out api.CreateTableOutput
		if err := s.mutateEngine(ctx, record, "CreateTable", &in, &out); err != nil && !engineCode(err, "ResourceInUseException") {
			return false, err
		}
	case "UPDATING":
		if record.PendingUpdate == nil {
			return false, fmt.Errorf("updating table %s has no admitted input", record.Key.ARN())
		}
		if record.Replica.SettingsPending {
			if err := s.replicaSettingsAccess(ctx, record); err != nil {
				if replicaAuthorizationDenied(err) {
					return true, nil
				}
				return true, err
			}
		}
		if err := s.callEngine(ctx, record, "DescribeTable", &api.DescribeTableInput{TableName: physical}, &observed); err != nil {
			return false, err
		}
		if observed.Table == nil {
			return false, fmt.Errorf("engine DescribeTable omitted table %s", record.Key.ARN())
		}
		if value(observed.Table.TableStatus) != "ACTIVE" {
			return true, nil
		}
		in := engineUpdateInput(record.PendingUpdate, observed.Table)
		in.TableName = physical
		if !engineUpdateApplied(observed.Table, &in) {
			var out api.UpdateTableOutput
			if err := s.mutateEngine(ctx, record, "UpdateTable", &in, &out); err != nil {
				return false, err
			}
			observed.Table = nil
		}
	case "DELETING":
		if err := s.deleteTableData(ctx, record); err != nil && !engineCode(err, "ResourceNotFoundException") {
			return false, err
		}
	default:
		return false, nil
	}
	var err error
	if observed.Table == nil {
		err = s.callEngine(ctx, record, "DescribeTable", &api.DescribeTableInput{TableName: physical}, &observed)
	}
	if value(record.Data.TableStatus) == "DELETING" && engineCode(err, "ResourceNotFoundException") {
		return s.finishTableDeletion(ctx, record)
	}
	if err != nil {
		return false, err
	}
	if observed.Table == nil {
		return false, fmt.Errorf("engine DescribeTable omitted table %s", record.Key.ARN())
	}
	if value(observed.Table.TableStatus) != "ACTIVE" {
		return true, nil
	}
	if record.Data.RestoreSummary != nil {
		if err := s.restoreTableData(ctx, record); err != nil {
			return false, err
		}
	}
	if value(record.Data.TableStatus) == "CREATING" && record.Replica.GroupID != "" {
		ready, err := s.prepareReplicaTable(ctx, record)
		if err != nil || !ready {
			return true, err
		}
	}
	ready, err := s.replicaDependenciesReady(ctx, record)
	if err != nil || !ready {
		return true, err
	}
	var updated *TableRecord
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Table(record.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.PhysicalName != record.PhysicalName || value(current.Data.TableStatus) != value(record.Data.TableStatus) {
			return nil
		}
		wasProvisioned := provisionedTable(&current)
		s.observeEngineTable(&current, observed.Table)
		if current.Data.RestoreSummary != nil {
			finishRestoreHistory(&current.Data, s.clock.Now())
			current.RestoreRecoveryID = ""
			current.RestoreRecoverySequence = 0
		}
		if (current.PendingCreate != nil || wasProvisioned) && !provisionedTable(&current) {
			if err := recordOnDemandSwitch(tx, current.Key, *current.Data.BillingModeSummary.LastUpdateToPayPerRequestDateTime); err != nil {
				return err
			}
		}
		if err := s.observeStream(tx, &current, observed.Table); err != nil {
			return err
		}
		current.PendingCreate = nil
		current.PendingUpdate = nil
		current.UpdateAcceptedAt = time.Time{}
		current.Replica.SettingsPending = false
		if err := tx.PutTable(current); err != nil {
			return err
		}
		if current.Replica.GroupID != "" && !wasProvisioned && provisionedTable(&current) {
			if err := s.configureReplicaScaling(tx.Context(), &current); err != nil {
				return err
			}
		}
		updated = &current
		if s.capacityState != nil {
			return s.capacityState.ObserveTableCapacity(tx.Context(), current.Key, &current.Data)
		}
		return nil
	})
	if err == nil {
		if updated != nil {
			s.admission.observe(updated)
		}
		s.jobs.Wake()
	}
	return false, err
}

func (s *Service) finishTableDeletion(ctx context.Context, record *TableRecord) (bool, error) {
	planned, err := s.planTableGroup(ctx, record.Key)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	release, err := s.engines.lockTableDatabases(ctx, planned)
	if err != nil {
		return true, err
	}
	defer release()
	for _, member := range planned {
		if err := s.resolveMutationCapture(ctx, member.DatabaseID); err != nil {
			return true, err
		}
	}
	waiting := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Table(record.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.PhysicalName != record.PhysicalName || value(current.Data.TableStatus) != "DELETING" {
			return nil
		}
		members, err := validateTableGroup(tx, &current, planned)
		if err != nil {
			return err
		}
		ready, err := replicaRemovalReady(tx, &current, members)
		if err != nil {
			return err
		}
		if !ready {
			waiting = true
			return nil
		}
		if err := removeReplicaMember(tx, &current); err != nil {
			return err
		}
		generations, err := tx.Streams()
		if err != nil {
			return err
		}
		for _, g := range generations {
			if g.DatabaseID == current.DatabaseID && g.PhysicalName == current.PhysicalName && g.ClosedAt.IsZero() {
				g.ClosedAt = s.clock.Now()
				if err := tx.PutStream(g); err != nil {
					return err
				}
			}
		}
		destinations, err := tx.KinesisDestinations()
		if err != nil {
			return err
		}
		for _, destination := range destinations {
			if destination.PhysicalName != current.PhysicalName {
				continue
			}
			destination.Status = "DISABLED"
			destination.Due, destination.CaptureUntil = time.Time{}, time.Time{}
			if err := tx.PutKinesisDestination(destination); err != nil {
				return err
			}
		}
		if err := tx.DeleteTable(current.Key); err != nil {
			return err
		}
		return tx.DeletePolicy(PolicyKey{Scope: current.Key.Scope, ResourceARN: current.Key.ARN()})
	})
	if err == nil && !waiting {
		s.admission.forgetTable(record.Key)
		s.engines.wake()
	}
	return waiting, err
}

// observeEngineTable translates engine metadata while retaining Go-owned
// creation identity, billing history, table class and on-demand maximums.
func (s *Service) observeEngineTable(record *TableRecord, observed *api.TableDescription) {
	previous := record.Data
	next := api.CloneTableDescription(*observed)
	next.TableName = new(api.TableName(record.Key.Name))
	next.TableArn = new(api.String(record.Key.ARN()))
	next.TableId = previous.TableId
	next.CreationDateTime = previous.CreationDateTime
	next.TableClassSummary = previous.TableClassSummary
	next.DeletionProtectionEnabled = previous.DeletionProtectionEnabled
	next.BillingModeSummary = previous.BillingModeSummary
	next.RestoreSummary = previous.RestoreSummary
	if record.PendingCreate != nil && next.BillingModeSummary != nil {
		next.BillingModeSummary = new(api.CloneBillingModeSummary(*next.BillingModeSummary))
		next.BillingModeSummary.LastUpdateToPayPerRequestDateTime = previous.CreationDateTime
	}
	if update := record.PendingUpdate; update != nil {
		if update.DeletionProtectionEnabled != nil {
			next.DeletionProtectionEnabled = update.DeletionProtectionEnabled
		}
		if update.TableClass != nil {
			now := s.clock.Now()
			next.TableClassSummary = &api.TableClassSummary{TableClass: update.TableClass, LastUpdateDateTime: &now}
		}
		if update.BillingMode != nil {
			next.BillingModeSummary = &api.BillingModeSummary{BillingMode: update.BillingMode}
			if previous.BillingModeSummary != nil {
				next.BillingModeSummary.LastUpdateToPayPerRequestDateTime = previous.BillingModeSummary.LastUpdateToPayPerRequestDateTime
			}
			if *update.BillingMode == api.BillingModePAY_PER_REQUEST && provisionedTable(record) {
				now := s.clock.Now()
				next.BillingModeSummary.LastUpdateToPayPerRequestDateTime = &now
			}
		}
	}
	provisioned := next.BillingModeSummary == nil || value(next.BillingModeSummary.BillingMode) != "PAY_PER_REQUEST"
	next.OnDemandThroughput = nil
	if !provisioned {
		next.OnDemandThroughput = previous.OnDemandThroughput
	}
	if next.StreamSpecification != nil && (next.StreamSpecification.StreamEnabled == nil || !*next.StreamSpecification.StreamEnabled) {
		next.StreamSpecification = nil
	}
	next.LatestStreamArn = previous.LatestStreamArn
	next.LatestStreamLabel = previous.LatestStreamLabel
	read, write := warmCapacity(next.ProvisionedThroughput, next.BillingModeSummary, nil, nil)
	if previous.WarmThroughput != nil {
		read, write = warmCapacity(next.ProvisionedThroughput, next.BillingModeSummary, previous.WarmThroughput.ReadUnitsPerSecond, previous.WarmThroughput.WriteUnitsPerSecond)
	}
	next.WarmThroughput = &api.TableWarmThroughputDescription{ReadUnitsPerSecond: &read, WriteUnitsPerSecond: &write, Status: new(api.TableStatusACTIVE)}
	for i := range next.GlobalSecondaryIndexes {
		index := &next.GlobalSecondaryIndexes[i]
		index.IndexArn = new(api.String(record.Key.ARN() + "/index/" + value(index.IndexName)))
		index.Backfilling = nil
		var old *api.GlobalSecondaryIndexDescription
		index.OnDemandThroughput = nil
		for j := range previous.GlobalSecondaryIndexes {
			if value(previous.GlobalSecondaryIndexes[j].IndexName) == value(index.IndexName) {
				old = &previous.GlobalSecondaryIndexes[j]
				break
			}
		}
		read, write := warmCapacity(index.ProvisionedThroughput, next.BillingModeSummary, nil, nil)
		var oldCapacity *api.ProvisionedThroughputDescription
		if old != nil {
			if !provisioned {
				index.OnDemandThroughput = old.OnDemandThroughput
			}
			if old.WarmThroughput != nil {
				read, write = warmCapacity(index.ProvisionedThroughput, next.BillingModeSummary, old.WarmThroughput.ReadUnitsPerSecond, old.WarmThroughput.WriteUnitsPerSecond)
			}
			oldCapacity = old.ProvisionedThroughput
		}
		index.ProvisionedThroughput = observeThroughput(index.ProvisionedThroughput, oldCapacity, s.clock.Now(), provisioned, true)
		index.WarmThroughput = &api.GlobalSecondaryIndexWarmThroughputDescription{ReadUnitsPerSecond: &read, WriteUnitsPerSecond: &write, Status: new(api.IndexStatusACTIVE)}
	}
	for i := range next.LocalSecondaryIndexes {
		index := &next.LocalSecondaryIndexes[i]
		index.IndexArn = new(api.String(record.Key.ARN() + "/index/" + value(index.IndexName)))
	}
	next.ProvisionedThroughput = observeThroughput(next.ProvisionedThroughput, previous.ProvisionedThroughput, s.clock.Now(), provisioned, provisioned == provisionedTable(record))
	if !provisioned && record.PendingUpdate != nil {
		updateOnDemand(&next, record.PendingUpdate)
	}
	record.Data = next
}
