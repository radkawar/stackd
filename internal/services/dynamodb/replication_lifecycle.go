package dynamodb

import (
	"context"
	"errors"
	"time"
)

func (s *Service) replicaDependenciesReady(ctx context.Context, table *TableRecord) (bool, error) {
	pending := table.PendingUpdate
	if table.Replica.GroupID == "" || table.Replica.SettingsPending || pending == nil || len(pending.ReplicaUpdates) == 0 && !hasGlobalTableSettings(pending) {
		return true, nil
	}
	ready := true
	err := s.repository.View(ctx, func(r Reader) error {
		members, err := r.ReplicaTables(table.Replica.GroupID)
		if err != nil {
			return err
		}
		for _, member := range members {
			if len(pending.ReplicaUpdates) != 0 {
				requested := false
				for _, update := range pending.ReplicaUpdates {
					requested = requested || update.Create != nil && value(update.Create.RegionName) == member.Key.Region ||
						update.Update != nil && value(update.Update.RegionName) == member.Key.Region ||
						update.Delete != nil && value(update.Delete.RegionName) == member.Key.Region
				}
				if !requested {
					continue
				}
			}
			if member.Key != table.Key && (value(member.Data.TableStatus) != "ACTIVE" || member.PendingUpdate != nil || member.Replica.SettingsPending) {
				ready = false
			}
		}
		return nil
	})
	return ready, err
}

// Do not discard an accepted source write when removing the penultimate member.
// Its native table may be gone, but the final survivor still owns delivery from
// the retained log. Authorization and capacity remain enforced while draining.
func replicaRemovalReady(r Reader, table *TableRecord, planned []TableRecord) (bool, error) {
	if table.Replica.GroupID == "" || len(planned) != 2 {
		return true, nil
	}
	for _, candidate := range planned {
		if candidate.Key == table.Key {
			continue
		}
		survivor, err := r.Table(candidate.Key)
		if err != nil {
			return false, err
		}
		if value(survivor.Data.TableStatus) == "DELETING" {
			return true, nil
		}
		tail, err := r.ReplicaSequence(table.Replica.GroupID)
		return survivor.Replica.Cursor >= tail, err
	}
	return true, nil
}

// removeReplicaMember runs with every member database quiesced and outstanding
// captures resolved. The last regional table keeps its data and enabled stream;
// it no longer needs the replication role or the source-region deletion delay.
func removeReplicaMember(tx Transaction, table *TableRecord) error {
	group := table.Replica.GroupID
	if group == "" {
		return nil
	}
	if err := tx.DeleteReplicaVersions(table.PhysicalName); err != nil {
		return err
	}
	table.Replica = ReplicaState{}
	if err := tx.PutTable(*table); err != nil {
		return err
	}
	remaining, err := tx.ReplicaTables(group)
	if err != nil {
		return err
	}
	if len(remaining) > 1 {
		return nil
	}
	if len(remaining) == 1 {
		last := &remaining[0]
		last.Replica = ReplicaState{}
		if err := tx.DeleteReplicaVersions(last.PhysicalName); err != nil {
			return err
		}
		if err := tx.PutTable(*last); err != nil {
			return err
		}
	}
	tail, err := tx.ReplicaSequence(group)
	if err != nil {
		return err
	}
	return tx.TrimReplicaChanges(group, tail)
}

func (s *Service) reconcileReplicas(ctx context.Context) (time.Time, bool, error) {
	bootstrapRetry, bootstrapErr := s.maintainReplicaBootstraps(ctx)
	deliveryRetry, deliveryErr := s.reconcileReplicaChanges(ctx)
	deadline, expiryRetry, expiryErr := s.expireReplicaAuthorization(ctx)
	return deadline, bootstrapRetry || deliveryRetry || expiryRetry, errors.Join(bootstrapErr, deliveryErr, expiryErr)
}

func (s *Service) expireReplicaAuthorization(ctx context.Context) (time.Time, bool, error) {
	var members []TableRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		members, err = r.ReplicaTables("")
		return err
	}); err != nil {
		return time.Time{}, true, err
	}
	var deadline time.Time
	retry := false
	for _, member := range members {
		if member.Replica.UnauthorizedAt == nil {
			continue
		}
		at := member.Replica.UnauthorizedAt.Add(20 * time.Hour)
		if s.clock.Now().Before(at) {
			if deadline.IsZero() || at.Before(deadline) {
				deadline = at
			}
			continue
		}
		if value(member.Data.TableStatus) != "ACTIVE" || member.PendingCreate != nil || member.PendingUpdate != nil {
			// TODO: Comeback capture authorization-expiry behavior during initial
			// replica creation and partially applied schema/settings transitions.
			// Do not publish incomplete baseline data as an ACTIVE standalone table.
			retry = true
			continue
		}
		if err := s.detachUnauthorizedReplica(ctx, &member); err != nil {
			return deadline, true, err
		}
	}
	return deadline, retry, nil
}

func (s *Service) detachUnauthorizedReplica(ctx context.Context, expected *TableRecord) error {
	planned, err := s.planTableGroup(ctx, expected.Key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	release, err := s.engines.lockTableDatabases(ctx, planned)
	if err != nil {
		return err
	}
	defer release()
	for _, member := range planned {
		if err := s.resolveMutationCapture(ctx, member.DatabaseID); err != nil {
			return err
		}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Table(expected.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !sameReplicaIncarnation(&current, expected) || current.Replica.UnauthorizedAt == nil || s.clock.Now().Before(current.Replica.UnauthorizedAt.Add(20*time.Hour)) || value(current.Data.TableStatus) != "ACTIVE" {
			return nil
		}
		if _, err := validateTableGroup(tx, &current, planned); err != nil {
			return err
		}
		return removeReplicaMember(tx, &current)
	})
}
