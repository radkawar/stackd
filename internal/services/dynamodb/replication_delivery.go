package dynamodb

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/dynamodb"
)

const replicaDeliveryBatchSize = 100

// reconcileReplicaChanges consumes one bounded, ordered batch per current member.
// A blocked member never prevents another region from consuming its own batch.
func (s *Service) reconcileReplicaChanges(ctx context.Context) (bool, error) {
	var members []TableRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		members, err = r.ReplicaTables("")
		return err
	}); err != nil {
		return true, err
	}
	retry := false
	var failures error
	var groups []string
	seen := make(map[string]bool)
	for i := range members {
		member := &members[i]
		if !seen[member.Replica.GroupID] {
			seen[member.Replica.GroupID] = true
			groups = append(groups, member.Replica.GroupID)
		}
		var changes []ReplicaChange
		eligible := false
		err := s.repository.View(ctx, func(r Reader) error {
			var err error
			eligible, err = replicaCanConsume(r, member)
			if err != nil || !eligible {
				return err
			}
			changes, err = r.ReplicaChanges(member.Replica.GroupID, member.Replica.Cursor, replicaDeliveryBatchSize)
			return err
		})
		if err != nil {
			failures = errors.Join(failures, err)
			retry = true
			continue
		}
		if !eligible {
			retry = true
			continue
		}
		// Conflict winners can make a denied row obsolete. Recovery still has
		// to clear that member's interval even when there is nothing to apply.
		if member.Replica.UnauthorizedAt != nil {
			retry = true
			_, err := s.replicaAccess(ctx, member.Key, member, "PutItem")
			if !replicaAuthorizationDenied(err) && !errors.Is(err, errReplicaChanged) {
				failures = errors.Join(failures, err)
			}
		}
		for j := range changes {
			acknowledged, err := s.deliverReplicaChange(ctx, member, &changes[j])
			if err != nil || !acknowledged {
				retry = true
				if !replicaAuthorizationDenied(err) && !capacityThrottled(err) && !errors.Is(err, errReplicaChanged) {
					failures = errors.Join(failures, err)
				}
				break
			}
		}
		if len(changes) == replicaDeliveryBatchSize {
			retry = true
		}
	}
	if err := s.trimReplicaGroups(ctx, groups); err != nil {
		retry = true
		failures = errors.Join(failures, err)
	}
	return retry, failures
}

func replicaCanConsume(r Reader, table *TableRecord) (bool, error) {
	switch value(table.Data.TableStatus) {
	case "ACTIVE", "UPDATING":
		return true, nil
	case "CREATING":
		bootstrap, err := r.ReplicaBootstrap(table.Key)
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return bootstrap.Copied, err
	default:
		return false, nil
	}
}

func (s *Service) deliverReplicaChange(ctx context.Context, table *TableRecord, change *ReplicaChange) (bool, error) {
	expected := *table
	acknowledged := false
	// withMutation is the only data gate here. In particular, reading an
	// immutable retained row never acquires the origin database's gate.
	err := s.withMutation(ctx, table, func() error {
		eligible := false
		var installed int64
		err := s.repository.View(ctx, func(r Reader) error {
			current, err := r.Table(expected.Key)
			if errors.Is(err, ErrNotFound) {
				return errReplicaChanged
			}
			if err != nil {
				return err
			}
			if !sameReplicaIncarnation(&current, &expected) || change.GroupID != current.Replica.GroupID {
				return errReplicaChanged
			}
			*table = current
			if current.Replica.Cursor >= change.Sequence {
				acknowledged = true
				return nil
			}
			eligible, err = replicaCanConsume(r, table)
			if err != nil || !eligible {
				return err
			}
			installed, err = r.ReplicaVersion(table.PhysicalName, replicaKeyID(table.Data.KeySchema, change.Key))
			return err
		})
		if err != nil || acknowledged || !eligible {
			return err
		}
		own := change.Origin == table.Key && change.OriginPhysicalName == table.PhysicalName
		if !own && installed < change.Version {
			action := "PutItem"
			if change.Item == nil {
				action = "DeleteItem"
			}
			roleCtx, err := s.replicaAccessIncarnation(ctx, change.Origin, change.OriginPhysicalName, table, action)
			if err != nil {
				return err
			}
			if err := s.applyReplicaChange(roleCtx, table, change); err != nil {
				return err
			}
		}
		// Publication installs the original conflict version only after observing
		// the actual native postimage. A lost response is therefore safe to retry.
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Table(expected.Key)
			if errors.Is(err, ErrNotFound) {
				return errReplicaChanged
			}
			if err != nil {
				return err
			}
			if !sameReplicaIncarnation(&current, &expected) {
				return errReplicaChanged
			}
			if current.Replica.Cursor >= change.Sequence {
				acknowledged = true
				return nil
			}
			if !own {
				installed, err := tx.ReplicaVersion(current.PhysicalName, replicaKeyID(current.Data.KeySchema, change.Key))
				if err != nil || installed < change.Version {
					return err
				}
			}
			current.Replica.Cursor = change.Sequence
			if err := tx.PutTable(current); err != nil {
				return err
			}
			*table = current
			acknowledged = true
			return nil
		})
	})
	return acknowledged, err
}

// applyReplicaChange runs inside the destination mutation interval. It supplies
// absolute images, not a customer's old expression or conditions, to native I/O.
func (s *Service) applyReplicaChange(ctx context.Context, table *TableRecord, change *ReplicaChange) error {
	ctx = s.withDataMetrics(ctx)
	var plan dataPlan
	if err := plan.add(&table, table.Key.Name); err != nil {
		return err
	}
	if err := s.admit(ctx, table, "", true); err != nil {
		return errors.Join(err, s.persistReplicaMetrics(ctx))
	}
	writes := []capacityWrite{{table: table, key: change.Key, after: change.Item, readBefore: true, readAfter: true, replica: change}}
	if err := s.collectCapacityImages(ctx, &plan, writes, false); err != nil {
		return err
	}
	pending, err := s.beginMutationWrite(ctx, writes, nil)
	if err != nil {
		return err
	}
	if change.Item == nil {
		var out api.DeleteItemOutput
		err = s.callEngine(ctx, table, "DeleteItem", &api.DeleteItemInput{TableName: dataPhysical(table), Key: change.Key}, &out)
	} else {
		var out api.PutItemOutput
		err = s.callEngine(ctx, table, "PutItem", &api.PutItemInput{TableName: dataPhysical(table), Item: api.PutItemInputAttributeMap(change.Item)}, &out)
	}
	if err != nil {
		return err
	}
	if err := s.collectCapacityImages(ctx, &plan, writes, true); err != nil {
		return err
	}
	var charge writeCharge
	charge.add(&writes[0], false)
	capacity := new(charge.capacity(table.PhysicalName, false))
	s.admission.charge(table, capacity, true)
	if err := s.completeCapacity(ctx, table, &capacity, nil, true); err != nil {
		return err
	}
	if err := s.persistReplicaMetrics(ctx); err != nil {
		return err
	}
	return s.finishMutationWrite(ctx, pending, writes, nil)
}

// Internal writes publish real capacity observations without inventing a second
// customer API call (completeExternal also emits audit, so it is not used here).
func (s *Service) persistReplicaMetrics(ctx context.Context) error {
	observed, _ := ctx.Value(dataMetricsKey{}).(*dataMetrics)
	if observed == nil || len(observed.samples) == 0 {
		return nil
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		for key, samples := range observed.samples {
			if err := tx.AddMetricSamples(key, samples); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}

func (s *Service) trimReplicaGroups(ctx context.Context, groups []string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		bootstraps, err := tx.ReplicaBootstraps("")
		if err != nil {
			return err
		}
		for _, group := range groups {
			members, err := tx.ReplicaTables(group)
			if err != nil {
				return err
			}
			if len(members) == 0 {
				continue
			}
			through := members[0].Replica.Cursor
			copying := false
			for _, member := range members {
				through = min(through, member.Replica.Cursor)
				for _, bootstrap := range bootstraps {
					if bootstrap.Table == member.Key {
						copying = copying || !bootstrap.Copied
						through = min(through, bootstrap.Cursor)
					}
				}
			}
			// Until snapshot versions are installed, preserve the source version
			// cut as well as log rows. Copied snapshots still pin their cursor.
			if !copying {
				if err := tx.TrimReplicaChanges(group, through); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
