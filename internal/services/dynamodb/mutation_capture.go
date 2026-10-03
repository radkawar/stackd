package dynamodb

import (
	"context"
	"errors"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

// beginMutationWrite runs under the database gate, after admission and before
// the external effect. The retained sources outlive control-plane membership.
func (s *Service) beginMutationWrite(ctx context.Context, writes []capacityWrite, at *time.Time, transactional ...bool) (*MutationCapture, error) {
	var pending MutationCapture
	pending.ParentEventID = apievents.EventID(ctx)
	pending.Transactional = len(transactional) != 0 && transactional[0]
	pending.TTL = at != nil
	var plan dataPlan
	var missing []capacityWrite
	seen := make(map[capacityItemID]bool)
	for _, write := range writes {
		if write.conditionOnly {
			continue
		}
		if write.table.RecoveryID == "" && write.table.Replica.GroupID == "" && len(write.table.KinesisConsumers) == 0 {
			continue
		}
		if err := plan.add(&write.table, write.table.Key.Name); err != nil {
			return nil, err
		}
		if (write.table.Replica.GroupID != "" || len(write.table.KinesisConsumers) != 0) && !write.beforeObserved && !seen[write.id()] {
			missing = append(missing, write)
			seen[write.id()] = true
		}
	}
	if plan.table == nil {
		return nil, nil
	}
	if _, err := s.observeMutationImages(ctx, &plan, missing, false); err != nil {
		return nil, err
	}
	before := make(map[capacityItemID]api.AttributeMap, len(missing))
	for _, write := range missing {
		before[write.id()] = write.before
	}
	clear(seen)
	sources := make(map[string]int)
	for _, write := range writes {
		if write.conditionOnly {
			continue
		}
		if write.table.RecoveryID == "" && write.table.Replica.GroupID == "" && len(write.table.KinesisConsumers) == 0 || seen[write.id()] {
			continue
		}
		seen[write.id()] = true
		position, found := sources[write.table.PhysicalName]
		if !found {
			position = len(pending.Sources)
			sources[write.table.PhysicalName] = position
			pending.Sources = append(pending.Sources, MutationSource{
				Table: write.table.Key, PhysicalName: write.table.PhysicalName, KeySchema: write.table.Data.KeySchema,
				WriteConsumers: WriteConsumers{RecoveryID: write.table.RecoveryID, ReplicationGroupID: write.table.Replica.GroupID, Kinesis: write.table.KinesisConsumers},
			})
		}
		item := MutationItem{Key: write.key}
		if write.table.Replica.GroupID != "" || len(write.table.KinesisConsumers) != 0 {
			item.Before = write.before
			if !write.beforeObserved {
				item.Before = before[write.id()]
			}
		}
		if write.replica != nil {
			item.ReplicaSequence = write.replica.Sequence
		}
		pending.Sources[position].Items = append(pending.Sources[position].Items, item)
	}
	pending.DatabaseID = plan.table.DatabaseID
	if at == nil {
		pending.At = s.clock.Now()
	} else {
		pending.At = *at
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		pending.Version, err = tx.CreateMutationCapture(pending)
		return err
	})
	return &pending, err
}

// finishMutationWrite coalesces accepted keys to their final actual image. Native
// unprocessed entries and failed statements are not published. Capacity keeps its
// own request images; postimage collection here only affects retained consumers.
func (s *Service) finishMutationWrite(ctx context.Context, pending *MutationCapture, writes []capacityWrite, excluded map[capacityItemID]bool) error {
	if pending == nil {
		return nil
	}
	accepted := make(map[capacityItemID]capacityWrite, len(writes))
	repeated := make(map[capacityItemID]bool)
	for _, write := range writes {
		id := write.id()
		if excluded[id] {
			continue
		}
		if _, found := accepted[id]; found {
			repeated[id] = true
		}
		accepted[id] = write
	}
	var plan dataPlan
	var observed []capacityWrite
	for _, source := range pending.Sources {
		table := mutationSourceTable(pending.DatabaseID, source)
		if err := plan.add(&table, table.Key.Name); err != nil {
			return err
		}
		for _, item := range source.Items {
			id := capacityKeyID(source.PhysicalName, source.KeySchema, item.Key)
			write, found := accepted[id]
			if !found {
				continue
			}
			write.table = table
			write.readAfter = repeated[id] || len(source.Kinesis) != 0 || source.ReplicationGroupID != "" && !write.afterObserved
			observed = append(observed, write)
		}
	}
	missing, err := s.observeMutationImages(ctx, &plan, observed, true)
	if err != nil {
		return err
	}
	images := make(map[capacityItemID]api.AttributeMap, len(observed))
	for _, write := range observed {
		if !missing[write.id()] {
			images[write.id()] = write.after
		}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		var changes []RecoveryChange
		for _, source := range pending.Sources {
			for _, item := range source.Items {
				image, found := images[capacityKeyID(source.PhysicalName, source.KeySchema, item.Key)]
				if !found {
					continue
				}
				if source.RecoveryID != "" {
					changes = append(changes, RecoveryChange{RecoveryID: source.RecoveryID, At: pending.At, Key: item.Key, Item: image})
				}
				if err := publishReplicaMutation(tx, pending, source, item, image); err != nil {
					return err
				}
				if err := publishKinesisMutation(tx, pending, source, item, image); err != nil {
					return err
				}
			}
		}
		if err := tx.AppendRecoveryChanges(changes); err != nil {
			return err
		}
		return tx.DeleteMutationCapture(pending.DatabaseID)
	})
}

// Whole-request native client errors are nonmutating. Ambiguous transport or
// process errors retain the keys until actual native reads settle publication.
func (s *Service) failMutationWrite(ctx context.Context, databaseID string, rejected error) error {
	err := s.repository.View(ctx, func(r Reader) error {
		_, err := r.MutationCapture(databaseID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var wire *awswire.Error
	if errors.As(rejected, &wire) && wire.StatusCode >= 400 && wire.StatusCode < 500 {
		return s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteMutationCapture(databaseID) })
	}
	return s.resolveMutationCapture(ctx, databaseID)
}

// resolveMutationCapture never replays customer expressions. A retained incoming
// sequence is looked up during publication; a pre-effect failure cannot install
// its conflict version, so the receiver leaves the log row unacknowledged.
func (s *Service) resolveMutationCapture(ctx context.Context, databaseID string) error {
	var pending MutationCapture
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		pending, err = r.MutationCapture(databaseID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var plan dataPlan
	var writes []capacityWrite
	for _, source := range pending.Sources {
		table := mutationSourceTable(databaseID, source)
		if err := plan.add(&table, table.Key.Name); err != nil {
			return err
		}
		for _, item := range source.Items {
			writes = append(writes, capacityWrite{table: table, key: item.Key, readAfter: true})
		}
	}
	excluded, err := s.observeMutationImages(ctx, &plan, writes, true)
	if err != nil {
		return err
	}
	return s.finishMutationWrite(ctx, &pending, writes, excluded)
}

func mutationSourceTable(databaseID string, source MutationSource) *TableRecord {
	return &TableRecord{Key: source.Table, DatabaseID: databaseID, PhysicalName: source.PhysicalName,
		RecoveryID: source.RecoveryID, Replica: ReplicaState{GroupID: source.ReplicationGroupID}, KinesisConsumers: source.Kinesis,
		Data: api.TableDescription{KeySchema: source.KeySchema}}
}

// Invalid keys and removed native incarnations must not block unrelated tables.
// All other read failures keep the capture unresolved rather than guessing images.
func (s *Service) observeMutationImages(ctx context.Context, plan *dataPlan, writes []capacityWrite, after bool) (map[capacityItemID]bool, error) {
	if err := s.collectCapacityImages(ctx, plan, writes, after); err != nil {
		if !engineCode(err, "ValidationException") && !engineCode(err, "ResourceNotFoundException") {
			return nil, err
		}
		excluded := make(map[capacityItemID]bool)
		for i := range writes {
			write := &writes[i]
			if after && !write.readAfter {
				continue
			}
			var out api.GetItemOutput
			input := &api.GetItemInput{TableName: dataPhysical(write.table), Key: write.key, ConsistentRead: new(api.ConsistentRead(true))}
			if err := s.callEngine(ctx, write.table, "GetItem", input, &out); err != nil {
				if !engineCode(err, "ValidationException") && !engineCode(err, "ResourceNotFoundException") {
					return nil, err
				}
				excluded[write.id()] = true
				continue
			}
			if after {
				write.after, write.afterObserved = out.Item, true
			} else {
				write.before, write.beforeObserved = out.Item, true
			}
		}
		return excluded, nil
	}
	return nil, nil
}
