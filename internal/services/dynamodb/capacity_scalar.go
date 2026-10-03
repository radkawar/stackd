package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodb"
)

func (s *Service) needsCapacity(requested *api.ReturnConsumedCapacity, write bool, table *TableRecord, additional ...*TableRecord) bool {
	if s.metrics != nil || value(requested) == "TOTAL" || value(requested) == "INDEXES" || capacityLimited(table, write) || write && (table.RecoveryID != "" || table.Replica.GroupID != "" || len(table.KinesisConsumers) != 0) {
		return true
	}
	for _, table := range additional {
		if capacityLimited(table, write) || write && (table.RecoveryID != "" || table.Replica.GroupID != "" || len(table.KinesisConsumers) != 0) {
			return true
		}
	}
	return false
}

func (s *Service) writeItemMutation(ctx context.Context, write *capacityWrite, capacity **api.ConsumedCapacity, requested *api.ReturnConsumedCapacity, apply func() error) error {
	return s.withMutation(ctx, write.table, func() error {
		if err := s.admit(ctx, write.table, "", true); err != nil {
			return err
		}
		if !s.needsCapacity(requested, true, write.table) {
			return apply()
		}
		var plan dataPlan
		if err := plan.add(&write.table, write.table.Key.Name); err != nil {
			return err
		}
		if write.readBefore || write.table.Replica.GroupID != "" || len(write.table.KinesisConsumers) != 0 {
			images := []capacityWrite{*write}
			if err := s.collectCapacityImages(ctx, &plan, images, false); err != nil {
				return err
			}
			write.before = images[0].before
			write.beforeObserved = true
		}
		pending, err := s.beginMutationWrite(ctx, []capacityWrite{*write}, nil)
		if err != nil {
			return err
		}
		if err := apply(); err != nil {
			return err
		}
		if write.readAfter {
			images := []capacityWrite{*write}
			if err := s.collectCapacityImages(ctx, &plan, images, true); err != nil {
				return err
			}
			write.after = images[0].after
			write.afterObserved = true
		}
		if err := s.finishMutationWrite(ctx, pending, []capacityWrite{*write}, nil); err != nil {
			return err
		}
		var charge writeCharge
		charge.add(write, false)
		*capacity = new(charge.capacity(write.table.PhysicalName, false))
		s.admission.charge(write.table, *capacity, true)
		return s.completeCapacity(ctx, write.table, capacity, requested, true)
	})
}
