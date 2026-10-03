package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodb"
)

func (s *Service) writeBatch(ctx context.Context, group *dataWriteBatch, out *api.BatchWriteItemOutput) error {
	requested := group.input.ReturnConsumedCapacity
	return s.withMutation(ctx, group.plan.table, func() error {
		if !s.needsCapacity(requested, true, group.plan.table, group.plan.additional...) {
			return s.callEngine(ctx, group.plan.table, "BatchWriteItem", &group.input, out)
		}
		var writes []capacityWrite
		names := dataSortedTables(group.input.RequestItems)
		for _, name := range names {
			table := group.plan.tables[name]
			for _, request := range group.input.RequestItems[api.TableArn(name)] {
				write := capacityWrite{table: table}
				if request.PutRequest != nil {
					write.after = api.AttributeMap(request.PutRequest.Item)
					write.key = capacityKey(table.Data.KeySchema, write.after)
				} else if request.DeleteRequest != nil {
					write.key = request.DeleteRequest.Key
				}
				writes = append(writes, write)
			}
		}
		if err := s.collectCapacityImages(ctx, &group.plan, writes, false); err != nil {
			return err
		}
		var preview *capacityAdmission
		if group.plan.limited(true) {
			preview = s.admission.preview(&group.plan)
		}
		charges := make([]api.ConsumedCapacity, len(writes))
		blocked := make(map[capacityItemID][]api.IndexName)
		for i := range writes {
			write := &writes[i]
			if preview != nil {
				if indexes := preview.check(write.table, "", true); len(indexes) != 0 {
					blocked[capacityKeyID(write.table.PhysicalName, write.table.Data.KeySchema, write.key)] = indexes
					continue
				}
			}
			var charge writeCharge
			charge.add(write, false)
			charges[i] = charge.capacity(write.table.PhysicalName, false)
			if preview != nil {
				preview.charge(write.table, &charges[i], true)
			}
		}
		input := group.input
		input.ReturnConsumedCapacity = nil
		var rejected error
		if len(blocked) != 0 {
			if err := s.validateWriteBatch(ctx, group); err != nil {
				return err
			}
			input.RequestItems = make(api.BatchWriteItemRequestMap)
			out.UnprocessedItems = make(api.BatchWriteItemRequestMap)
			position := 0
			for _, name := range names {
				selector := api.TableArn(name)
				for _, request := range group.input.RequestItems[selector] {
					write := &writes[position]
					position++
					id := capacityKeyID(write.table.PhysicalName, write.table.Data.KeySchema, write.key)
					if indexes := blocked[id]; len(indexes) != 0 {
						out.UnprocessedItems[selector] = append(out.UnprocessedItems[selector], request)
						err := s.throttle(ctx, write.table, indexes, true, 1)
						if rejected == nil {
							rejected = err
						}
					} else {
						input.RequestItems[selector] = append(input.RequestItems[selector], request)
					}
				}
			}
			if len(input.RequestItems) == 0 {
				return rejected
			}
		}
		pendingCapture, err := s.beginMutationWrite(ctx, writes, nil)
		if err != nil {
			return err
		}
		unprocessed := out.UnprocessedItems
		out.UnprocessedItems = nil
		if err := s.callEngine(ctx, group.plan.table, "BatchWriteItem", &input, out); err != nil {
			return err
		}
		if len(unprocessed) != 0 && out.UnprocessedItems == nil {
			out.UnprocessedItems = make(api.BatchWriteItemRequestMap)
		}
		for name, requests := range unprocessed {
			out.UnprocessedItems[name] = append(out.UnprocessedItems[name], requests...)
		}
		pending := make(map[capacityItemID]bool)
		for name, requests := range out.UnprocessedItems {
			table := group.plan.tables[string(name)]
			for _, request := range requests {
				var key api.Key
				if request.PutRequest != nil {
					key = api.Key(request.PutRequest.Item)
				} else {
					key = request.DeleteRequest.Key
				}
				pending[capacityKeyID(table.PhysicalName, table.Data.KeySchema, key)] = true
			}
		}
		if err := s.finishMutationWrite(ctx, pendingCapture, writes, pending); err != nil {
			return err
		}
		out.ConsumedCapacity = nil
		for i, write := range writes {
			if pending[capacityKeyID(write.table.PhysicalName, write.table.Data.KeySchema, write.key)] {
				continue
			}
			s.admission.charge(write.table, &charges[i], true)
			mergeStatementCapacity(&out.ConsumedCapacity, &charges[i])
		}
		return s.completeCapacities(ctx, &group.plan, &out.ConsumedCapacity, requested, true)
	}, group.plan.additional...)
}
