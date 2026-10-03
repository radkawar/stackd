package dynamodb

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/dynamodb"
)

// JSONRequestLimit preserves BatchWriteItem's original 16 MiB HTTP envelope,
// including JSON escapes and whitespace, before filtering or database routing.
func (*Service) JSONRequestLimit(action string) int {
	if action == "BatchWriteItem" {
		return 16 << 20
	}
	return 0
}

// validateWriteBatch preserves whole-request validation before routing or
// filtering changes the native batch. The impossible native condition validates
// complete item/key shapes without changing an item or creating a Streams event.
// Ordinary, intact batches continue to use the native batch validator directly.
func (s *Service) validateWriteBatch(ctx context.Context, group *dataWriteBatch) error {
	seen := make(map[capacityItemID]bool)
	for _, name := range dataSortedTables(group.input.RequestItems) {
		table := group.plan.tables[name]
		pk := dataPartitionKey(table, "")
		condition := new(api.ConditionExpression("attribute_exists(#key) AND attribute_not_exists(#key)"))
		names := api.ExpressionAttributeNameMap{"#key": api.AttributeName(pk)}
		requests := group.input.RequestItems[api.TableArn(name)]
		if len(requests) == 0 {
			return failure("ValidationException", "A batch table must contain at least one write request.")
		}
		for _, request := range requests {
			if (request.PutRequest == nil) == (request.DeleteRequest == nil) {
				return failure("ValidationException", "Each batch write must contain exactly one put or delete request.")
			}
			var key api.Key
			var err error
			if request.PutRequest != nil {
				key = capacityKey(table.Data.KeySchema, api.AttributeMap(request.PutRequest.Item))
				input := api.PutItemInput{TableName: dataPhysical(table), Item: request.PutRequest.Item, ConditionExpression: condition, ExpressionAttributeNames: names}
				err = s.callEngine(ctx, table, "PutItem", &input, new(api.PutItemOutput))
			} else {
				key = request.DeleteRequest.Key
				input := api.DeleteItemInput{TableName: dataPhysical(table), Key: key, ConditionExpression: condition, ExpressionAttributeNames: names}
				err = s.callEngine(ctx, table, "DeleteItem", &input, new(api.DeleteItemOutput))
			}
			if !engineCode(err, "ConditionalCheckFailedException") {
				if err == nil {
					return errors.New("DynamoDB engine did not reject the impossible validation condition")
				}
				return err
			}
			id := capacityKeyID(table.PhysicalName, table.Data.KeySchema, key)
			if seen[id] {
				return failure("ValidationException", "Provided list of item keys contains duplicates")
			}
			seen[id] = true
		}
	}
	return nil
}

func (s *Service) readBatch(ctx context.Context, group *dataGetBatch, out *api.BatchGetItemOutput) error {
	return s.withData(ctx, group.plan.table, func() error {
		input := group.input
		input.ReturnConsumedCapacity = s.capacityRequest(group.input.ReturnConsumedCapacity, group.plan.table, group.plan.additional...)
		// This read owns validation of the complete original batch and its native
		// size limits. It is public work only for the keys admitted below.
		if err := s.callEngine(ctx, group.plan.table, "BatchGetItem", &input, out); err != nil {
			return err
		}
		capacities := out.ConsumedCapacity
		// Each table contributes at most one aggregate, so reuse native storage.
		out.ConsumedCapacity = capacities[:0]
		var rejected error
		for i := range capacities {
			capacity := &capacities[i]
			table := group.plan.tables[value(capacity.TableName)]
			selector := api.TableArn(table.PhysicalName)
			request := input.RequestItems[selector]
			processed := len(request.Keys) - len(out.UnprocessedKeys[selector].Keys)
			if s.admission.coversReadBatch(table, tableCapacityUnits(capacity, false).read, processed) {
				s.admission.charge(table, capacity, false)
				out.ConsumedCapacity = append(out.ConsumedCapacity, *capacity)
				continue
			}
			if err := s.readBatchKeys(ctx, table, request, out); err != nil {
				if !capacityThrottled(err) {
					return err
				}
				if rejected == nil {
					rejected = err
				}
			}
		}
		if err := s.completeCapacities(ctx, &group.plan, &out.ConsumedCapacity, group.input.ReturnConsumedCapacity, false); err != nil {
			return err
		}
		return rejected
	})
}

func (s *Service) readBatchKeys(ctx context.Context, table *TableRecord, request api.KeysAndAttributes, out *api.BatchGetItemOutput) error {
	selector := api.TableArn(table.PhysicalName)
	// Never retry keys already withheld by the native response-size boundary.
	nativePending := make(map[capacityItemID]bool, len(out.UnprocessedKeys[selector].Keys))
	for _, key := range out.UnprocessedKeys[selector].Keys {
		nativePending[capacityKeyID(table.PhysicalName, table.Data.KeySchema, key)] = true
	}
	delete(out.Responses, selector)
	pending := request
	pending.Keys = nil
	single := api.BatchGetItemInput{
		RequestItems: make(api.BatchGetRequestMap, 1), ReturnConsumedCapacity: new(api.ReturnConsumedCapacity("INDEXES")),
	}
	var rejected int64
	for i, key := range request.Keys {
		if len(nativePending) != 0 && nativePending[capacityKeyID(table.PhysicalName, table.Data.KeySchema, key)] {
			pending.Keys = append(pending.Keys, key)
			continue
		}
		if !s.admission.coversReadBatch(table, 0, 1) {
			pending.Keys = append(pending.Keys, key)
			rejected++
			continue
		}
		member := request
		member.Keys = request.Keys[i : i+1]
		single.RequestItems[selector] = member
		var part api.BatchGetItemOutput
		if err := s.callEngine(ctx, table, "BatchGetItem", &single, &part); err != nil {
			return err
		}
		for j := range part.ConsumedCapacity {
			capacity := &part.ConsumedCapacity[j]
			s.admission.charge(table, capacity, false)
			mergeStatementCapacity(&out.ConsumedCapacity, capacity)
		}
		if items, ok := part.Responses[selector]; ok {
			if previous, exists := out.Responses[selector]; exists {
				out.Responses[selector] = append(previous, items...)
			} else {
				out.Responses = dataMergeMaps(out.Responses, part.Responses)
			}
		}
		pending.Keys = append(pending.Keys, part.UnprocessedKeys[selector].Keys...)
	}
	if len(pending.Keys) != 0 {
		if out.UnprocessedKeys == nil {
			out.UnprocessedKeys = make(api.BatchGetRequestMap)
		}
		out.UnprocessedKeys[selector] = pending
	}
	if rejected != 0 {
		return s.throttle(ctx, table, []api.IndexName{""}, false, rejected)
	}
	return nil
}
