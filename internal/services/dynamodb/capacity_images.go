package dynamodb

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/dynamodb"
)

// capacityWrite retains the images needed for one accepted native write. The
// caller holds withMutation's gate across collection, execution and accounting.
// Put/Delete already supply their resulting image; Update needs the engine's.
type capacityWrite struct {
	table                         *TableRecord
	key                           api.Key
	before, after                 api.AttributeMap
	readBefore, readAfter         bool
	replica                       *ReplicaChange
	beforeObserved, afterObserved bool
	conditionOnly                 bool
}

type capacityItemID struct{ table, partition, sort string }

func capacityKey(schema api.KeySchema, item api.AttributeMap) api.Key {
	key := make(api.Key, len(schema))
	for _, member := range schema {
		name := api.AttributeName(value(member.AttributeName))
		if attribute, ok := item[name]; ok {
			key[name] = attribute
		}
	}
	return key
}

func capacityKeyID(table string, schema api.KeySchema, key api.Key) capacityItemID {
	id := capacityItemID{table: table}
	for _, member := range schema {
		scalar, _ := dataCanonicalScalar(key[api.AttributeName(value(member.AttributeName))])
		if value(member.KeyType) == "HASH" {
			id.partition = scalar
		} else {
			id.sort = scalar
		}
	}
	return id
}

func (w *capacityWrite) id() capacityItemID {
	return capacityKeyID(w.table.PhysicalName, w.table.Data.KeySchema, w.key)
}

func (s *Service) collectCapacityImages(ctx context.Context, plan *dataPlan, writes []capacityWrite, after bool) error {
	requests := make(api.BatchGetRequestMap)
	seen := make(map[capacityItemID]bool, len(writes))
	for i := range writes {
		write := &writes[i]
		if after && !write.readAfter || seen[write.id()] {
			continue
		}
		seen[write.id()] = true
		name := api.TableArn(write.table.PhysicalName)
		request := requests[name]
		request.ConsistentRead = new(api.ConsistentRead(true))
		request.Keys = append(request.Keys, write.key)
		requests[name] = request
	}
	if len(requests) == 0 {
		return nil
	}
	images := make(map[capacityItemID]api.AttributeMap, len(seen))
	for len(requests) != 0 {
		out := new(api.BatchGetItemOutput)
		if err := s.callEngine(ctx, plan.table, "BatchGetItem", &api.BatchGetItemInput{RequestItems: requests}, out); err != nil {
			return err
		}
		for name, items := range out.Responses {
			table := plan.tables[string(name)]
			for _, item := range items {
				images[capacityKeyID(table.PhysicalName, table.Data.KeySchema, api.Key(item))] = item
			}
		}
		pending, previous := 0, 0
		for _, request := range requests {
			previous += len(request.Keys)
		}
		for _, request := range out.UnprocessedKeys {
			pending += len(request.Keys)
		}
		if pending >= previous {
			return errors.New("DynamoDB engine made no progress collecting write capacity images")
		}
		requests = out.UnprocessedKeys
	}
	for i := range writes {
		write := &writes[i]
		if after {
			if write.readAfter {
				write.after = images[write.id()]
				write.afterObserved = true
			}
		} else {
			write.before = images[write.id()]
			write.beforeObserved = true
		}
	}
	return nil
}
