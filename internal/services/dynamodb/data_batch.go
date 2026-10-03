package dynamodb

import (
	"context"
	"sort"

	api "stackd/internal/awsapi/dynamodb"
)

func dataSortedTables[M ~map[api.TableArn]V, V any](m M) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, string(name))
	}
	sort.Strings(names)
	return names
}

type dataGetBatch struct {
	plan  dataPlan
	input api.BatchGetItemInput
}
type dataWriteBatch struct {
	plan  dataPlan
	input api.BatchWriteItemInput
}

func (s *Service) batchGetItem(ctx context.Context, in *api.BatchGetItemInput) (*api.BatchGetItemOutput, error) {
	var groups []*dataGetBatch
	count := 0
	err := s.repository.View(ctx, func(r Reader) error {
		for _, selector := range dataSortedTables(in.RequestItems) {
			request := in.RequestItems[api.TableArn(selector)]
			count += len(request.Keys)
			table, err := s.dataTable(r.Context(), r, selector)
			if err != nil {
				return err
			}
			a := dataAccess{keys: request.Keys, attributes: dataAttributeList(request.AttributesToGet), names: request.ExpressionAttributeNames, projection: value(request.ProjectionExpression), selectMode: dataSelect("", value(request.ProjectionExpression), request.AttributesToGet, "")}
			for _, key := range request.Keys {
				a.attributes = append(a.attributes, dataMapAttributes(key)...)
			}
			if err := s.dataAuthorize(r.Context(), r, table, "BatchGetItem", "", a); err != nil {
				return err
			}
			var group *dataGetBatch
			for _, candidate := range groups {
				if candidate.plan.table.DatabaseID == table.DatabaseID && candidate.plan.table.Key.Scope == table.Key.Scope {
					group = candidate
					break
				}
			}
			if group == nil {
				group = &dataGetBatch{input: *in}
				group.input.RequestItems = make(api.BatchGetRequestMap)
				groups = append(groups, group)
			}
			if _, duplicate := group.input.RequestItems[api.TableArn(table.PhysicalName)]; duplicate {
				return failure("ValidationException", "The same table cannot appear under multiple table identifiers.")
			}
			if err := group.plan.add(&table, selector); err != nil {
				return err
			}
			group.input.RequestItems[api.TableArn(table.PhysicalName)] = request
		}
		if len(groups) == 0 {
			return failure("ValidationException", "The request must contain at least one table.")
		}
		// The native limit applies to the original request, not each routed part.
		if count > 100 {
			return failure("ValidationException", "Too many items requested for the BatchGetItem call.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := new(api.BatchGetItemOutput)
	var throttled error
	processed := count
	for _, group := range groups {
		part := new(api.BatchGetItemOutput)
		if err := s.readBatch(ctx, group, part); err != nil {
			if !capacityThrottled(err) {
				return nil, err
			}
			if throttled == nil {
				throttled = err
			}
		}
		for _, request := range part.UnprocessedKeys {
			processed -= len(request.Keys)
		}
		out.ConsumedCapacity = append(out.ConsumedCapacity, part.ConsumedCapacity...)
		out.Responses = dataMergeMaps(out.Responses, dataRemap(part.Responses, &group.plan))
		out.UnprocessedKeys = dataMergeMaps(out.UnprocessedKeys, dataRemap(part.UnprocessedKeys, &group.plan))
	}
	if processed == 0 && throttled != nil {
		return nil, throttled
	}
	return out, nil
}
func (s *Service) batchWriteItem(ctx context.Context, in *api.BatchWriteItemInput) (*api.BatchWriteItemOutput, error) {
	var groups []*dataWriteBatch
	count := 0
	err := s.repository.View(ctx, func(r Reader) error {
		for _, selector := range dataSortedTables(in.RequestItems) {
			requests := in.RequestItems[api.TableArn(selector)]
			count += len(requests)
			table, err := s.dataTable(r.Context(), r, selector)
			if err != nil {
				return err
			}
			a := dataAccess{}
			for _, request := range requests {
				if request.PutRequest != nil {
					a.keys = append(a.keys, api.Key(request.PutRequest.Item))
					a.attributes = append(a.attributes, dataMapAttributes(request.PutRequest.Item)...)
				}
				if request.DeleteRequest != nil {
					a.keys = append(a.keys, request.DeleteRequest.Key)
					a.attributes = append(a.attributes, dataMapAttributes(request.DeleteRequest.Key)...)
				}
			}
			if err := s.dataAuthorize(r.Context(), r, table, "BatchWriteItem", "", a); err != nil {
				return err
			}
			var group *dataWriteBatch
			for _, candidate := range groups {
				if candidate.plan.table.DatabaseID == table.DatabaseID && candidate.plan.table.Key.Scope == table.Key.Scope {
					group = candidate
					break
				}
			}
			if group == nil {
				group = &dataWriteBatch{input: *in}
				group.input.RequestItems = make(api.BatchWriteItemRequestMap)
				groups = append(groups, group)
			}
			if _, duplicate := group.input.RequestItems[api.TableArn(table.PhysicalName)]; duplicate {
				return failure("ValidationException", "The same table cannot appear under multiple table identifiers.")
			}
			if err := group.plan.add(&table, selector); err != nil {
				return err
			}
			group.input.RequestItems[api.TableArn(table.PhysicalName)] = requests
		}
		if len(groups) == 0 {
			return failure("ValidationException", "The request must contain at least one table.")
		}
		if count > 25 {
			return failure("ValidationException", "Too many items requested for the BatchWriteItem call.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(groups) > 1 {
		for _, group := range groups {
			if err := s.validateWriteBatch(ctx, group); err != nil {
				return nil, err
			}
		}
	}
	out := new(api.BatchWriteItemOutput)
	var throttled error
	processed := count
	for _, group := range groups {
		part := new(api.BatchWriteItemOutput)
		if err := s.writeBatch(ctx, group, part); err != nil {
			if !capacityThrottled(err) {
				return nil, err
			}
			if throttled == nil {
				throttled = err
			}
		}
		for _, requests := range part.UnprocessedItems {
			processed -= len(requests)
		}
		out.ConsumedCapacity = append(out.ConsumedCapacity, part.ConsumedCapacity...)
		out.ItemCollectionMetrics = dataMergeMaps(out.ItemCollectionMetrics, dataRemap(part.ItemCollectionMetrics, &group.plan))
		out.UnprocessedItems = dataMergeMaps(out.UnprocessedItems, dataRemap(part.UnprocessedItems, &group.plan))
	}
	if processed == 0 && throttled != nil {
		return nil, throttled
	}
	return out, nil
}
