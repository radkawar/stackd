package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodb"
)

func registerData(s *Service) {
	registerExternal(s, "PutItem", s.putItem)
	registerExternal(s, "GetItem", s.getItem)
	registerExternal(s, "UpdateItem", s.updateItem)
	registerExternal(s, "DeleteItem", s.deleteItem)
	registerExternal(s, "Query", s.query)
	registerExternal(s, "Scan", s.scan)
	registerExternal(s, "BatchGetItem", s.batchGetItem)
	registerExternal(s, "BatchWriteItem", s.batchWriteItem)
	registerExternal(s, "TransactGetItems", s.transactGetItems)
	registerExternal(s, "TransactWriteItems", s.transactWriteItems)
	registerExternal(s, "ExecuteStatement", s.executeStatement)
	registerExternal(s, "BatchExecuteStatement", s.batchExecuteStatement)
	registerExternal(s, "ExecuteTransaction", s.executeTransaction)
}
func (s *Service) putItem(ctx context.Context, in *api.PutItemInput) (*api.PutItemOutput, error) {
	a := dataAccess{keys: []api.Key{api.Key(in.Item)}, attributes: append(dataMapAttributes(in.Item), dataMapAttributes(in.Expected)...), names: in.ExpressionAttributeNames, expressions: []string{value(in.ConditionExpression)}, returns: dataReturn(value(in.ReturnValues))}
	table, err := s.prepareData(ctx, value(in.TableName), "PutItem", "", a)
	if err != nil {
		return nil, err
	}
	input := *in
	input.TableName = dataPhysical(table)
	input.ReturnConsumedCapacity = nil
	input.ReturnValuesOnConditionCheckFailure = s.conditionCapacityRequest(in.ReturnValuesOnConditionCheckFailure, table)
	out := new(api.PutItemOutput)
	meter := s.needsCapacity(in.ReturnConsumedCapacity, true, table)
	if meter && (value(in.ReturnValues) == "" || value(in.ReturnValues) == "NONE") {
		input.ReturnValues = new(api.ReturnValueALL_OLD)
	}
	write := capacityWrite{table: table, key: capacityKey(table.Data.KeySchema, api.AttributeMap(in.Item)), after: api.AttributeMap(in.Item), readBefore: value(input.ReturnValues) != "ALL_OLD"}
	if err := s.writeItemMutation(ctx, &write, &out.ConsumedCapacity, in.ReturnConsumedCapacity, func() error {
		if err := s.callEngine(ctx, table, "PutItem", &input, out); err != nil {
			return s.conditionFailure(ctx, table, err, in.ReturnValuesOnConditionCheckFailure)
		}
		if value(input.ReturnValues) == "ALL_OLD" {
			write.before = out.Attributes
		}
		if value(in.ReturnValues) != "ALL_OLD" {
			out.Attributes = nil
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) getItem(ctx context.Context, in *api.GetItemInput) (*api.GetItemOutput, error) {
	a := dataAccess{keys: []api.Key{in.Key}, attributes: append(dataAttributeList(in.AttributesToGet), dataMapAttributes(in.Key)...), names: in.ExpressionAttributeNames, projection: value(in.ProjectionExpression), selectMode: dataSelect("", value(in.ProjectionExpression), in.AttributesToGet, "")}
	table, err := s.prepareData(ctx, value(in.TableName), "GetItem", "", a)
	if err != nil {
		return nil, err
	}
	input := *in
	input.TableName = dataPhysical(table)
	input.ReturnConsumedCapacity = s.capacityRequest(in.ReturnConsumedCapacity, table)
	out := new(api.GetItemOutput)
	if err := s.readCapacity(ctx, table, "", "GetItem", &input, out, &out.ConsumedCapacity, in.ReturnConsumedCapacity); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) updateItem(ctx context.Context, in *api.UpdateItemInput) (*api.UpdateItemOutput, error) {
	attributes := append(dataMapAttributes(in.Key), dataMapAttributes(in.AttributeUpdates)...)
	attributes = append(attributes, dataMapAttributes(in.Expected)...)
	a := dataAccess{keys: []api.Key{in.Key}, attributes: attributes, names: in.ExpressionAttributeNames, expressions: []string{value(in.ConditionExpression), value(in.UpdateExpression)}, returns: dataReturn(value(in.ReturnValues))}
	table, err := s.prepareData(ctx, value(in.TableName), "UpdateItem", "", a)
	if err != nil {
		return nil, err
	}
	input := *in
	input.TableName = dataPhysical(table)
	input.ReturnConsumedCapacity = nil
	input.ReturnValuesOnConditionCheckFailure = s.conditionCapacityRequest(in.ReturnValuesOnConditionCheckFailure, table)
	out := new(api.UpdateItemOutput)
	write := capacityWrite{table: table, key: in.Key, readBefore: true, readAfter: true}
	meter := s.needsCapacity(in.ReturnConsumedCapacity, true, table)
	if meter {
		switch value(in.ReturnValues) {
		case "", "NONE", "ALL_OLD":
			input.ReturnValues = new(api.ReturnValueALL_OLD)
			write.readBefore = false
		case "ALL_NEW":
			write.readAfter = false
		}
	}
	if err := s.writeItemMutation(ctx, &write, &out.ConsumedCapacity, in.ReturnConsumedCapacity, func() error {
		if err := s.callEngine(ctx, table, "UpdateItem", &input, out); err != nil {
			return s.conditionFailure(ctx, table, err, in.ReturnValuesOnConditionCheckFailure)
		}
		if !write.readBefore {
			write.before = out.Attributes
		}
		if !write.readAfter {
			write.after = out.Attributes
			write.afterObserved = true
		}
		if value(in.ReturnValues) == "" || value(in.ReturnValues) == "NONE" {
			out.Attributes = nil
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) deleteItem(ctx context.Context, in *api.DeleteItemInput) (*api.DeleteItemOutput, error) {
	a := dataAccess{keys: []api.Key{in.Key}, attributes: append(dataMapAttributes(in.Key), dataMapAttributes(in.Expected)...), names: in.ExpressionAttributeNames, expressions: []string{value(in.ConditionExpression)}, returns: dataReturn(value(in.ReturnValues))}
	table, err := s.prepareData(ctx, value(in.TableName), "DeleteItem", "", a)
	if err != nil {
		return nil, err
	}
	input := *in
	input.TableName = dataPhysical(table)
	input.ReturnConsumedCapacity = nil
	input.ReturnValuesOnConditionCheckFailure = s.conditionCapacityRequest(in.ReturnValuesOnConditionCheckFailure, table)
	out := new(api.DeleteItemOutput)
	meter := s.needsCapacity(in.ReturnConsumedCapacity, true, table)
	if meter && (value(in.ReturnValues) == "" || value(in.ReturnValues) == "NONE") {
		input.ReturnValues = new(api.ReturnValueALL_OLD)
	}
	write := capacityWrite{table: table, key: in.Key, readBefore: value(input.ReturnValues) != "ALL_OLD"}
	if err := s.writeItemMutation(ctx, &write, &out.ConsumedCapacity, in.ReturnConsumedCapacity, func() error {
		if err := s.callEngine(ctx, table, "DeleteItem", &input, out); err != nil {
			return s.conditionFailure(ctx, table, err, in.ReturnValuesOnConditionCheckFailure)
		}
		if value(input.ReturnValues) == "ALL_OLD" {
			write.before = out.Attributes
		}
		if value(in.ReturnValues) != "ALL_OLD" {
			out.Attributes = nil
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) query(ctx context.Context, in *api.QueryInput) (*api.QueryOutput, error) {
	index := value(in.IndexName)
	attributes := append(dataAttributeList(in.AttributesToGet), dataMapAttributes(in.KeyConditions)...)
	attributes = append(attributes, dataMapAttributes(in.QueryFilter)...)
	a := dataAccess{attributes: attributes, names: in.ExpressionAttributeNames, expressions: []string{value(in.KeyConditionExpression), value(in.FilterExpression)}, projection: value(in.ProjectionExpression), selectMode: dataSelect(value(in.Select), value(in.ProjectionExpression), in.AttributesToGet, index)}
	var table *TableRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		table, err = s.dataTable(r.Context(), r, value(in.TableName))
		if err != nil {
			return err
		}
		pk := dataPartitionKey(table, index)
		if condition, ok := in.KeyConditions[api.AttributeName(pk)]; ok && value(condition.ComparisonOperator) == "EQ" && len(condition.AttributeValueList) == 1 {
			a.keys = []api.Key{{api.AttributeName(pk): condition.AttributeValueList[0]}}
		}
		if in.KeyConditionExpression != nil {
			a.keys = dataQueryKeys(value(in.KeyConditionExpression), in.ExpressionAttributeNames, in.ExpressionAttributeValues, pk)
		}
		return s.dataAuthorize(r.Context(), r, table, "Query", index, a)
	})
	if err != nil {
		return nil, err
	}
	input := *in
	input.TableName = dataPhysical(table)
	input.ReturnConsumedCapacity = s.capacityRequest(in.ReturnConsumedCapacity, table)
	out := new(api.QueryOutput)
	if err := s.readCapacity(ctx, table, index, "Query", &input, out, &out.ConsumedCapacity, in.ReturnConsumedCapacity); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) scan(ctx context.Context, in *api.ScanInput) (*api.ScanOutput, error) {
	index := value(in.IndexName)
	a := dataAccess{attributes: append(dataAttributeList(in.AttributesToGet), dataMapAttributes(in.ScanFilter)...), names: in.ExpressionAttributeNames, expressions: []string{value(in.FilterExpression)}, projection: value(in.ProjectionExpression), selectMode: dataSelect(value(in.Select), value(in.ProjectionExpression), in.AttributesToGet, index)}
	table, err := s.prepareData(ctx, value(in.TableName), "Scan", index, a)
	if err != nil {
		return nil, err
	}
	input := *in
	input.TableName = dataPhysical(table)
	input.ReturnConsumedCapacity = s.capacityRequest(in.ReturnConsumedCapacity, table)
	out := new(api.ScanOutput)
	if err := s.readCapacity(ctx, table, index, "Scan", &input, out, &out.ConsumedCapacity, in.ReturnConsumedCapacity); err != nil {
		return nil, err
	}
	return out, nil
}
