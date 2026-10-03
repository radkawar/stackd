package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodb"
)

func (s *Service) transactionTable(ctx context.Context, r Reader, plan *dataPlan, selector, action string, a dataAccess) (*api.TableArn, error) {
	table, err := s.dataTable(ctx, r, selector)
	if err != nil {
		return nil, err
	}
	if err := s.dataAuthorize(ctx, r, table, action, "", a); err != nil {
		return nil, err
	}
	if err := plan.add(&table, selector); err != nil {
		return nil, err
	}
	return dataPhysical(table), nil
}
func (s *Service) transactGetItems(ctx context.Context, in *api.TransactGetItemsInput) (*api.TransactGetItemsOutput, error) {
	input := *in
	input.TransactItems = make(api.TransactGetItemList, len(in.TransactItems))
	plan := dataPlan{}
	err := s.repository.View(ctx, func(r Reader) error {
		for i, request := range in.TransactItems {
			if request.Get == nil {
				return failure("ValidationException", "A transaction get operation is required.")
			}
			get := *request.Get
			a := dataAccess{keys: []api.Key{get.Key}, attributes: dataMapAttributes(get.Key), names: get.ExpressionAttributeNames, projection: value(get.ProjectionExpression), selectMode: dataSelect("", value(get.ProjectionExpression), nil, ""), enclosing: "TransactGetItems"}
			name, err := s.transactionTable(r.Context(), r, &plan, value(get.TableName), "GetItem", a)
			if err != nil {
				return err
			}
			get.TableName = name
			input.TransactItems[i] = api.TransactGetItem{Get: &get}
		}
		return plan.ready()
	})
	if err != nil {
		return nil, err
	}
	input.ReturnConsumedCapacity = s.capacityRequest(in.ReturnConsumedCapacity, plan.table, plan.additional...)
	out := new(api.TransactGetItemsOutput)
	err = s.withData(ctx, plan.table, func() error {
		if err := s.admitPlan(ctx, &plan, false); err != nil {
			return err
		}
		if err := s.callEngine(ctx, plan.table, "TransactGetItems", &input, out); err != nil {
			return err
		}
		s.chargeCapacities(&plan, out.ConsumedCapacity, false)
		return s.completeCapacities(ctx, &plan, &out.ConsumedCapacity, in.ReturnConsumedCapacity, false)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) transactWriteItems(ctx context.Context, in *api.TransactWriteItemsInput) (*api.TransactWriteItemsOutput, error) {
	input := *in
	input.TransactItems = make(api.TransactWriteItemList, len(in.TransactItems))
	plan := dataPlan{}
	err := s.repository.View(ctx, func(r Reader) error {
		for i, request := range in.TransactItems {
			count := 0
			if request.Put != nil {
				count++
			}
			if request.Update != nil {
				count++
			}
			if request.Delete != nil {
				count++
			}
			if request.ConditionCheck != nil {
				count++
			}
			if count != 1 {
				return failure("ValidationException", "Each transaction item must contain exactly one operation.")
			}
			switch {
			case request.Put != nil:
				put := *request.Put
				a := dataAccess{keys: []api.Key{api.Key(put.Item)}, attributes: dataMapAttributes(put.Item), names: put.ExpressionAttributeNames, expressions: []string{value(put.ConditionExpression)}, enclosing: "TransactWriteItems"}
				name, err := s.transactionTable(r.Context(), r, &plan, value(put.TableName), "PutItem", a)
				if err != nil {
					return err
				}
				put.TableName = name
				put.ReturnValuesOnConditionCheckFailure = transactionConditionReturn(put.ReturnValuesOnConditionCheckFailure)
				put.Item, _ = transactionAttributes(put.Item)
				put.ExpressionAttributeValues, _ = transactionAttributes(put.ExpressionAttributeValues)
				input.TransactItems[i].Put = &put
			case request.Update != nil:
				update := *request.Update
				a := dataAccess{keys: []api.Key{update.Key}, attributes: dataMapAttributes(update.Key), names: update.ExpressionAttributeNames, expressions: []string{value(update.ConditionExpression), value(update.UpdateExpression)}, enclosing: "TransactWriteItems"}
				name, err := s.transactionTable(r.Context(), r, &plan, value(update.TableName), "UpdateItem", a)
				if err != nil {
					return err
				}
				update.TableName = name
				update.ReturnValuesOnConditionCheckFailure = transactionConditionReturn(update.ReturnValuesOnConditionCheckFailure)
				update.Key, _ = transactionAttributes(update.Key)
				update.ExpressionAttributeValues, _ = transactionAttributes(update.ExpressionAttributeValues)
				input.TransactItems[i].Update = &update
			case request.Delete != nil:
				del := *request.Delete
				a := dataAccess{keys: []api.Key{del.Key}, attributes: dataMapAttributes(del.Key), names: del.ExpressionAttributeNames, expressions: []string{value(del.ConditionExpression)}, enclosing: "TransactWriteItems"}
				name, err := s.transactionTable(r.Context(), r, &plan, value(del.TableName), "DeleteItem", a)
				if err != nil {
					return err
				}
				del.TableName = name
				del.ReturnValuesOnConditionCheckFailure = transactionConditionReturn(del.ReturnValuesOnConditionCheckFailure)
				del.Key, _ = transactionAttributes(del.Key)
				del.ExpressionAttributeValues, _ = transactionAttributes(del.ExpressionAttributeValues)
				input.TransactItems[i].Delete = &del
			case request.ConditionCheck != nil:
				check := *request.ConditionCheck
				a := dataAccess{keys: []api.Key{check.Key}, attributes: dataMapAttributes(check.Key), names: check.ExpressionAttributeNames, expressions: []string{value(check.ConditionExpression)}, enclosing: "TransactWriteItems"}
				name, err := s.transactionTable(r.Context(), r, &plan, value(check.TableName), "ConditionCheckItem", a)
				if err != nil {
					return err
				}
				check.TableName = name
				check.ReturnValuesOnConditionCheckFailure = transactionConditionReturn(check.ReturnValuesOnConditionCheckFailure)
				check.Key, _ = transactionAttributes(check.Key)
				check.ExpressionAttributeValues, _ = transactionAttributes(check.ExpressionAttributeValues)
				input.TransactItems[i].ConditionCheck = &check
			}
		}
		return plan.ready()
	})
	if err != nil {
		return nil, err
	}
	out := new(api.TransactWriteItemsOutput)
	if err := s.writeTransaction(ctx, &plan, &input, out); err != nil {
		return nil, err
	}
	out.ItemCollectionMetrics = dataRemap(out.ItemCollectionMetrics, &plan)
	return out, nil
}

// Local distinguishes an omitted condition-return mode from explicit NONE in
// token equality; AWS treats them identically. Normalize only the native input.
func transactionConditionReturn(mode *api.ReturnValuesOnConditionCheckFailure) *api.ReturnValuesOnConditionCheckFailure {
	if value(mode) == "NONE" {
		return nil
	}
	return mode
}
