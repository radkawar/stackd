package dynamodb

import (
	"context"
	"encoding/json"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

type orderedReadCursor struct {
	Range int     `json:"range"`
	Key   api.Key `json:"key,omitempty"`
}

// executeStatementRead preserves native PartiQL expression validation and
// evaluation, but uses Query for ordered traversal: Local ignores ORDER BY.
// Neither returned items nor their projected values are synthesized here.
func (s *Service) executeStatementRead(ctx context.Context, statement *dataStatement, in *api.ExecuteStatementInput, out *api.ExecuteStatementOutput) error {
	table := statement.table
	indexName := statement.parsed.Index()
	schema := dataKeySchema(table, indexName)
	for _, index := range table.Data.GlobalSecondaryIndexes {
		if value(index.IndexName) != indexName {
			continue
		}
		if !indexProjectsAttributes(table.Data.KeySchema, schema, index.Projection, statement.access.Attributes) {
			return failure("ValidationException", "Secondary index "+indexName+" does not project one or more requested attributes.")
		}
	}
	plan, planErr := statement.access.ReadPlan, statement.access.ReadError
	if planErr == nil && (plan == nil || !plan.Ordered && len(plan.Ranges) == 1) {
		return s.callEngine(ctx, table, "ExecuteStatement", in, out)
	}
	// Native PartiQL owns expression validation, while Query owns ORDER BY.
	// Local both ignores direction and fails some valid ORDER BY projections.
	// Its unrelated cursor decoder must never receive our Query continuation.
	validation := *in
	validation.Statement = new(api.PartiQLStatement(statement.parsed.UnorderedRead(table.PhysicalName)))
	validation.NextToken = nil
	validation.ReturnConsumedCapacity = nil
	if validation.Limit == nil || *validation.Limit > 1 {
		validation.Limit = new(api.PositiveIntegerObject(1))
	}
	if err := s.callEngine(ctx, table, "ExecuteStatement", &validation, new(api.ExecuteStatementOutput)); err != nil {
		return err
	}
	if planErr != nil {
		return failure("ValidationException", planErr.Error())
	}
	cursor := orderedReadCursor{}
	if in.NextToken != nil {
		raw, ok := strings.CutPrefix(string(*in.NextToken), "query:")
		if !ok || json.Unmarshal([]byte(raw), &cursor) != nil || cursor.Range < 0 || cursor.Range >= len(plan.Ranges) {
			return failure("ValidationException", "Invalid NextToken")
		}
	}
	out.Items = api.ItemList{}
	var capacities api.ConsumedCapacityMultiple
	evaluatedCount, evaluatedBytes := 0, 0
	for cursor.Range < len(plan.Ranges) {
		r := &plan.Ranges[cursor.Range]
		query := &api.QueryInput{
			TableName: new(api.TableArn(table.PhysicalName)), KeyConditions: r.Conditions,
			ConsistentRead: in.ConsistentRead, ScanIndexForward: new(api.BooleanObject(plan.Forward)),
			ExclusiveStartKey: cursor.Key,
		}
		if in.Limit != nil {
			query.Limit = new(api.PositiveIntegerObject(int(*in.Limit) - evaluatedCount))
		}
		if indexName != "" {
			query.IndexName = new(api.IndexName(indexName))
		}
		evaluated := new(api.QueryOutput)
		point := r.Point && indexName == ""
		var pointKey api.Key
		if point {
			pointKey = make(api.Key, len(r.Conditions))
			for name, condition := range r.Conditions {
				pointKey[name] = condition.AttributeValueList[0]
			}
			result := new(api.GetItemOutput)
			if err := s.callEngine(ctx, table, "GetItem", &api.GetItemInput{TableName: query.TableName, Key: pointKey, ConsistentRead: in.ConsistentRead}, result); err != nil {
				return err
			}
			if len(result.Item) != 0 {
				evaluated.Items = api.ItemList{result.Item}
			}
		} else if err := s.callEngine(ctx, table, "Query", query, evaluated); err != nil {
			return err
		}
		// The public page budget spans all ranges. Reading beyond this prefix
		// is an auxiliary engine read, not additional customer-evaluated data.
		for i, image := range evaluated.Items {
			size := itemSize(image)
			if evaluatedBytes+size > 1<<20 {
				evaluated.Items = evaluated.Items[:i]
				if i == 0 {
					goto complete
				}
				evaluated.LastEvaluatedKey = capacityKey(table.Data.KeySchema, evaluated.Items[i-1])
				for _, member := range schema {
					name := api.AttributeName(*member.AttributeName)
					evaluated.LastEvaluatedKey[name] = evaluated.Items[i-1][name]
				}
				break
			}
			evaluatedBytes += size
		}
		evaluatedCount += len(evaluated.Items)
		if statement.parsed.DirectReadItems(r) {
			out.Items = append(out.Items, evaluated.Items...)
		} else {
			for _, image := range evaluated.Items {
				text, parameters := statement.parsed.PointStatement(r, table.PhysicalName, schema, table.Data.KeySchema, image, statement.parameters)
				request := &api.ExecuteStatementInput{Statement: new(api.PartiQLStatement(text)), Parameters: parameters, ConsistentRead: in.ConsistentRead}
				for {
					result := new(api.ExecuteStatementOutput)
					if err := s.callEngine(ctx, table, "ExecuteStatement", request, result); err != nil {
						return err
					}
					out.Items = append(out.Items, result.Items...)
					if result.NextToken == nil {
						break
					}
					request.NextToken = result.NextToken
				}
			}
		}
		// Do not bill auxiliary EOF discovery as a new missing-key lookup.
		// TODO: Comeback account for native storage-partition continuation overhead.
		exhausted := len(evaluated.Items) == 0 && len(cursor.Key) != 0 && cursor.Range+1 < len(plan.Ranges)
		if !exhausted && s.needsCapacity(in.ReturnConsumedCapacity, false, statement.table) {
			page := &api.ExecuteStatementOutput{Items: evaluated.Items}
			capacity, err := s.statementReadCapacityPage(ctx, statement, in, false, page, r.Conditions)
			if err != nil {
				return err
			}
			mergeStatementCapacity(&capacities, capacity)
		}
		out.LastEvaluatedKey = evaluated.LastEvaluatedKey
		cursor.Key = evaluated.LastEvaluatedKey
		if len(cursor.Key) == 0 {
			cursor.Range++
		}
		if in.Limit != nil && evaluatedCount >= int(*in.Limit) {
			if point && !r.Filtered() {
				out.LastEvaluatedKey = pointKey
			}
			break
		}
		if len(cursor.Key) != 0 {
			break
		} // native one-megabyte boundary
	}
complete:
	if cursor.Range < len(plan.Ranges) {
		raw, err := json.Marshal(cursor)
		if err != nil {
			return err
		}
		out.NextToken = new(api.PartiQLNextToken("query:" + string(raw)))
	}
	if len(capacities) != 0 {
		out.ConsumedCapacity = &capacities[0]
	}
	return nil
}
