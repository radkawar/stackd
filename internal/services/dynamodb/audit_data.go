package dynamodb

import (
	"encoding/json"
	"sort"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
	"stackd/internal/services/dynamodb/partiql"
)

// Attribute bags and SQL never reach EncodeDocument. Only schema-proven key
// scalars and redacted statements are added afterward. Nested batch/transaction
// members are projected independently, then flattened to native requestItems.
var auditDataRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Item":                             {Mode: awsapi.OmitField},
	"Key":                              {Mode: awsapi.OmitField},
	"Keys":                             {Mode: awsapi.OmitField},
	"ClientRequestToken":               {Mode: awsapi.OmitField},
	"ExclusiveStartKey":                {Mode: awsapi.OmitField},
	"ExpressionAttributeValues":        {Mode: awsapi.OmitField},
	"Expected.Value":                   {Mode: awsapi.OmitField},
	"Expected.AttributeValueList":      {Mode: awsapi.OmitField},
	"AttributeUpdates.Value":           {Mode: awsapi.OmitField},
	"KeyConditions.AttributeValueList": {Mode: awsapi.OmitField},
	"QueryFilter.AttributeValueList":   {Mode: awsapi.OmitField},
	"ScanFilter.AttributeValueList":    {Mode: awsapi.OmitField},
	"SearchVector":                     {Mode: awsapi.OmitField},
	"Statement":                        {Mode: awsapi.OmitField},
	"Parameters":                       {Mode: awsapi.OmitField},
	"RequestItems":                     {Mode: awsapi.OmitField},
	"TransactItems":                    {Mode: awsapi.OmitField},
	"Statements":                       {Mode: awsapi.OmitField},
	"TransactStatements":               {Mode: awsapi.OmitField},
	"ReturnValues":                     {Name: "returnValue"},
}}

var auditBatchStatementRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Statement":      {Mode: awsapi.OmitField},
	"Parameters":     {Mode: awsapi.OmitField},
	"ConsistentRead": {Mode: awsapi.OmitField},
}}

func (a *auditCall) document(shape string, in any, projection *awsapi.DocumentProjection) (map[string]any, error) {
	body, err := awsapi.EncodeDocument(a.model, awscatalog.ShapeID("com.amazonaws.dynamodb#"+shape), in, projection)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if result == nil {
		result = make(map[string]any)
	}
	return result, nil
}

func (a *auditCall) key(selector string, key api.Key) (map[string]string, error) {
	public := make(map[string]string)
	table, err := a.table(selector)
	if err != nil {
		return nil, err
	}
	if table == nil {
		return public, nil
	}
	for _, member := range table.Data.KeySchema {
		name := value(member.AttributeName)
		if scalar, ok := dataCanonicalScalar(key[api.AttributeName(name)]); ok {
			public[name] = scalar
		}
	}
	return public, nil
}

func (a *auditCall) item(request map[string]any, selector string, key api.Key, item api.PutItemInputAttributeMap) error {
	a.resource(selector, "")
	if item != nil {
		attributes := make([]string, 0, len(item))
		for name := range item {
			attributes = append(attributes, string(name))
		}
		sort.Strings(attributes) // Native order is not stable between identical calls.
		request["items"] = attributes
		key = api.Key(item)
	}
	if key != nil {
		public, err := a.key(selector, key)
		if err != nil {
			return err
		}
		request["key"] = public
	}
	return nil
}

func (a *auditCall) statement(request map[string]any, text *api.PartiQLStatement) error {
	if text == nil {
		return nil
	}
	statement, err := partiql.Parse(string(*text))
	if err != nil {
		// Failed parsing gives no reliable literal boundaries. Logging original
		// SQL on this path would leak arbitrary rejected payloads.
		request["statement"] = "***(Redacted)"
		a.unparsedStatement = true
		return nil
	}
	a.resource(statement.Table(), statement.Index())
	table, err := a.table(statement.Table())
	if err != nil {
		return err
	}
	var keys []string
	if table != nil {
		keys = make([]string, 0, len(table.Data.KeySchema))
		for _, member := range table.Data.KeySchema {
			keys = append(keys, value(member.AttributeName))
		}
	}
	request["statement"] = statement.Redacted(keys)
	return nil
}

func (a *auditCall) transactionItem(shape string, in any, selector string, key api.Key, item api.PutItemInputAttributeMap) (map[string]any, error) {
	request, err := a.document(shape, in, &auditDataRequest)
	if err != nil {
		return nil, err
	}
	request["operation"] = shape
	if err := a.item(request, selector, key, item); err != nil {
		return nil, err
	}
	return request, nil
}

func (a *auditCall) dataRequest(request map[string]any, input any) error {
	switch in := input.(type) {
	case *api.PutItemInput:
		if in == nil {
			return nil
		}
		return a.item(request, value(in.TableName), nil, in.Item)
	case *api.GetItemInput:
		if in == nil {
			return nil
		}
		return a.item(request, value(in.TableName), in.Key, nil)
	case *api.UpdateItemInput:
		if in == nil {
			return nil
		}
		return a.item(request, value(in.TableName), in.Key, nil)
	case *api.DeleteItemInput:
		if in == nil {
			return nil
		}
		return a.item(request, value(in.TableName), in.Key, nil)
	case *api.QueryInput:
		if in == nil {
			return nil
		}
		table, err := a.table(value(in.TableName))
		if err != nil {
			return err
		}
		if table != nil {
			key := make(map[string]string)
			for _, member := range dataKeySchema(table, value(in.IndexName)) {
				name := value(member.AttributeName)
				values := dataQueryKeys(value(in.KeyConditionExpression), in.ExpressionAttributeNames, in.ExpressionAttributeValues, name)
				if legacy, ok := in.KeyConditions[api.AttributeName(name)]; ok && value(legacy.ComparisonOperator) == "EQ" && len(legacy.AttributeValueList) == 1 {
					values = []api.Key{{api.AttributeName(name): legacy.AttributeValueList[0]}}
				}
				for _, entry := range values {
					if scalar, ok := dataCanonicalScalar(entry[api.AttributeName(name)]); ok {
						key[name] = scalar
					}
				}
			}
			request["key"] = key
		}
		if in.ExclusiveStartKey != nil {
			key, err := a.key(value(in.TableName), in.ExclusiveStartKey)
			if err != nil {
				return err
			}
			request["exclusiveStartKey"] = key
		}
	case *api.ScanInput:
		if in == nil {
			return nil
		}
		if in.ConsistentRead == nil {
			request["consistentRead"] = false
		}
		if in.ExclusiveStartKey != nil {
			key, err := a.key(value(in.TableName), in.ExclusiveStartKey)
			if err != nil {
				return err
			}
			request["exclusiveStartKey"] = key
		}
	case *api.BatchGetItemInput:
		if in == nil || in.RequestItems == nil {
			return nil
		}
		selectors := make([]string, 0, len(in.RequestItems))
		for selector := range in.RequestItems {
			selectors = append(selectors, string(selector))
		}
		sort.Strings(selectors)
		items := make([]map[string]any, 0, len(selectors))
		for _, selector := range selectors {
			entry := in.RequestItems[api.TableArn(selector)]
			projected, err := a.document("KeysAndAttributes", &entry, &auditDataRequest)
			if err != nil {
				return err
			}
			projected["tableName"] = selector
			a.resource(selector, "")
			if entry.Keys != nil {
				keys := make([]map[string]string, 0, len(entry.Keys))
				for _, key := range entry.Keys {
					public, err := a.key(selector, key)
					if err != nil {
						return err
					}
					keys = append(keys, public)
				}
				projected["keys"] = keys
			}
			items = append(items, projected)
		}
		request["requestItems"] = items
	case *api.BatchWriteItemInput:
		if in == nil || in.RequestItems == nil {
			return nil
		}
		selectors := make([]string, 0, len(in.RequestItems))
		for selector := range in.RequestItems {
			selectors = append(selectors, string(selector))
		}
		sort.Strings(selectors)
		items := make([]map[string]any, 0)
		for _, selector := range selectors {
			a.resource(selector, "")
			for _, entry := range in.RequestItems[api.TableArn(selector)] {
				if entry.PutRequest != nil {
					projected := map[string]any{"tableName": selector, "operation": "Put"}
					if err := a.item(projected, selector, nil, entry.PutRequest.Item); err != nil {
						return err
					}
					items = append(items, projected)
				}
				if entry.DeleteRequest != nil {
					projected := map[string]any{"tableName": selector, "operation": "Delete"}
					if err := a.item(projected, selector, entry.DeleteRequest.Key, nil); err != nil {
						return err
					}
					items = append(items, projected)
				}
			}
		}
		request["requestItems"] = items
	case *api.TransactGetItemsInput:
		if in == nil || in.TransactItems == nil {
			return nil
		}
		items := make([]map[string]any, 0, len(in.TransactItems))
		for _, entry := range in.TransactItems {
			if entry.Get == nil {
				continue
			}
			projected, err := a.transactionItem("Get", entry.Get, value(entry.Get.TableName), entry.Get.Key, nil)
			if err != nil {
				return err
			}
			items = append(items, projected)
		}
		request["requestItems"] = items
	case *api.TransactWriteItemsInput:
		if in == nil || in.TransactItems == nil {
			return nil
		}
		items := make([]map[string]any, 0, len(in.TransactItems))
		for _, entry := range in.TransactItems {
			// Invalid multi-action entries are still audited without exposing any
			// of their values. Do not choose one action and silently lose others.
			if entry.ConditionCheck != nil {
				op := entry.ConditionCheck
				projected, err := a.transactionItem("ConditionCheck", op, value(op.TableName), op.Key, nil)
				if err != nil {
					return err
				}
				items = append(items, projected)
			}
			if entry.Put != nil {
				op := entry.Put
				projected, err := a.transactionItem("Put", op, value(op.TableName), nil, op.Item)
				if err != nil {
					return err
				}
				items = append(items, projected)
			}
			if entry.Update != nil {
				op := entry.Update
				projected, err := a.transactionItem("Update", op, value(op.TableName), op.Key, nil)
				if err != nil {
					return err
				}
				items = append(items, projected)
			}
			if entry.Delete != nil {
				op := entry.Delete
				projected, err := a.transactionItem("Delete", op, value(op.TableName), op.Key, nil)
				if err != nil {
					return err
				}
				items = append(items, projected)
			}
		}
		request["requestItems"] = items
	case *api.ExecuteStatementInput:
		if in == nil {
			return nil
		}
		return a.statement(request, in.Statement)
	case *api.BatchExecuteStatementInput:
		if in == nil {
			return nil
		}
		if in.ReturnConsumedCapacity == nil {
			request["returnConsumedCapacity"] = "NONE"
		}
		if in.Statements == nil {
			return nil
		}
		items := make([]map[string]any, 0, len(in.Statements))
		for _, entry := range in.Statements {
			projected, err := a.document("BatchStatementRequest", &entry, &auditBatchStatementRequest)
			if err != nil {
				return err
			}
			if err := a.statement(projected, entry.Statement); err != nil {
				return err
			}
			items = append(items, projected)
		}
		request["requestItems"] = items
	case *api.ExecuteTransactionInput:
		if in == nil || in.TransactStatements == nil {
			return nil
		}
		items := make([]map[string]any, 0, len(in.TransactStatements))
		for _, entry := range in.TransactStatements {
			projected, err := a.document("ParameterizedStatement", &entry, &auditBatchStatementRequest)
			if err != nil {
				return err
			}
			if err := a.statement(projected, entry.Statement); err != nil {
				return err
			}
			items = append(items, projected)
		}
		request["requestItems"] = items
	}
	return nil
}
