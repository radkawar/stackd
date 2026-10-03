package dynamodb

import (
	"encoding/json"
	"fmt"

	api "stackd/internal/awsapi/dynamodb"
)

// localReadCapacity corrects measured Local 3.3.1 response differences, not
// admission or CloudWatch accounting. Keep backend corrections here so another
// Database implementation is not charged for work it already accounts for.
func localReadCapacity(operation string, request, body []byte) ([]byte, error) {
	switch operation {
	case "BatchGetItem", "Query", "Scan", "TransactGetItems":
	default:
		return body, nil
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	encoded, ok := response["ConsumedCapacity"]
	if !ok {
		return body, nil
	}
	switch operation {
	case "BatchGetItem":
		var input struct {
			RequestItems map[api.TableArn]struct {
				Keys           []json.RawMessage
				ConsistentRead bool
			}
		}
		var output struct {
			Responses       map[api.TableArn][]json.RawMessage
			UnprocessedKeys map[api.TableArn]struct{ Keys []json.RawMessage }
		}
		var capacities api.ConsumedCapacityMultiple
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &output); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(encoded, &capacities); err != nil {
			return nil, err
		}
		changed := false
		for i := range capacities {
			capacity := &capacities[i]
			name := api.TableArn(*capacity.TableName)
			asked := input.RequestItems[name]
			missing := len(asked.Keys) - len(output.UnprocessedKeys[name].Keys) - len(output.Responses[name])
			if missing < 0 {
				return nil, fmt.Errorf("DynamoDB Local BatchGetItem returned more items than it processed for %s", name)
			}
			if missing == 0 {
				continue
			}
			units := api.ConsumedCapacityUnits(float64(missing) * 0.5)
			if asked.ConsistentRead {
				units *= 2
			}
			*capacity.CapacityUnits += units
			if capacity.Table != nil {
				*capacity.Table.CapacityUnits += units
			}
			changed = true
		}
		if !changed {
			return body, nil
		}
		var err error
		encoded, err = json.Marshal(capacities)
		if err != nil {
			return nil, err
		}
	case "Query", "Scan":
		var capacity api.ConsumedCapacity
		if err := json.Unmarshal(encoded, &capacity); err != nil {
			return nil, err
		}
		if capacity.CapacityUnits == nil || *capacity.CapacityUnits != 0 {
			return body, nil
		}
		var input struct {
			ConsistentRead bool
			IndexName      api.IndexName
		}
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, err
		}
		units := api.ConsumedCapacityUnits(0.5)
		if input.ConsistentRead {
			units = 1
		}
		capacity.CapacityUnits = &units
		if index, ok := capacity.GlobalSecondaryIndexes[input.IndexName]; ok {
			index.CapacityUnits = &units
			capacity.GlobalSecondaryIndexes[input.IndexName] = index
		} else if index, ok := capacity.LocalSecondaryIndexes[input.IndexName]; ok {
			index.CapacityUnits = &units
			capacity.LocalSecondaryIndexes[input.IndexName] = index
		} else if capacity.Table != nil {
			capacity.Table.CapacityUnits = &units
		}
		var err error
		encoded, err = json.Marshal(capacity)
		if err != nil {
			return nil, err
		}
	case "TransactGetItems":
		var capacities api.ConsumedCapacityMultiple
		if err := json.Unmarshal(encoded, &capacities); err != nil {
			return nil, err
		}
		for i := range capacities {
			capacity := &capacities[i]
			capacity.ReadCapacityUnits = capacity.CapacityUnits
			if capacity.Table != nil {
				capacity.Table.ReadCapacityUnits = capacity.Table.CapacityUnits
			}
		}
		var err error
		encoded, err = json.Marshal(capacities)
		if err != nil {
			return nil, err
		}
	}
	response["ConsumedCapacity"] = encoded
	return json.Marshal(response)
}
