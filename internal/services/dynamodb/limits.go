package dynamodb

import (
	"context"
	"fmt"
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

const tableCapacityLimit = 40000

func (s *Service) describeLimits(ctx context.Context, _ Transaction, _ *api.DescribeLimitsInput) (*api.DescribeLimitsOutput, error) {
	if err := s.authorize(ctx, "DescribeLimits", "*", nil); err != nil {
		return nil, err
	}
	return &api.DescribeLimitsOutput{
		AccountMaxReadCapacityUnits: new(api.PositiveLongObject(80000)), AccountMaxWriteCapacityUnits: new(api.PositiveLongObject(80000)),
		TableMaxReadCapacityUnits: new(api.PositiveLongObject(tableCapacityLimit)), TableMaxWriteCapacityUnits: new(api.PositiveLongObject(tableCapacityLimit)),
	}, nil
}

type endpointHostKey struct{}

func registerEndpoints(s *Service) {
	registerExternal(s, "DescribeEndpoints", s.describeEndpoints)
}

func (s *Service) describeEndpoints(ctx context.Context, _ *api.DescribeEndpointsInput) (*api.DescribeEndpointsOutput, error) {
	if err := s.authorize(ctx, "DescribeEndpoints", "*", nil); err != nil {
		return nil, err
	}
	host, _ := ctx.Value(endpointHostKey{}).(string)
	if host == "" {
		return nil, unsupported("DynamoDB endpoint discovery requires an HTTP transport endpoint.")
	}
	return &api.DescribeEndpointsOutput{Endpoints: api.Endpoints{{Address: new(api.String(host)), CachePeriodInMinutes: new(api.Long(1440))}}}, nil
}

func validateAccountCapacity(r Reader, key TableKey, desired *api.CreateTableInput) error {
	tables, err := r.Tables(TableQuery{Scope: key.Scope})
	if err != nil {
		return err
	}
	var readUnits, writeUnits int64
	if desired.ProvisionedThroughput != nil {
		readUnits = int64(*desired.ProvisionedThroughput.ReadCapacityUnits)
		writeUnits = int64(*desired.ProvisionedThroughput.WriteCapacityUnits)
	}
	for _, index := range desired.GlobalSecondaryIndexes {
		if index.ProvisionedThroughput != nil {
			readUnits += int64(*index.ProvisionedThroughput.ReadCapacityUnits)
			writeUnits += int64(*index.ProvisionedThroughput.WriteCapacityUnits)
		}
	}
	for _, table := range tables {
		if table.Key == key {
			continue
		}
		reads, writes := reservedCapacity(table.Data.ProvisionedThroughput, nil)
		if table.PendingUpdate != nil {
			reads, writes = reservedCapacity(table.Data.ProvisionedThroughput, table.PendingUpdate.ProvisionedThroughput)
		}
		readUnits += reads
		writeUnits += writes
		for _, index := range table.Data.GlobalSecondaryIndexes {
			var pending *api.ProvisionedThroughput
			if table.PendingUpdate != nil {
				for _, update := range table.PendingUpdate.GlobalSecondaryIndexUpdates {
					if update.Update != nil && value(update.Update.IndexName) == value(index.IndexName) {
						pending = update.Update.ProvisionedThroughput
					}
				}
			}
			reads, writes = reservedCapacity(index.ProvisionedThroughput, pending)
			readUnits += reads
			writeUnits += writes
		}
	}
	if readUnits > 80000 || writeUnits > 80000 {
		return failure("LimitExceededException", "The provisioned throughput exceeds the account maximum of 80000 capacity units")
	}
	return nil
}

func reservedCapacity(current *api.ProvisionedThroughputDescription, pending *api.ProvisionedThroughput) (int64, int64) {
	var reads, writes int64
	if current != nil {
		if current.ReadCapacityUnits != nil {
			reads = int64(*current.ReadCapacityUnits)
		}
		if current.WriteCapacityUnits != nil {
			writes = int64(*current.WriteCapacityUnits)
		}
	}
	if pending != nil {
		if pending.ReadCapacityUnits != nil {
			reads = max(reads, int64(*pending.ReadCapacityUnits))
		}
		if pending.WriteCapacityUnits != nil {
			writes = max(writes, int64(*pending.WriteCapacityUnits))
		}
	}
	return reads, writes
}

// Validate every member before staging any change: one exhausted or unchanged
// resource rejects a combined table/index update without consuming sibling quota.
// The caller has already validated index existence and throughput shape.
func validateThroughputUpdates(table *api.TableDescription, in *api.UpdateTableInput, now time.Time) error {
	for _, change := range in.GlobalSecondaryIndexUpdates {
		if change.Update == nil {
			continue
		}
		index := tableIndex(table, value(change.Update.IndexName))
		if err := validateThroughputUpdate(index.ProvisionedThroughput, change.Update.ProvisionedThroughput, now); err != nil {
			return err
		}
	}
	return validateThroughputUpdate(table.ProvisionedThroughput, in.ProvisionedThroughput, now)
}

func validateThroughputUpdate(current *api.ProvisionedThroughputDescription, wanted *api.ProvisionedThroughput, now time.Time) error {
	if current == nil || wanted == nil {
		return nil
	}
	read, write := api.NonNegativeLongObject(*wanted.ReadCapacityUnits), api.NonNegativeLongObject(*wanted.WriteCapacityUnits)
	if read == *current.ReadCapacityUnits && write == *current.WriteCapacityUnits {
		return invalidTable("The provisioned throughput is already configured with these capacity units")
	}
	if read >= *current.ReadCapacityUnits && write >= *current.WriteCapacityUnits {
		return nil
	}
	count := decreasesToday(current, now)
	if count < 4 {
		return nil
	}
	next := current.LastDecreaseDateTime.Add(time.Hour)
	if now.Before(next) {
		return failure("LimitExceededException", fmt.Sprintf("After the first 4 provisioned throughput decreases in a UTC day, each subsequent decrease must be at least 3600 seconds apart. Number of decreases today: %d. Next decrease can be made at %s", count, next.UTC().Format(time.RFC3339)))
	}
	return nil
}
