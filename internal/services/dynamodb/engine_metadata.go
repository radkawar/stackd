package dynamodb

import (
	api "stackd/internal/awsapi/dynamodb"
	"time"
)

func warmCapacity(capacity *api.ProvisionedThroughputDescription, billing *api.BillingModeSummary, previousRead, previousWrite *api.PositiveLongObject) (api.PositiveLongObject, api.PositiveLongObject) {
	var read, write api.PositiveLongObject
	if billing != nil && value(billing.BillingMode) == "PAY_PER_REQUEST" {
		read, write = 12000, 4000
	} else if capacity != nil {
		if capacity.ReadCapacityUnits != nil {
			read = api.PositiveLongObject(*capacity.ReadCapacityUnits)
		}
		if capacity.WriteCapacityUnits != nil {
			write = api.PositiveLongObject(*capacity.WriteCapacityUnits)
		}
	}
	if previousRead != nil {
		read = max(read, *previousRead)
	}
	if previousWrite != nil {
		write = max(write, *previousWrite)
	}
	return read, write
}

// The retained timestamp dates the counter; reads do not need a midnight job
// or a second quota record to present the current UTC day's count.
func decreasesToday(capacity *api.ProvisionedThroughputDescription, now time.Time) api.PositiveLongObject {
	if capacity == nil || capacity.NumberOfDecreasesToday == nil || capacity.LastDecreaseDateTime == nil || capacity.LastDecreaseDateTime.Before(now.UTC().Truncate(24*time.Hour)) {
		return 0
	}
	return *capacity.NumberOfDecreasesToday
}

func refreshDecreaseCount(capacity *api.ProvisionedThroughputDescription, now time.Time) {
	if capacity != nil && capacity.NumberOfDecreasesToday != nil {
		*capacity.NumberOfDecreasesToday = decreasesToday(capacity, now)
	}
}

// Ordinary throughput updates expose old units until completion. A billing-mode
// transition exposes the target units immediately, but neither projection
// overwrites settled history or the capacities used by admission.
// A nil timestamp preserves GSI history during billing-mode transitions.
func stageThroughput(current *api.ProvisionedThroughputDescription, wanted *api.ProvisionedThroughput, at *time.Time, changingMode bool) {
	if current == nil || wanted == nil && !changingMode {
		return
	}
	var read, write api.NonNegativeLongObject
	if wanted != nil {
		read, write = api.NonNegativeLongObject(*wanted.ReadCapacityUnits), api.NonNegativeLongObject(*wanted.WriteCapacityUnits)
	}
	if at != nil {
		if read > *current.ReadCapacityUnits || write > *current.WriteCapacityUnits {
			current.LastIncreaseDateTime = at
		}
		if read < *current.ReadCapacityUnits || write < *current.WriteCapacityUnits {
			current.LastDecreaseDateTime = at
		}
	}
	if changingMode {
		current.ReadCapacityUnits, current.WriteCapacityUnits = &read, &write
	}
}

// Billing transitions preserve base-table history, but GSI history includes
// the reduction to zero on entering on-demand mode and the later increase.
func observeThroughput(current, previous *api.ProvisionedThroughputDescription, now time.Time, provisioned, trackChanges bool) *api.ProvisionedThroughputDescription {
	if !provisioned {
		current = throughputDescription(nil)
	}
	if current == nil || previous == nil {
		return current
	}
	current.NumberOfDecreasesToday = previous.NumberOfDecreasesToday
	current.LastIncreaseDateTime = previous.LastIncreaseDateTime
	current.LastDecreaseDateTime = previous.LastDecreaseDateTime
	if !trackChanges {
		return current
	}
	if *current.ReadCapacityUnits < *previous.ReadCapacityUnits || *current.WriteCapacityUnits < *previous.WriteCapacityUnits {
		current.NumberOfDecreasesToday = new(decreasesToday(previous, now) + 1)
		current.LastDecreaseDateTime = &now
	}
	if *current.ReadCapacityUnits > *previous.ReadCapacityUnits || *current.WriteCapacityUnits > *previous.WriteCapacityUnits {
		current.LastIncreaseDateTime = &now
	}
	return current
}

// Partial changes retain configured positive limits, not previously removed
// ones. An explicit -1 remains visible for the request that removes a limit.
func mergeOnDemand(previous, change *api.OnDemandThroughput) *api.OnDemandThroughput {
	if change == nil {
		return previous
	}
	next := api.OnDemandThroughput{}
	if previous != nil {
		if previous.MaxReadRequestUnits != nil && *previous.MaxReadRequestUnits > 0 {
			next.MaxReadRequestUnits = previous.MaxReadRequestUnits
		}
		if previous.MaxWriteRequestUnits != nil && *previous.MaxWriteRequestUnits > 0 {
			next.MaxWriteRequestUnits = previous.MaxWriteRequestUnits
		}
	}
	if change.MaxReadRequestUnits != nil {
		next.MaxReadRequestUnits = change.MaxReadRequestUnits
	}
	if change.MaxWriteRequestUnits != nil {
		next.MaxWriteRequestUnits = change.MaxWriteRequestUnits
	}
	if next.MaxReadRequestUnits == nil && next.MaxWriteRequestUnits == nil {
		return nil
	}
	return &next
}

func updateOnDemand(table *api.TableDescription, in *api.UpdateTableInput) {
	table.OnDemandThroughput = mergeOnDemand(table.OnDemandThroughput, in.OnDemandThroughput)
	for _, change := range in.GlobalSecondaryIndexUpdates {
		if change.Update == nil || change.Update.OnDemandThroughput == nil {
			continue
		}
		for i := range table.GlobalSecondaryIndexes {
			index := &table.GlobalSecondaryIndexes[i]
			if value(index.IndexName) == value(change.Update.IndexName) {
				index.OnDemandThroughput = mergeOnDemand(index.OnDemandThroughput, change.Update.OnDemandThroughput)
				break
			}
		}
	}
}
