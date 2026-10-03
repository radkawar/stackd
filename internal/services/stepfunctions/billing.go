package stepfunctions

import (
	"time"

	api "stackd/internal/awsapi/stepfunctions"
)

// Native observability.json reports 64,000,000 Bytes, not 64 MiB. Source-owned
// PeakMemoryBytes follows the documented memory model; it is not a measurement
// of AWS's private allocator. Billing rounds that estimate in decimal 64-MB units.
func expressBilledMemoryBytes(execution ExecutionRecord) int64 {
	const increment = int64(64_000_000)
	return max((execution.PeakMemoryBytes+increment-1)/increment, 1) * increment
}

func expressBilledDurationMilliseconds(execution ExecutionRecord) int64 {
	if execution.Stopped == nil {
		return 0
	}
	const increment = 100 * time.Millisecond
	elapsed := execution.Stopped.Sub(execution.Started)
	return max(int64((elapsed+increment-1)/increment), 1) * 100
}

func expressBilling(execution ExecutionRecord) api.BillingDetails {
	return api.BillingDetails{
		BilledDurationInMilliseconds: new(api.BilledDuration(expressBilledDurationMilliseconds(execution))),
		BilledMemoryUsedInMB:         new(api.BilledMemoryUsed(expressBilledMemoryBytes(execution) / 1_000_000)),
	}
}
