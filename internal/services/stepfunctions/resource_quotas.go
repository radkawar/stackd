package stepfunctions

// Account/Region defaults are retained in api_throttling.json's native Service
// Quotas catalogue. These count retained resources, not API admission tokens.
const (
	maxRegisteredMachines   int64 = 100_000
	maxRegisteredActivities int64 = 100_000
	maxOpenExecutions       int64 = 1_000_000
)

// openExecutionCapacity is shared by public admission and Distributed Map
// dispatch. The caller's transaction owns both the count and new running state.
func openExecutionCapacity(r Reader, scope Scope) (int64, error) {
	count, err := r.OpenExecutionCount(scope)
	if err != nil {
		return 0, err
	}
	return maxOpenExecutions - count, nil
}

func requireOpenExecutionCapacity(r Reader, scope Scope) error {
	available, err := openExecutionCapacity(r, scope)
	if err != nil {
		return err
	}
	if available <= 0 {
		return failure("ExecutionLimitExceeded", "The maximum number of running executions has been reached.", 400)
	}
	return nil
}
