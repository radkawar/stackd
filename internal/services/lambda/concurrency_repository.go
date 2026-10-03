package lambda

// AccountUsage aggregates committed functions and reservations in one scope.
// Pending replacements do not count as additional functions or reservations.
type AccountUsage struct {
	FunctionCount, TotalCodeSize, ReservedConcurrency int64
}

// ConcurrencyReader keeps an absent reservation distinct from a reservation of
// zero. Runtime occupancy belongs to the service, not retained repository state.
type ConcurrencyReader interface {
	FunctionConcurrency(FunctionKey) (reserved int32, present bool, err error)
	AccountUsage(Scope) (AccountUsage, error)
}

type ConcurrencyWriter interface {
	PutFunctionConcurrency(FunctionKey, int32) error
	DeleteFunctionConcurrency(FunctionKey) error
}
