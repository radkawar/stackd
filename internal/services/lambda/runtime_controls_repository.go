package lambda

import "time"

// ProvisionedConcurrencyRecord retains desired capacity, never a claim that an
// external runtime survived controller replacement. Live counts come from slots.
type ProvisionedConcurrencyRecord struct {
	Key                  FunctionReference
	Requested            int32
	Generation           string
	Status, StatusReason string
	Modified             time.Time
}

type RuntimeControlReader interface {
	RecursiveLoop(FunctionKey) (string, error)
	RuntimeManagement(FunctionVersionKey) (string, error)
	ProvisionedConcurrency(FunctionReference) (ProvisionedConcurrencyRecord, error)
	AllProvisionedConcurrency() ([]ProvisionedConcurrencyRecord, error)
}

type RuntimeControlWriter interface {
	PutRecursiveLoop(FunctionKey, string) error
	PutRuntimeManagement(FunctionVersionKey, string) error
	DeleteRuntimeManagement(FunctionVersionKey) error
	PutProvisionedConcurrency(ProvisionedConcurrencyRecord) error
	DeleteProvisionedConcurrency(FunctionReference) error
}
