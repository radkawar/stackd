package lambda

import (
	"slices"
	"time"

	api "stackd/internal/awsapi/lambda"
)

// DurableExecutionRecord retains SDK checkpoints, not customer process state.
// A committed checkpoint skips its completed effect on replay; an interrupted
// effect without a checkpoint remains at-least-once.
type DurableExecutionRecord struct {
	ARN, Name, ID                           string
	Function                                FunctionVersionKey
	Status                                  string
	Input, Result                           *string
	Error                                   *api.ErrorObject
	StartedAt, EndedAt, Deadline, ExpiresAt time.Time
	ExecutionTimeout, RetentionDays         int32
	Token                                   string
	Generation                              uint64
	Claimed                                 bool
	NextRunAt                               time.Time
	InvocationType, TraceID, ClientContext  string
	KeyARN                                  string
	WrappedKey                              []byte
	Encrypted                               bool
	Operations                              []DurableOperationRecord
	History                                 []DurableEventRecord
	Checkpoints                             []DurableCheckpointRecord
}

// DurableOperationRecord separates typed orchestration fields from customer
// payload strings. SQL adapters persist these fields in service-owned columns.
type DurableOperationRecord struct {
	ID, ParentID, Name, Type, SubType, Status string
	StartedAt, EndedAt, DueAt                 time.Time
	Payload                                   *string
	Error                                     *api.ErrorObject
	Attempt                                   int32
	ReplayChildren                            bool
	CallbackID                                string
	CallbackTimeoutAt, HeartbeatAt            time.Time
	HeartbeatSeconds, TimeoutSeconds          int32
	TargetFunction, TargetTenant              string
	Generation                                uint64
}

type DurableEventRecord struct {
	ID        int32
	At        time.Time
	Type      string
	Operation DurableOperationRecord
}

// DurableCheckpointRecord implements the documented 15-minute ClientToken
// window. Input bytes are the canonical typed checkpoint request, not a second
// resource representation; digest chains and internal receipts are not used.
type DurableCheckpointRecord struct {
	ClientToken, PreviousToken, NextToken string
	Request                               []byte
	ExpiresAt                             time.Time
	Operations                            []DurableOperationRecord
}

type DurableReader interface {
	DurableExecution(string) (DurableExecutionRecord, error)
	DurableExecutions() ([]DurableExecutionRecord, error)
}

type DurableTransaction interface {
	PutDurableExecution(DurableExecutionRecord) error
	DeleteDurableExecution(string) error
}

func cloneDurableError(v *api.ErrorObject) *api.ErrorObject {
	if v == nil {
		return nil
	}
	out := *v
	out.ErrorData = cloneDurablePointer(v.ErrorData)
	out.ErrorMessage = cloneDurablePointer(v.ErrorMessage)
	out.ErrorType = cloneDurablePointer(v.ErrorType)
	out.StackTrace = slices.Clone(v.StackTrace)
	return &out
}

func cloneDurablePointer[T any](v *T) *T {
	if v == nil {
		return nil
	}
	return new(*v)
}

func cloneDurableConfig(v *api.DurableConfig) *api.DurableConfig {
	if v == nil {
		return nil
	}
	out := *v
	out.ExecutionTimeout = cloneDurablePointer(v.ExecutionTimeout)
	out.RetentionPeriodInDays = cloneDurablePointer(v.RetentionPeriodInDays)
	out.KMSKeyArn = cloneDurablePointer(v.KMSKeyArn)
	return &out
}

func cloneDurableOperation(v DurableOperationRecord) DurableOperationRecord {
	v.Payload = cloneDurablePointer(v.Payload)
	v.Error = cloneDurableError(v.Error)
	return v
}

func cloneDurableExecution(v DurableExecutionRecord) DurableExecutionRecord {
	v.WrappedKey = slices.Clone(v.WrappedKey)
	v.Input, v.Result = cloneDurablePointer(v.Input), cloneDurablePointer(v.Result)
	v.Error = cloneDurableError(v.Error)
	v.Operations = slices.Clone(v.Operations)
	for i := range v.Operations {
		v.Operations[i] = cloneDurableOperation(v.Operations[i])
	}
	v.History = slices.Clone(v.History)
	for i := range v.History {
		v.History[i].Operation = cloneDurableOperation(v.History[i].Operation)
	}
	v.Checkpoints = slices.Clone(v.Checkpoints)
	for i := range v.Checkpoints {
		v.Checkpoints[i].Request = slices.Clone(v.Checkpoints[i].Request)
		v.Checkpoints[i].Operations = slices.Clone(v.Checkpoints[i].Operations)
		for j := range v.Checkpoints[i].Operations {
			v.Checkpoints[i].Operations[j] = cloneDurableOperation(v.Checkpoints[i].Operations[j])
		}
	}
	return v
}
