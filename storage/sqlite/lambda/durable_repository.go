package lambda

import (
	"database/sql"
	"errors"
	"math"

	api "stackd/internal/awsapi/lambda"
	domain "stackd/storage/lambda"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

var _ domain.DurableReader = reader{}
var _ domain.DurableTransaction = writer{}

func durableSQLString[T ~string](v *T) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*v), Valid: true}
}

func durableString[T ~string](v sql.NullString) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.String))
}

func (r reader) functionDurableConfig(k domain.FunctionKey, pending bool, version uint64) (*api.DurableConfig, error) {
	v, err := r.q.GetFunctionDurableConfig(r.ctx, sqlcgen.GetFunctionDurableConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(version)})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &api.DurableConfig{KMSKeyArn: durableString[api.KMSKeyArn](v.KmsKeyArn)}
	if v.ExecutionTimeout.Valid {
		out.ExecutionTimeout = new(api.ExecutionTimeout(v.ExecutionTimeout.Int64))
	}
	if v.RetentionDays.Valid {
		out.RetentionPeriodInDays = new(api.RetentionPeriodInDays(v.RetentionDays.Int64))
	}
	return out, nil
}

func (w writer) putFunctionDurableConfig(v domain.FunctionRecord, pending bool) error {
	k := v.Key
	if v.Durable == nil {
		return w.q.DeleteFunctionDurableConfig(w.ctx, sqlcgen.DeleteFunctionDurableConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version)})
	}
	p := sqlcgen.PutFunctionDurableConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version), KmsKeyArn: durableSQLString(v.Durable.KMSKeyArn)}
	if v.Durable.ExecutionTimeout != nil {
		p.ExecutionTimeout = sql.NullInt64{Int64: int64(*v.Durable.ExecutionTimeout), Valid: true}
	}
	if v.Durable.RetentionPeriodInDays != nil {
		p.RetentionDays = sql.NullInt64{Int64: int64(*v.Durable.RetentionPeriodInDays), Valid: true}
	}
	return w.q.PutFunctionDurableConfig(w.ctx, p)
}

func (r reader) DurableExecution(arn string) (domain.DurableExecutionRecord, error) {
	v, err := r.q.GetDurableExecution(r.ctx, arn)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DurableExecutionRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.DurableExecutionRecord{}, err
	}
	return r.durableExecution(v)
}

func (r reader) DurableExecutions() ([]domain.DurableExecutionRecord, error) {
	rows, err := r.q.ListDurableExecutions(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DurableExecutionRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.durableExecution(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) durableExecution(v sqlcgen.LambdaDurableExecution) (domain.DurableExecutionRecord, error) {
	out := domain.DurableExecutionRecord{
		ARN: v.Arn, Name: v.Name, ID: v.ID,
		Function: domain.FunctionVersionKey{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Version: uint64(v.FunctionVersion)},
		KeyARN:   v.KeyArn, WrappedKey: v.WrappedKey, Encrypted: v.Encrypted,
		Status: v.Status, Input: durableString[string](v.Input), Result: durableString[string](v.Result),
		StartedAt: v.StartedAt, EndedAt: v.EndedAt, Deadline: v.Deadline, ExpiresAt: v.ExpiresAt,
		ExecutionTimeout: int32(v.ExecutionTimeout), RetentionDays: int32(v.RetentionDays),
		Token: v.Token, Generation: uint64(v.Generation), Claimed: v.Claimed, NextRunAt: v.NextRunAt,
		InvocationType: v.InvocationType, TraceID: v.TraceID, ClientContext: v.ClientContext,
	}
	var err error
	out.Error, err = r.durableError(v.Arn, "EXECUTION", 0, 0)
	if err != nil {
		return domain.DurableExecutionRecord{}, err
	}
	out.Operations, err = r.durableOperations(v.Arn, "CURRENT", 0)
	if err != nil {
		return domain.DurableExecutionRecord{}, err
	}
	history, err := r.q.ListDurableHistory(r.ctx, v.Arn)
	if err != nil {
		return domain.DurableExecutionRecord{}, err
	}
	if len(history) != 0 {
		out.History = make([]domain.DurableEventRecord, 0, len(history))
	}
	for _, h := range history {
		operations, err := r.durableOperations(v.Arn, "HISTORY", h.Position)
		if err != nil {
			return domain.DurableExecutionRecord{}, err
		}
		if len(operations) != 1 {
			return domain.DurableExecutionRecord{}, errors.New("invalid durable history operation snapshot")
		}
		out.History = append(out.History, domain.DurableEventRecord{ID: int32(h.ID), At: h.At, Type: h.Type, Operation: operations[0]})
	}
	checkpoints, err := r.q.ListDurableCheckpoints(r.ctx, v.Arn)
	if err != nil {
		return domain.DurableExecutionRecord{}, err
	}
	if len(checkpoints) != 0 {
		out.Checkpoints = make([]domain.DurableCheckpointRecord, 0, len(checkpoints))
	}
	for _, c := range checkpoints {
		operations, err := r.durableOperations(v.Arn, "CHECKPOINT", c.Position)
		if err != nil {
			return domain.DurableExecutionRecord{}, err
		}
		out.Checkpoints = append(out.Checkpoints, domain.DurableCheckpointRecord{ClientToken: c.ClientToken, PreviousToken: c.PreviousToken, NextToken: c.NextToken, Request: c.Request, ExpiresAt: c.ExpiresAt, Operations: operations})
	}
	return out, nil
}

func (r reader) durableOperations(arn, collection string, snapshot int64) ([]domain.DurableOperationRecord, error) {
	rows, err := r.q.ListDurableOperations(r.ctx, sqlcgen.ListDurableOperationsParams{ExecutionArn: arn, Collection: collection, SnapshotPosition: snapshot})
	if err != nil {
		return nil, err
	}
	var out []domain.DurableOperationRecord
	if len(rows) != 0 {
		out = make([]domain.DurableOperationRecord, 0, len(rows))
	}
	for _, v := range rows {
		failure, err := r.durableError(arn, collection, snapshot, v.Position)
		if err != nil {
			return nil, err
		}
		out = append(out, domain.DurableOperationRecord{
			ID: v.ID, ParentID: v.ParentID, Name: v.Name, Type: v.Type, SubType: v.SubType, Status: v.Status,
			StartedAt: v.StartedAt, EndedAt: v.EndedAt, DueAt: v.DueAt, Payload: durableString[string](v.Payload), Error: failure,
			Attempt: int32(v.Attempt), ReplayChildren: v.ReplayChildren, CallbackID: v.CallbackID,
			CallbackTimeoutAt: v.CallbackTimeoutAt, HeartbeatAt: v.HeartbeatAt,
			HeartbeatSeconds: int32(v.HeartbeatSeconds), TimeoutSeconds: int32(v.TimeoutSeconds),
			TargetFunction: v.TargetFunction, TargetTenant: v.TargetTenant, Generation: uint64(v.Generation),
		})
	}
	return out, nil
}

func (r reader) durableError(arn, collection string, snapshot, position int64) (*api.ErrorObject, error) {
	v, err := r.q.GetDurableError(r.ctx, sqlcgen.GetDurableErrorParams{ExecutionArn: arn, Collection: collection, SnapshotPosition: snapshot, Position: position})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &api.ErrorObject{ErrorData: durableString[api.ErrorData](v.ErrorData), ErrorMessage: durableString[api.ErrorMessage](v.ErrorMessage), ErrorType: durableString[api.ErrorType](v.ErrorType)}
	if v.HasStackTrace {
		frames, err := r.q.ListDurableErrorFrames(r.ctx, sqlcgen.ListDurableErrorFramesParams{ExecutionArn: arn, Collection: collection, SnapshotPosition: snapshot, OperationPosition: position})
		if err != nil {
			return nil, err
		}
		out.StackTrace = make(api.StackTraceEntries, len(frames))
		for i, frame := range frames {
			out.StackTrace[i] = api.StackTraceEntry(frame)
		}
	}
	return out, nil
}

func (w writer) PutDurableExecution(v domain.DurableExecutionRecord) error {
	if v.Function.Version > math.MaxInt64 {
		return errors.New("invalid durable function version")
	}
	k := v.Function
	changed, err := w.q.PutDurableExecution(w.ctx, sqlcgen.PutDurableExecutionParams{
		Arn: v.ARN, Name: v.Name, ID: v.ID, Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, FunctionVersion: int64(k.Version),
		KeyArn: v.KeyARN, WrappedKey: v.WrappedKey, Encrypted: v.Encrypted,
		Status: v.Status, Input: durableSQLString(v.Input), Result: durableSQLString(v.Result),
		StartedAt: v.StartedAt.UTC(), EndedAt: v.EndedAt.UTC(), Deadline: v.Deadline.UTC(), ExpiresAt: v.ExpiresAt.UTC(),
		ExecutionTimeout: int64(v.ExecutionTimeout), RetentionDays: int64(v.RetentionDays),
		Token: v.Token, Generation: sqlite.Uint64(v.Generation), Claimed: v.Claimed, NextRunAt: v.NextRunAt.UTC(),
		InvocationType: v.InvocationType, TraceID: v.TraceID, ClientContext: v.ClientContext,
	})
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("durable execution identity is immutable")
	}
	if err := w.q.DeleteDurableErrors(w.ctx, v.ARN); err != nil {
		return err
	}
	if err := w.q.DeleteDurableOperations(w.ctx, v.ARN); err != nil {
		return err
	}
	if err := w.q.DeleteDurableHistory(w.ctx, v.ARN); err != nil {
		return err
	}
	if err := w.q.DeleteDurableCheckpoints(w.ctx, v.ARN); err != nil {
		return err
	}
	if err := w.putDurableError(v.ARN, "EXECUTION", 0, 0, v.Error); err != nil {
		return err
	}
	for i, op := range v.Operations {
		if err := w.putDurableOperation(v.ARN, "CURRENT", 0, int64(i), op); err != nil {
			return err
		}
	}
	for i, h := range v.History {
		if err := w.q.PutDurableHistory(w.ctx, sqlcgen.PutDurableHistoryParams{ExecutionArn: v.ARN, Position: int64(i), ID: int64(h.ID), At: h.At.UTC(), Type: h.Type}); err != nil {
			return err
		}
		if err := w.putDurableOperation(v.ARN, "HISTORY", int64(i), 0, h.Operation); err != nil {
			return err
		}
	}
	for i, c := range v.Checkpoints {
		if err := w.q.PutDurableCheckpoint(w.ctx, sqlcgen.PutDurableCheckpointParams{ExecutionArn: v.ARN, Position: int64(i), ClientToken: c.ClientToken, PreviousToken: c.PreviousToken, NextToken: c.NextToken, Request: c.Request, ExpiresAt: c.ExpiresAt.UTC()}); err != nil {
			return err
		}
		for j, op := range c.Operations {
			if err := w.putDurableOperation(v.ARN, "CHECKPOINT", int64(i), int64(j), op); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) putDurableOperation(arn, collection string, snapshot, position int64, v domain.DurableOperationRecord) error {
	if err := w.q.PutDurableOperation(w.ctx, sqlcgen.PutDurableOperationParams{
		ExecutionArn: arn, Collection: collection, SnapshotPosition: snapshot, Position: position,
		ID: v.ID, ParentID: v.ParentID, Name: v.Name, Type: v.Type, SubType: v.SubType, Status: v.Status,
		StartedAt: v.StartedAt.UTC(), EndedAt: v.EndedAt.UTC(), DueAt: v.DueAt.UTC(), Payload: durableSQLString(v.Payload),
		Attempt: int64(v.Attempt), ReplayChildren: v.ReplayChildren, CallbackID: v.CallbackID,
		CallbackTimeoutAt: v.CallbackTimeoutAt.UTC(), HeartbeatAt: v.HeartbeatAt.UTC(), HeartbeatSeconds: int64(v.HeartbeatSeconds), TimeoutSeconds: int64(v.TimeoutSeconds),
		TargetFunction: v.TargetFunction, TargetTenant: v.TargetTenant, Generation: sqlite.Uint64(v.Generation),
	}); err != nil {
		return err
	}
	return w.putDurableError(arn, collection, snapshot, position, v.Error)
}

func (w writer) putDurableError(arn, collection string, snapshot, position int64, v *api.ErrorObject) error {
	if v == nil {
		return nil
	}
	if err := w.q.PutDurableError(w.ctx, sqlcgen.PutDurableErrorParams{
		ExecutionArn: arn, Collection: collection, SnapshotPosition: snapshot, Position: position,
		ErrorData: durableSQLString(v.ErrorData), ErrorMessage: durableSQLString(v.ErrorMessage), ErrorType: durableSQLString(v.ErrorType), HasStackTrace: v.StackTrace != nil,
	}); err != nil {
		return err
	}
	for i, frame := range v.StackTrace {
		if err := w.q.PutDurableErrorFrame(w.ctx, sqlcgen.PutDurableErrorFrameParams{ExecutionArn: arn, Collection: collection, SnapshotPosition: snapshot, OperationPosition: position, Position: int64(i), Frame: string(frame)}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteDurableExecution(arn string) error {
	return w.q.DeleteDurableExecution(w.ctx, arn)
}
