package lambda

import (
	"database/sql"
	"errors"
	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) EventInvokeConfig(k domain.FunctionReference) (domain.EventInvokeConfig, error) {
	v, err := r.q.GetEventInvokeConfig(r.ctx, sqlcgen.GetEventInvokeConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.EventInvokeConfig{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.EventInvokeConfig{}, err
	}
	return eventInvokeConfig(v), nil
}
func eventInvokeConfig(v sqlcgen.LambdaEventInvokeConfig) domain.EventInvokeConfig {
	k := domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Qualifier: v.Qualifier}
	return domain.EventInvokeConfig{Key: k, Modified: v.Modified, MaxAgeSeconds: int(v.MaxAgeSeconds), MaxRetries: int(v.MaxRetries), HasMaxAge: v.HasMaxAge, HasMaxRetries: v.HasMaxRetries, OnSuccessARN: v.OnSuccessArn, OnFailureARN: v.OnFailureArn, Effective: domain.EventInvokeSettings{MaxAgeSeconds: int(v.EffectiveMaxAgeSeconds), MaxRetries: int(v.EffectiveMaxRetries), OnSuccessARN: v.EffectiveOnSuccessArn, OnFailureARN: v.EffectiveOnFailureArn}, AppliesAt: v.AppliesAt, Version: uint64(v.Version), Deleted: v.Deleted}
}
func (r reader) EventInvokeConfigs(k domain.FunctionKey) ([]domain.EventInvokeConfig, error) {
	rows, err := r.q.ListEventInvokeConfigs(r.ctx, sqlcgen.ListEventInvokeConfigsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.EventInvokeConfig, 0, len(rows))
	for _, row := range rows {
		out = append(out, eventInvokeConfig(row))
	}
	return out, nil
}
func (r reader) NextEventInvokeConfigChange() (domain.InvocationJob, bool, error) {
	v, err := r.q.NextEventInvokeConfigChange(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.InvocationJob{}, false, nil
	}
	if err != nil {
		return domain.InvocationJob{}, false, err
	}
	key := domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Qualifier: v.Qualifier}
	return domain.InvocationJob{Key: key.ARN(), Version: uint64(v.Version), Due: *v.AppliesAt}, true, nil
}
func (w writer) PutEventInvokeConfig(v domain.EventInvokeConfig) error {
	k := v.Key
	return w.q.PutEventInvokeConfig(w.ctx, sqlcgen.PutEventInvokeConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier, Modified: v.Modified, MaxAgeSeconds: int64(v.MaxAgeSeconds), MaxRetries: int64(v.MaxRetries), HasMaxAge: v.HasMaxAge, HasMaxRetries: v.HasMaxRetries, OnSuccessArn: v.OnSuccessARN, OnFailureArn: v.OnFailureARN, EffectiveMaxAgeSeconds: int64(v.Effective.MaxAgeSeconds), EffectiveMaxRetries: int64(v.Effective.MaxRetries), EffectiveOnSuccessArn: v.Effective.OnSuccessARN, EffectiveOnFailureArn: v.Effective.OnFailureARN, AppliesAt: v.AppliesAt, Version: int64(v.Version), Deleted: v.Deleted})
}
func (w writer) DeleteEventInvokeConfig(k domain.FunctionReference) error {
	return w.q.DeleteEventInvokeConfig(w.ctx, sqlcgen.DeleteEventInvokeConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier})
}
func invocation(v sqlcgen.LambdaInvocation) domain.InvocationRecord {
	return domain.InvocationRecord{ID: v.ID, TraceHeader: v.TraceHeader, Key: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, FunctionARN: v.FunctionArn, Payload: v.Payload, RequestID: v.RequestID, ParentEventID: v.ParentEventID, Accepted: v.Accepted, Due: v.Due, Version: uint64(v.Version), State: v.State, InvokeCount: int(v.InvokeCount), SystemErrors: int(v.SystemErrors), ResponsePayload: v.ResponsePayload, ResponseError: v.ResponseError, ResponseStatus: int(v.ResponseStatus), ResponseVersion: v.ResponseVersion, Completed: v.Completed, Completion: v.Completion, RoleARN: v.RoleArn, Settings: domain.EventInvokeSettings{MaxAgeSeconds: int(v.MaxAgeSeconds), MaxRetries: int(v.MaxRetries), OnSuccessARN: v.OnSuccessArn, OnFailureARN: v.OnFailureArn}, SettingsDetached: v.SettingsDetached, DeadLetterARN: v.DeadLetterArn}
}
func (r reader) Invocation(id string) (domain.InvocationRecord, error) {
	v, err := r.q.GetInvocation(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.InvocationRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.InvocationRecord{}, err
	}
	return invocation(v), nil
}
func (r reader) NextInvocation() (domain.InvocationJob, bool, error) {
	v, err := r.q.NextInvocation(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.InvocationJob{}, false, nil
	}
	if err != nil {
		return domain.InvocationJob{}, false, err
	}
	return domain.InvocationJob{Key: v.ID, Version: uint64(v.Version), Due: v.Due}, true, nil
}
func (r reader) InFlightInvocations() ([]domain.InvocationRecord, error) {
	rows, err := r.q.ListInFlightInvocations(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.InvocationRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, invocation(v))
	}
	return out, nil
}
func (w writer) PutInvocation(v domain.InvocationRecord) error {
	k := v.Key
	return w.q.PutInvocation(w.ctx, sqlcgen.PutInvocationParams{ID: v.ID, TraceHeader: v.TraceHeader, Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, FunctionArn: v.FunctionARN, Payload: v.Payload, RequestID: v.RequestID, ParentEventID: v.ParentEventID, Accepted: v.Accepted, Due: v.Due, Version: int64(v.Version), State: v.State, InvokeCount: int64(v.InvokeCount), SystemErrors: int64(v.SystemErrors), ResponsePayload: v.ResponsePayload, ResponseError: v.ResponseError, ResponseStatus: int64(v.ResponseStatus), ResponseVersion: v.ResponseVersion, Completed: v.Completed, Completion: v.Completion, RoleArn: v.RoleARN, MaxAgeSeconds: int64(v.Settings.MaxAgeSeconds), MaxRetries: int64(v.Settings.MaxRetries), OnSuccessArn: v.Settings.OnSuccessARN, OnFailureArn: v.Settings.OnFailureARN, SettingsDetached: v.SettingsDetached, DeadLetterArn: v.DeadLetterARN})
}
func (w writer) DeleteInvocation(id string) error { return w.q.DeleteInvocation(w.ctx, id) }

func (w writer) ReattachInvocationSettings(k domain.FunctionReference) error {
	latest := k.ARN()
	if k.Qualifier == "" {
		latest += ":$LATEST"
	}
	return w.q.ReattachInvocationSettings(w.ctx, sqlcgen.ReattachInvocationSettingsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, FunctionArn: k.ARN(), LatestArn: latest})
}
