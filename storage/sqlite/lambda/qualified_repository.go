package lambda

import (
	"database/sql"
	"errors"
	"math"
	"strconv"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) FunctionVersion(k domain.FunctionVersionKey) (domain.FunctionRecord, error) {
	if k.Version > math.MaxInt64 {
		return domain.FunctionRecord{}, domain.ErrNotFound
	}
	v, err := r.q.GetFunction(r.ctx, sqlcgen.GetFunctionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Version: int64(k.Version)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FunctionRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	return r.function(v)
}

func (r reader) FunctionVersions(k domain.FunctionKey) ([]domain.FunctionRecord, error) {
	rows, err := r.q.ListFunctionVersions(r.ctx, sqlcgen.ListFunctionVersionsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	return r.functions(rows)
}

func (r reader) LastAllocatedVersion(k domain.FunctionKey) (uint64, error) {
	v, err := r.q.LastAllocatedVersion(r.ctx, sqlcgen.LastAllocatedVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return uint64(v), err
}

func (w writer) AllocateFunctionVersion(k domain.FunctionKey) (uint64, error) {
	v, err := w.q.AllocateFunctionVersion(w.ctx, sqlcgen.AllocateFunctionVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("function version allocation exhausted")
	}
	return uint64(v), err
}

func (w writer) PutFunctionVersion(v domain.FunctionRecord) error {
	if v.Version == 0 || v.Version > math.MaxInt64 {
		return errors.New("invalid published Lambda version")
	}
	return w.putFunction(v, false)
}

func (w writer) SetPublishedDeploymentState(v domain.FunctionRecord) error {
	k := v.Key
	return w.q.SetPublishedDeploymentState(w.ctx, sqlcgen.SetPublishedDeploymentStateParams{State: v.State, StateReason: v.StateReason, StateReasonCode: v.StateReasonCode, UpdateStatus: v.UpdateStatus, UpdateReason: v.UpdateReason, Revision: v.Revision, Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, DeploymentRevision: v.DeploymentRevision})
}

func (w writer) DeleteFunctionVersion(k domain.FunctionVersionKey) error {
	if k.Version == 0 {
		return errors.New("cannot delete latest as a published version")
	}
	if k.Version > math.MaxInt64 {
		return nil
	}
	if err := w.q.DeleteFunctionVersion(w.ctx, sqlcgen.DeleteFunctionVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Version: int64(k.Version)}); err != nil {
		return err
	}
	return w.deleteQualifiedControls(domain.FunctionReference{FunctionKey: k.FunctionKey, Qualifier: strconv.FormatUint(k.Version, 10)})
}

func aliasRecord(v sqlcgen.LambdaAlias) domain.AliasRecord {
	return domain.AliasRecord{Key: domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Qualifier: v.Qualifier}, FunctionVersion: uint64(v.FunctionVersion), AdditionalVersion: uint64(v.AdditionalVersion), AdditionalWeight: v.AdditionalWeight, Description: v.Description, Revision: v.Revision, Owner: domain.AliasOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken}}
}

func (r reader) Alias(k domain.FunctionReference) (domain.AliasRecord, error) {
	v, err := r.q.GetAlias(r.ctx, sqlcgen.GetAliasParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AliasRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AliasRecord{}, err
	}
	return aliasRecord(v), nil
}

func (r reader) Aliases(k domain.FunctionKey) ([]domain.AliasRecord, error) {
	rows, err := r.q.ListAliases(r.ctx, sqlcgen.ListAliasesParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AliasRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, aliasRecord(v))
	}
	return out, nil
}

func (w writer) PutAlias(v domain.AliasRecord) error {
	k := v.Key
	return w.q.PutAlias(w.ctx, sqlcgen.PutAliasParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier, FunctionVersion: int64(v.FunctionVersion), AdditionalVersion: int64(v.AdditionalVersion), AdditionalWeight: v.AdditionalWeight, Description: v.Description, Revision: v.Revision, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token})
}

func (w writer) DeleteAlias(k domain.FunctionReference) error {
	if err := w.q.DeleteAlias(w.ctx, sqlcgen.DeleteAliasParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier}); err != nil {
		return err
	}
	return w.deleteQualifiedControls(k)
}

func (w writer) deleteQualifiedControls(k domain.FunctionReference) error {
	if err := w.DeleteFunctionPolicy(k); err != nil {
		return err
	}
	return w.DeleteEventInvokeConfig(k)
}
