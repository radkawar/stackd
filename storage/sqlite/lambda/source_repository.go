package lambda

import (
	"database/sql"
	"errors"
	"time"

	"stackd/internal/scheduler"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) functionS3Source(k domain.FunctionKey, pending bool, version uint64) (*domain.S3ObjectReference, time.Time, error) {
	v, err := r.q.GetFunctionS3Source(r.ctx, sqlcgen.GetFunctionS3SourceParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(version)})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	return &domain.S3ObjectReference{Bucket: v.ReferenceBucket, Key: v.ReferenceKey, VersionID: v.ReferenceVersionID}, v.CodeSourceCheckAt, nil
}

func (w writer) putFunctionS3Source(v domain.FunctionRecord, pending bool) error {
	k := v.Key
	if v.Reference == nil {
		return w.q.DeleteFunctionS3Source(w.ctx, sqlcgen.DeleteFunctionS3SourceParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version)})
	}
	return w.q.PutFunctionS3Source(w.ctx, sqlcgen.PutFunctionS3SourceParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version),
		ReferenceBucket: v.Reference.Bucket, ReferenceKey: v.Reference.Key, ReferenceVersionID: v.Reference.VersionID,
		CodeSourceCheckAt: v.CodeSourceCheckAt,
	})
}

func (r reader) NextCodeSourceCheck() (scheduler.Job, bool, error) {
	v, err := r.q.NextCodeSourceCheck(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	key := domain.FunctionVersionKey{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Version: uint64(v.Version)}
	return scheduler.Job{Key: key.ARN(), Version: key.Version, Due: v.CodeSourceCheckAt}, true, nil
}

func (w writer) SetCodeSourceState(v domain.FunctionRecord) error {
	k := v.Key
	if err := w.q.SetCodeSourceState(w.ctx, sqlcgen.SetCodeSourceStateParams{
		State: v.State, StateReason: v.StateReason, StateReasonCode: v.StateReasonCode, Revision: v.Revision,
		Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Version: int64(v.Version),
	}); err != nil {
		return err
	}
	return w.q.SetCodeSourceCheckAt(w.ctx, sqlcgen.SetCodeSourceCheckAtParams{
		CodeSourceCheckAt: v.CodeSourceCheckAt,
		Partition:         k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Version: int64(v.Version),
	})
}
