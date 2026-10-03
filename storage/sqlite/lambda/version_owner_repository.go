package lambda

import (
	"database/sql"
	"errors"
	"math"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) OwnedFunctionVersion(k domain.FunctionKey, owner domain.VersionOwner) (domain.FunctionRecord, error) {
	version, err := r.q.GetOwnedFunctionVersion(r.ctx, sqlcgen.GetOwnedFunctionVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, OwnerStackID: owner.StackID, OwnerLogicalID: owner.LogicalID, OwnerToken: owner.Token})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FunctionRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	return r.FunctionVersion(domain.FunctionVersionKey{FunctionKey: k, Version: uint64(version)})
}

func (r reader) FunctionVersionOwner(k domain.FunctionVersionKey) (domain.VersionOwner, error) {
	if k.Version == 0 || k.Version >= math.MaxInt64 {
		return domain.VersionOwner{}, domain.ErrNotFound
	}
	row, err := r.q.GetFunctionVersionOwner(r.ctx, sqlcgen.GetFunctionVersionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Version: int64(k.Version)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.VersionOwner{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.VersionOwner{}, err
	}
	return domain.VersionOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}, nil
}

func (w writer) PutFunctionVersionOwner(k domain.FunctionVersionKey, owner domain.VersionOwner) error {
	if k.Version == 0 || k.Version >= math.MaxInt64 || owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return errors.New("invalid Lambda version ownership receipt")
	}
	version, err := w.q.GetOwnedFunctionVersion(w.ctx, sqlcgen.GetOwnedFunctionVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, OwnerStackID: owner.StackID, OwnerLogicalID: owner.LogicalID, OwnerToken: owner.Token})
	if err == nil {
		if uint64(version) != k.Version {
			return errors.New("lambda version owner already has a publication")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := w.FunctionVersion(k); err != nil {
		return err
	}
	return w.q.PutFunctionVersionOwner(w.ctx, sqlcgen.PutFunctionVersionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Version: int64(k.Version), OwnerStackID: owner.StackID, OwnerLogicalID: owner.LogicalID, OwnerToken: owner.Token})
}
