package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) InstanceCreditModification(k domain.InstanceCreditModificationKey) (domain.InstanceCreditModificationRecord, error) {
	s := k.Scope
	row, err := r.q.GetInstanceCreditModification(r.ctx, sqlcgen.GetInstanceCreditModificationParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token})
	if err != nil {
		return domain.InstanceCreditModificationRecord{}, missing(err)
	}
	out := domain.InstanceCreditModificationRecord{Key: k}
	if row.SpecificationsPresent {
		rows, err := r.q.ListInstanceCreditModificationSpecs(r.ctx, sqlcgen.ListInstanceCreditModificationSpecsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token})
		if err != nil {
			return out, err
		}
		out.Specifications = make([]domain.InstanceCreditModification, len(rows))
		for i, v := range rows {
			out.Specifications[i] = domain.InstanceCreditModification{InstanceID: v.InstanceID, Mode: v.Mode}
		}
	}
	if row.SuccessfulPresent {
		rows, err := r.q.ListInstanceCreditModificationSuccesses(r.ctx, sqlcgen.ListInstanceCreditModificationSuccessesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token})
		if err != nil {
			return out, err
		}
		out.Result.SuccessfulInstanceCreditSpecifications = make(api.SuccessfulInstanceCreditSpecificationSet, len(rows))
		for i, v := range rows {
			out.Result.SuccessfulInstanceCreditSpecifications[i] = api.SuccessfulInstanceCreditSpecificationItem{InstanceId: stringPointer[api.String](v.InstanceID)}
		}
	}
	if row.UnsuccessfulPresent {
		rows, err := r.q.ListInstanceCreditModificationFailures(r.ctx, sqlcgen.ListInstanceCreditModificationFailuresParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token})
		if err != nil {
			return out, err
		}
		out.Result.UnsuccessfulInstanceCreditSpecifications = make(api.UnsuccessfulInstanceCreditSpecificationSet, len(rows))
		for i, v := range rows {
			item := &out.Result.UnsuccessfulInstanceCreditSpecifications[i]
			item.InstanceId = stringPointer[api.String](v.InstanceID)
			if v.ErrorPresent {
				item.Error = &api.UnsuccessfulInstanceCreditSpecificationItemError{Code: stringPointer[api.UnsuccessfulInstanceCreditSpecificationErrorCode](v.ErrorCode), Message: stringPointer[api.String](v.ErrorMessage)}
			}
		}
	}
	return out, nil
}

func (w writer) PutInstanceCreditModification(v domain.InstanceCreditModificationRecord) error {
	k, s := v.Key, v.Key.Scope
	if err := w.q.PutInstanceCreditModification(w.ctx, sqlcgen.PutInstanceCreditModificationParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token, SpecificationsPresent: v.Specifications != nil, SuccessfulPresent: v.Result.SuccessfulInstanceCreditSpecifications != nil, UnsuccessfulPresent: v.Result.UnsuccessfulInstanceCreditSpecifications != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteInstanceCreditModificationSpecs(w.ctx, sqlcgen.DeleteInstanceCreditModificationSpecsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token}); err != nil {
		return err
	}
	for i, spec := range v.Specifications {
		if err := w.q.PutInstanceCreditModificationSpec(w.ctx, sqlcgen.PutInstanceCreditModificationSpecParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token, Position: int64(i), InstanceID: spec.InstanceID, Mode: spec.Mode}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInstanceCreditModificationSuccesses(w.ctx, sqlcgen.DeleteInstanceCreditModificationSuccessesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token}); err != nil {
		return err
	}
	for i, item := range v.Result.SuccessfulInstanceCreditSpecifications {
		if err := w.q.PutInstanceCreditModificationSuccess(w.ctx, sqlcgen.PutInstanceCreditModificationSuccessParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token, Position: int64(i), InstanceID: nullableString(item.InstanceId)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInstanceCreditModificationFailures(w.ctx, sqlcgen.DeleteInstanceCreditModificationFailuresParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token}); err != nil {
		return err
	}
	for i, item := range v.Result.UnsuccessfulInstanceCreditSpecifications {
		p := sqlcgen.PutInstanceCreditModificationFailureParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: k.Token, Position: int64(i), InstanceID: nullableString(item.InstanceId), ErrorPresent: item.Error != nil}
		if item.Error != nil {
			p.ErrorCode, p.ErrorMessage = nullableString(item.Error.Code), nullableString(item.Error.Message)
		}
		if err := w.q.PutInstanceCreditModificationFailure(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}
