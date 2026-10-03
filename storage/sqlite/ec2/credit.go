package ec2

import (
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) InstanceCreditDefault(scope domain.Scope, family string) (domain.InstanceCreditDefaultRecord, error) {
	row, err := r.q.GetInstanceCreditDefault(r.ctx, sqlcgen.GetInstanceCreditDefaultParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Family: family})
	if err != nil {
		return domain.InstanceCreditDefaultRecord{}, missing(err)
	}
	out := domain.InstanceCreditDefaultRecord{Scope: scope, Family: family, Mode: row.Mode}
	if row.ChangesPresent {
		out.Changes, err = r.q.ListInstanceCreditDefaultChanges(r.ctx, sqlcgen.ListInstanceCreditDefaultChangesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Family: family})
	}
	return out, err
}

func (w writer) PutInstanceCreditDefault(v domain.InstanceCreditDefaultRecord) error {
	s := v.Scope
	if err := w.q.PutInstanceCreditDefault(w.ctx, sqlcgen.PutInstanceCreditDefaultParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Family: v.Family, Mode: v.Mode, ChangesPresent: v.Changes != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteInstanceCreditDefaultChanges(w.ctx, sqlcgen.DeleteInstanceCreditDefaultChangesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Family: v.Family}); err != nil {
		return err
	}
	for i, at := range v.Changes {
		if err := w.q.PutInstanceCreditDefaultChange(w.ctx, sqlcgen.PutInstanceCreditDefaultChangeParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Family: v.Family, Position: int64(i), ChangedAt: at.UTC()}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) InstanceCreditLaunches(scope domain.Scope) (domain.InstanceCreditLaunchRecord, error) {
	row, err := r.q.GetInstanceCreditLaunches(r.ctx, sqlcgen.GetInstanceCreditLaunchesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return domain.InstanceCreditLaunchRecord{}, missing(err)
	}
	out := domain.InstanceCreditLaunchRecord{Scope: scope}
	if row.StartsPresent {
		out.Starts, err = r.q.ListInstanceCreditLaunchStarts(r.ctx, sqlcgen.ListInstanceCreditLaunchStartsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	}
	return out, err
}

func (w writer) PutInstanceCreditLaunches(v domain.InstanceCreditLaunchRecord) error {
	s := v.Scope
	if err := w.q.PutInstanceCreditLaunches(w.ctx, sqlcgen.PutInstanceCreditLaunchesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, StartsPresent: v.Starts != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteInstanceCreditLaunchStarts(w.ctx, sqlcgen.DeleteInstanceCreditLaunchStartsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region}); err != nil {
		return err
	}
	for i, at := range v.Starts {
		if err := w.q.PutInstanceCreditLaunchStart(w.ctx, sqlcgen.PutInstanceCreditLaunchStartParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Position: int64(i), StartedAt: at.UTC()}); err != nil {
			return err
		}
	}
	return nil
}
