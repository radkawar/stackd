package dynamodb

import (
	"time"

	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) OnDemandSwitches(k domain.TableKey) ([]time.Time, error) {
	return r.q.ListOnDemandSwitches(r.ctx, sqlcgen.ListOnDemandSwitchesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}

func (w writer) PutOnDemandSwitches(k domain.TableKey, times []time.Time) error {
	if err := w.q.DeleteOnDemandSwitches(w.ctx, sqlcgen.DeleteOnDemandSwitchesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for i, at := range times {
		if err := w.q.PutOnDemandSwitch(w.ctx, sqlcgen.PutOnDemandSwitchParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), SwitchedAt: at}); err != nil {
			return err
		}
	}
	return nil
}
