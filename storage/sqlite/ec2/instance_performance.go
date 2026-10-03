package ec2

import (
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) instancePerformanceGroups(record *domain.InstanceRecord) error {
	k := record.Key
	rows, err := r.q.ListInstancePerformanceGroups(r.ctx, sqlcgen.ListInstancePerformanceGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		record.Performance.Groups = make([]domain.InstancePerformanceGroup, 0, len(rows))
	}
	for _, row := range rows {
		record.Performance.Groups = append(record.Performance.Groups, domain.InstancePerformanceGroup{
			Name: row.GroupName,
			InstancePerformanceStatistics: domain.InstancePerformanceStatistics{
				CPUCount: row.CpuCount, CPUSum: row.CpuSum, CPUMin: row.CpuMin, CPUMax: row.CpuMax,
				NetworkIn: uint64(row.NetworkIn), NetworkOut: uint64(row.NetworkOut), NetworkObserved: row.NetworkObserved,
			},
		})
	}
	return nil
}

func (w writer) putInstancePerformanceGroups(record domain.InstanceRecord) error {
	k := record.Key
	if err := w.q.DeleteInstancePerformanceGroups(w.ctx, sqlcgen.DeleteInstancePerformanceGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for _, group := range record.Performance.Groups {
		if err := w.q.PutInstancePerformanceGroup(w.ctx, sqlcgen.PutInstancePerformanceGroupParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, GroupName: group.Name,
			CpuCount: group.CPUCount, CpuSum: group.CPUSum, CpuMin: group.CPUMin, CpuMax: group.CPUMax,
			NetworkIn: sqlite.Uint64(group.NetworkIn), NetworkOut: sqlite.Uint64(group.NetworkOut), NetworkObserved: group.NetworkObserved,
		}); err != nil {
			return err
		}
	}
	return nil
}
