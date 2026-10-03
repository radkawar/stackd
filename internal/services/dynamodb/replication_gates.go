package dynamodb

import (
	"context"
	"slices"
)

func (s *Service) planTableGroup(ctx context.Context, key TableKey) ([]TableRecord, error) {
	var tables []TableRecord
	err := s.repository.View(ctx, func(r Reader) error {
		table, err := r.Table(key)
		if err != nil {
			return err
		}
		if table.Replica.GroupID == "" {
			tables = []TableRecord{table}
			return nil
		}
		tables, err = r.ReplicaTables(table.Replica.GroupID)
		return err
	})
	return tables, err
}

// Membership transitions quiesce all affected databases in a stable order.
// Ordinary replication holds only its destination gate; native I/O never holds
// a repository transaction while waiting for either kind of gate.
func (c *engineController) lockTableDatabases(ctx context.Context, tables []TableRecord) (func(), error) {
	ids := make([]string, 0, len(tables))
	for _, table := range tables {
		ids = append(ids, table.DatabaseID)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	releases := make([]func(), 0, len(ids))
	release := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for _, id := range ids {
		unlock, err := c.lockData(ctx, id)
		if err != nil {
			release()
			return nil, err
		}
		releases = append(releases, unlock)
	}
	return release, nil
}

func validateTableGroup(r Reader, table *TableRecord, planned []TableRecord) ([]TableRecord, error) {
	current := []TableRecord{*table}
	if table.Replica.GroupID != "" {
		var err error
		current, err = r.ReplicaTables(table.Replica.GroupID)
		if err != nil {
			return nil, err
		}
	}
	// A completed removal cannot introduce an unlocked native database. Return
	// current membership so deletion readiness does not count departed peers.
	// Additions or changed incarnations still require a new lock plan.
	for _, member := range current {
		if !slices.ContainsFunc(planned, func(expected TableRecord) bool {
			return member.Key == expected.Key && member.PhysicalName == expected.PhysicalName && member.DatabaseID == expected.DatabaseID && member.Replica.GroupID == expected.Replica.GroupID
		}) {
			return nil, failure("ResourceInUseException", "The table's replica membership changed while the request was waiting: "+table.Key.Name)
		}
	}
	return current, nil
}
