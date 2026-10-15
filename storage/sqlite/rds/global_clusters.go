package rds

import (
	domain "stackd/storage/rds"
	"stackd/storage/sqlite/rds/internal/sqlcgen"
)

func globalResourceKey(k domain.GlobalKey) domain.Key {
	return domain.Key{Scope: domain.Scope{Partition: k.Partition, AccountID: k.AccountID}, Kind: "global-cluster", Name: k.Name}
}

func (r reader) GlobalCluster(k domain.GlobalKey) (domain.GlobalCluster, error) {
	row, err := r.q.GetGlobalCluster(r.ctx, sqlcgen.GetGlobalClusterParams{Partition: k.Partition, AccountID: k.AccountID, Name: k.Name})
	if err != nil {
		return domain.GlobalCluster{}, missing(err)
	}
	return r.globalCluster(row)
}

func (r reader) GlobalClusters(scope domain.GlobalScope) ([]domain.GlobalCluster, error) {
	rows, err := r.q.ListGlobalClusters(r.ctx, sqlcgen.ListGlobalClustersParams{Partition: scope.Partition, AccountID: scope.AccountID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.GlobalCluster, 0, len(rows))
	for _, row := range rows {
		v, err := r.globalCluster(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) globalCluster(row sqlcgen.RdsGlobalCluster) (domain.GlobalCluster, error) {
	v := domain.GlobalCluster{Key: domain.GlobalKey{GlobalScope: domain.GlobalScope{Partition: row.Partition, AccountID: row.AccountID}, Name: row.Name}, ResourceID: row.ResourceID, Engine: row.Engine, EngineVersion: row.EngineVersion, DatabaseName: row.DatabaseName, EngineLifecycleSupport: row.EngineLifecycleSupport, DeletionProtection: row.DeletionProtection != 0, StorageEncrypted: row.StorageEncrypted != 0}
	var err error
	v.Tags, err = r.tags(globalResourceKey(v.Key))
	return v, err
}

func (w writer) PutGlobalCluster(v domain.GlobalCluster) error {
	k := v.Key
	if err := w.q.PutGlobalCluster(w.ctx, sqlcgen.PutGlobalClusterParams{Partition: k.Partition, AccountID: k.AccountID, Name: k.Name, ResourceID: v.ResourceID, Engine: v.Engine, EngineVersion: v.EngineVersion, DatabaseName: v.DatabaseName, EngineLifecycleSupport: v.EngineLifecycleSupport, DeletionProtection: bit(v.DeletionProtection), StorageEncrypted: bit(v.StorageEncrypted)}); err != nil {
		return err
	}
	return w.putTags(globalResourceKey(k), v.Tags)
}

func (w writer) DeleteGlobalCluster(k domain.GlobalKey) error {
	key := globalResourceKey(k)
	if err := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Kind: key.Kind, Name: key.Name}); err != nil {
		return err
	}
	return w.q.DeleteGlobalCluster(w.ctx, sqlcgen.DeleteGlobalClusterParams{Partition: k.Partition, AccountID: k.AccountID, Name: k.Name})
}
