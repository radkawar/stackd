package rds

import (
	engine "stackd/engine/rds"
	domain "stackd/storage/rds"
	"stackd/storage/sqlite/rds/internal/sqlcgen"
)

func (r reader) Database(k domain.Key) (domain.Database, error) {
	row, e := r.q.GetDatabase(r.ctx, sqlcgen.GetDatabaseParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.Database{}, missing(e)
	}
	return r.database(row)
}

func (r reader) Databases(scope domain.Scope) ([]domain.Database, error) {
	rows, e := r.q.ListDatabases(r.ctx, sqlcgen.ListDatabasesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Database, 0, len(rows))
	for _, row := range rows {

		v, e := r.database(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)

	}
	return out, nil
}

func (r reader) AllDatabases() ([]domain.Database, error) {
	rows, e := r.q.AllDatabases(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Database, 0, len(rows))
	for _, row := range rows {

		v, e := r.database(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)

	}
	return out, nil
}

func (r reader) database(row sqlcgen.RdsDatabase) (domain.Database, error) {
	v := domain.Database{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, Engine: row.Engine, EngineVersion: row.EngineVersion, DatabaseName: row.DatabaseName, Username: row.Username, Class: row.Class, ParameterGroup: row.ParameterGroup, Cluster: row.Cluster, RuntimeID: row.RuntimeID, Status: row.Status, Desired: row.Desired, Operation: row.Operation, RestoreSnapshot: row.RestoreSnapshot, Ciphertext: row.Ciphertext, PendingCiphertext: row.PendingCiphertext, RequestedPort: int32(row.RequestedPort), Version: row.Version, Created: readTime(row.Created), Due: readTime(row.Due), DeletionProtection: row.DeletionProtection != 0, HTTPEnabled: row.HttpEnabled != 0, CopyTags: row.CopyTags != 0, PendingParameters: row.PendingParameters != 0, Endpoint: engine.Endpoint{Address: row.Address, Port: int32(row.Port)}}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Parameters, _, e = r.parameters(v.Key)
	return v, e
}

func (w writer) PutDatabase(v domain.Database) error {
	k := v.Key
	if e := w.q.PutDatabase(w.ctx, sqlcgen.PutDatabaseParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Engine: v.Engine, EngineVersion: v.EngineVersion, DatabaseName: v.DatabaseName, Username: v.Username, Class: v.Class, ParameterGroup: v.ParameterGroup, Cluster: v.Cluster, RuntimeID: v.RuntimeID, Status: v.Status, Desired: v.Desired, Operation: v.Operation, RestoreSnapshot: v.RestoreSnapshot, Ciphertext: blob(v.Ciphertext), PendingCiphertext: blob(v.PendingCiphertext), RequestedPort: int64(v.RequestedPort), Version: v.Version, Created: timeValue(v.Created), Due: timeValue(v.Due), DeletionProtection: bit(v.DeletionProtection), HttpEnabled: bit(v.HTTPEnabled), CopyTags: bit(v.CopyTags), PendingParameters: bit(v.PendingParameters), Address: v.Endpoint.Address, Port: int64(v.Endpoint.Port)}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	return w.putParameters(k, v.Parameters, nil)
}

func (w writer) DeleteDatabase(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteDatabase(w.ctx, sqlcgen.DeleteDatabaseParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
