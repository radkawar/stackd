package athena

import (
	api "stackd/internal/awsapi/athena"
	domain "stackd/storage/athena"
	"stackd/storage/sqlite/athena/internal/sqlcgen"
)

func (r reader) NamedQuery(key domain.ResourceKey) (domain.NamedQueryRecord, error) {
	row, err := r.q.GetNamedQuery(r.ctx, sqlcgen.GetNamedQueryParams{KeyScopePartition: key.Scope.Partition, KeyScopeAccountID: key.Scope.AccountID, KeyScopeRegion: key.Scope.Region, KeyName: key.Name})
	if err != nil {
		return domain.NamedQueryRecord{}, missing(err)
	}
	return r.namedQuery(&row)
}

func (r reader) NamedQueries(query domain.ResourceQuery) ([]domain.NamedQueryRecord, error) {
	rows, err := r.q.ListNamedQuerys(r.ctx, sqlcgen.ListNamedQuerysParams{Partition: query.Scope.Partition, AccountID: query.Scope.AccountID, Region: query.Scope.Region, AfterName: query.After, RowLimit: rowLimit(query.Limit), WorkGroup: query.WorkGroup})
	if err != nil {
		return nil, err
	}
	out := make([]domain.NamedQueryRecord, 0, len(rows))
	for i := range rows {
		value, err := r.namedQuery(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (w writer) DeleteNamedQuery(key domain.ResourceKey) error {
	return w.q.DeleteNamedQuery(w.ctx, sqlcgen.DeleteNamedQueryParams{KeyScopePartition: key.Scope.Partition, KeyScopeAccountID: key.Scope.AccountID, KeyScopeRegion: key.Scope.Region, KeyName: key.Name})
}

func (r reader) NamedQueryByToken(scope domain.Scope, token string) (domain.NamedQueryRecord, error) {
	row, err := r.q.GetNamedQueryByToken(r.ctx, sqlcgen.GetNamedQueryByTokenParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Token: token})
	if err != nil {
		return domain.NamedQueryRecord{}, missing(err)
	}
	return r.namedQuery(&row)
}

func (r reader) namedQuery(row *sqlcgen.AthenaNamedQuery) (domain.NamedQueryRecord, error) {
	var out domain.NamedQueryRecord
	out.CFNOwner = row.CfnOwner
	out.Key.Scope.Partition = row.KeyScopePartition
	out.Key.Scope.AccountID = row.KeyScopeAccountID
	out.Key.Scope.Region = row.KeyScopeRegion
	out.Key.Name = row.KeyName
	out.Data.Database = stringPointer[api.DatabaseString](row.DataDatabase)
	out.Data.Description = stringPointer[api.DescriptionString](row.DataDescription)
	out.Data.Name = stringPointer[api.NameString](row.DataName)
	out.Data.NamedQueryId = stringPointer[api.NamedQueryId](row.DataNamedQueryID)
	out.Data.QueryString = stringPointer[api.QueryString](row.DataQueryString)
	out.Data.WorkGroup = stringPointer[api.WorkGroupName](row.DataWorkGroup)
	out.Token = row.Token
	out.Fingerprint = row.Fingerprint
	return out, nil
}

func (w writer) PutNamedQuery(v domain.NamedQueryRecord) error {
	var p sqlcgen.PutNamedQueryParams
	p.CfnOwner = v.CFNOwner
	p.KeyScopePartition = v.Key.Scope.Partition
	p.KeyScopeAccountID = v.Key.Scope.AccountID
	p.KeyScopeRegion = v.Key.Scope.Region
	p.KeyName = v.Key.Name
	p.DataDatabase = nullableString(v.Data.Database)
	p.DataDescription = nullableString(v.Data.Description)
	p.DataName = nullableString(v.Data.Name)
	p.DataNamedQueryID = nullableString(v.Data.NamedQueryId)
	p.DataQueryString = nullableString(v.Data.QueryString)
	p.DataWorkGroup = nullableString(v.Data.WorkGroup)
	p.Token = v.Token
	p.Fingerprint = v.Fingerprint
	return w.q.PutNamedQuery(w.ctx, p)
}
