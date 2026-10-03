package athena

import (
	api "stackd/internal/awsapi/athena"
	domain "stackd/storage/athena"
	"stackd/storage/sqlite/athena/internal/sqlcgen"
)

func (r reader) PreparedStatement(key domain.StatementKey) (domain.PreparedStatementRecord, error) {
	row, err := r.q.GetPreparedStatement(r.ctx, sqlcgen.GetPreparedStatementParams{KeyWorkGroupScopePartition: key.WorkGroup.Scope.Partition, KeyWorkGroupScopeAccountID: key.WorkGroup.Scope.AccountID, KeyWorkGroupScopeRegion: key.WorkGroup.Scope.Region, KeyWorkGroupName: key.WorkGroup.Name, KeyName: key.Name})
	if err != nil {
		return domain.PreparedStatementRecord{}, missing(err)
	}
	return r.preparedStatement(&row)
}

func (r reader) PreparedStatements(query domain.ResourceQuery) ([]domain.PreparedStatementRecord, error) {
	rows, err := r.q.ListPreparedStatements(r.ctx, sqlcgen.ListPreparedStatementsParams{Partition: query.Scope.Partition, AccountID: query.Scope.AccountID, Region: query.Scope.Region, AfterName: query.After, RowLimit: rowLimit(query.Limit), WorkGroup: query.WorkGroup})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PreparedStatementRecord, 0, len(rows))
	for i := range rows {
		value, err := r.preparedStatement(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (w writer) DeletePreparedStatement(key domain.StatementKey) error {
	return w.q.DeletePreparedStatement(w.ctx, sqlcgen.DeletePreparedStatementParams{KeyWorkGroupScopePartition: key.WorkGroup.Scope.Partition, KeyWorkGroupScopeAccountID: key.WorkGroup.Scope.AccountID, KeyWorkGroupScopeRegion: key.WorkGroup.Scope.Region, KeyWorkGroupName: key.WorkGroup.Name, KeyName: key.Name})
}

func (r reader) preparedStatement(row *sqlcgen.AthenaPreparedStatement) (domain.PreparedStatementRecord, error) {
	var out domain.PreparedStatementRecord
	out.Key.WorkGroup.Scope.Partition = row.KeyWorkGroupScopePartition
	out.Key.WorkGroup.Scope.AccountID = row.KeyWorkGroupScopeAccountID
	out.Key.WorkGroup.Scope.Region = row.KeyWorkGroupScopeRegion
	out.Key.WorkGroup.Name = row.KeyWorkGroupName
	out.Key.Name = row.KeyName
	out.Data.Description = stringPointer[api.DescriptionString](row.DataDescription)
	out.Data.LastModifiedTime = timePointer(row.DataLastModifiedTime)
	out.Data.QueryStatement = stringPointer[api.QueryString](row.DataQueryStatement)
	out.Data.StatementName = stringPointer[api.StatementName](row.DataStatementName)
	out.Data.WorkGroupName = stringPointer[api.WorkGroupName](row.DataWorkGroupName)
	return out, nil
}

func (w writer) PutPreparedStatement(v domain.PreparedStatementRecord) error {
	var p sqlcgen.PutPreparedStatementParams
	p.KeyWorkGroupScopePartition = v.Key.WorkGroup.Scope.Partition
	p.KeyWorkGroupScopeAccountID = v.Key.WorkGroup.Scope.AccountID
	p.KeyWorkGroupScopeRegion = v.Key.WorkGroup.Scope.Region
	p.KeyWorkGroupName = v.Key.WorkGroup.Name
	p.KeyName = v.Key.Name
	p.DataDescription = nullableString(v.Data.Description)
	p.DataLastModifiedTime = nullableTime(v.Data.LastModifiedTime)
	p.DataQueryStatement = nullableString(v.Data.QueryStatement)
	p.DataStatementName = nullableString(v.Data.StatementName)
	p.DataWorkGroupName = nullableString(v.Data.WorkGroupName)
	return w.q.PutPreparedStatement(w.ctx, p)
}
