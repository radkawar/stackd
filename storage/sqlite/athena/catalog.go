package athena

import (
	api "stackd/internal/awsapi/athena"
	domain "stackd/storage/athena"
	"stackd/storage/sqlite/athena/internal/sqlcgen"
)

func (r reader) Catalog(key domain.ResourceKey) (domain.CatalogRecord, error) {
	row, err := r.q.GetCatalog(r.ctx, sqlcgen.GetCatalogParams{KeyScopePartition: key.Scope.Partition, KeyScopeAccountID: key.Scope.AccountID, KeyScopeRegion: key.Scope.Region, KeyName: key.Name})
	if err != nil {
		return domain.CatalogRecord{}, missing(err)
	}
	return r.catalog(&row)
}

func (r reader) Catalogs(query domain.ResourceQuery) ([]domain.CatalogRecord, error) {
	rows, err := r.q.ListCatalogs(r.ctx, sqlcgen.ListCatalogsParams{Partition: query.Scope.Partition, AccountID: query.Scope.AccountID, Region: query.Scope.Region, AfterName: query.After, RowLimit: rowLimit(query.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CatalogRecord, 0, len(rows))
	for i := range rows {
		value, err := r.catalog(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (w writer) DeleteCatalog(key domain.ResourceKey) error {
	return w.q.DeleteCatalog(w.ctx, sqlcgen.DeleteCatalogParams{KeyScopePartition: key.Scope.Partition, KeyScopeAccountID: key.Scope.AccountID, KeyScopeRegion: key.Scope.Region, KeyName: key.Name})
}

func (r reader) catalog(row *sqlcgen.AthenaCatalog) (domain.CatalogRecord, error) {
	var out domain.CatalogRecord
	out.Key.Scope.Partition = row.KeyScopePartition
	out.Key.Scope.AccountID = row.KeyScopeAccountID
	out.Key.Scope.Region = row.KeyScopeRegion
	out.Key.Name = row.KeyName
	out.Data.ConnectionType = stringPointer[api.ConnectionType](row.DataConnectionType)
	out.Data.Description = stringPointer[api.DescriptionString](row.DataDescription)
	out.Data.Error = stringPointer[api.ErrorMessage](row.DataError)
	out.Data.Name = stringPointer[api.CatalogNameString](row.DataName)
	if row.DataParametersPresent {
		values, err := r.catalogDataParameters(row.ID)
		if err != nil {
			return out, err
		}
		out.Data.Parameters = values
	}
	out.Data.Status = stringPointer[api.DataCatalogStatus](row.DataStatus)
	out.Data.Type = stringPointer[api.DataCatalogType](row.DataType)
	if row.TagsPresent {
		values, err := r.catalogTags(row.ID)
		if err != nil {
			return out, err
		}
		out.Tags = values
	}
	return out, nil
}

func (w writer) PutCatalog(v domain.CatalogRecord) error {
	var p sqlcgen.PutCatalogParams
	p.KeyScopePartition = v.Key.Scope.Partition
	p.KeyScopeAccountID = v.Key.Scope.AccountID
	p.KeyScopeRegion = v.Key.Scope.Region
	p.KeyName = v.Key.Name
	p.DataConnectionType = nullableString(v.Data.ConnectionType)
	p.DataDescription = nullableString(v.Data.Description)
	p.DataError = nullableString(v.Data.Error)
	p.DataName = nullableString(v.Data.Name)
	p.DataParametersPresent = v.Data.Parameters != nil
	p.DataStatus = nullableString(v.Data.Status)
	p.DataType = nullableString(v.Data.Type)
	p.TagsPresent = v.Tags != nil
	id, err := w.q.PutCatalog(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.q.DeleteCatalogDataParameters(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteCatalogTags(w.ctx, id); err != nil {
		return err
	}
	if err := w.putCatalogDataParameters(id, v.Data.Parameters); err != nil {
		return err
	}
	if err := w.putCatalogTags(id, v.Tags); err != nil {
		return err
	}
	return nil
}

func (r reader) catalogDataParameters(parentID int64) (api.ParametersMap, error) {
	rows, err := r.q.ListCatalogDataParameters(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.ParametersMap, len(rows))
	for i := range rows {
		row := &rows[i]
		value := api.ParametersMapValue(row.Value)
		out[api.KeyString(row.MapKey)] = value
	}
	return out, nil
}

func (w writer) putCatalogDataParameters(parentID int64, values api.ParametersMap) error {
	for key, value := range values {
		p := sqlcgen.PutCatalogDataParametersParams{ParentID: parentID}
		p.MapKey = string(key)
		p.Value = string(value)
		if err := w.q.PutCatalogDataParameters(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) catalogTags(parentID int64) (map[string]string, error) {
	rows, err := r.q.ListCatalogTags(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out[row.MapKey] = value
	}
	return out, nil
}

func (w writer) putCatalogTags(parentID int64, values map[string]string) error {
	for key, value := range values {
		p := sqlcgen.PutCatalogTagsParams{ParentID: parentID}
		p.MapKey = key
		p.Value = value
		if err := w.q.PutCatalogTags(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}
