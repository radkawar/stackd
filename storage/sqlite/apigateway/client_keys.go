package apigateway

import (
	"database/sql"

	domain "stackd/internal/services/apigateway"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func stringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return new(value.String)
}

func stringColumn(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

func (r reader) clientKey(row sqlcgen.ApigatewayClientKey) (domain.ClientKeyRecord, error) {
	key := domain.ClientKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ClientKeyID}
	out := domain.ClientKeyRecord{Key: key, Name: stringPointer(row.Name), Description: stringPointer(row.Description), CustomerID: stringPointer(row.CustomerID), Value: row.Value, Enabled: row.Enabled, Created: row.Created, Updated: row.Updated}
	out.Ownership = domain.Ownership{StackID: row.CfnStackID, LogicalID: row.CfnLogicalID, Incarnation: row.CfnIncarnation}
	tags, err := r.q.ListClientKeyTags(r.ctx, sqlcgen.ListClientKeyTagsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID})
	if err != nil {
		return domain.ClientKeyRecord{}, err
	}
	if len(tags) != 0 {
		out.Tags = make(map[string]string, len(tags))
		for _, tag := range tags {
			out.Tags[tag.Key] = tag.Value
		}
	}
	stages, err := r.q.ListClientKeyStages(r.ctx, sqlcgen.ListClientKeyStagesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID})
	if err != nil {
		return domain.ClientKeyRecord{}, err
	}
	out.StageKeys = make([]domain.StageKey, len(stages))
	for i, stage := range stages {
		out.StageKeys[i] = domain.StageKey{APIKey: domain.APIKey{Scope: key.Scope, ID: stage.ApiID}, Name: stage.StageName}
	}
	return out, nil
}

func (r reader) ClientKey(key domain.ClientKey) (domain.ClientKeyRecord, error) {
	row, err := r.q.GetClientKey(r.ctx, sqlcgen.GetClientKeyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID})
	if err != nil {
		return domain.ClientKeyRecord{}, missing(err)
	}
	return r.clientKey(row)
}

func (r reader) ClientKeyByValue(scope domain.Scope, value string) (domain.ClientKeyRecord, error) {
	row, err := r.q.GetClientKeyByValue(r.ctx, sqlcgen.GetClientKeyByValueParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Value: value})
	if err != nil {
		return domain.ClientKeyRecord{}, missing(err)
	}
	return r.clientKey(row)
}

func (r reader) ClientKeys(scope domain.Scope) ([]domain.ClientKeyRecord, error) {
	rows, err := r.q.ListClientKeys(r.ctx, sqlcgen.ListClientKeysParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ClientKeyRecord, 0, len(rows))
	for _, row := range rows {
		key, err := r.clientKey(row)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

func (w writer) PutClientKey(row domain.ClientKeyRecord) error {
	key := row.Key
	if err := w.q.PutClientKey(w.ctx, sqlcgen.PutClientKeyParams{CfnStackID: row.Ownership.StackID, CfnLogicalID: row.Ownership.LogicalID, CfnIncarnation: row.Ownership.Incarnation, Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID, Name: stringColumn(row.Name), Description: stringColumn(row.Description), CustomerID: stringColumn(row.CustomerID), Value: row.Value, Enabled: row.Enabled, Created: row.Created, Updated: row.Updated}); err != nil {
		return err
	}
	if err := w.q.DeleteClientKeyTags(w.ctx, sqlcgen.DeleteClientKeyTagsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID}); err != nil {
		return err
	}
	for name, value := range row.Tags {
		if err := w.q.PutClientKeyTag(w.ctx, sqlcgen.PutClientKeyTagParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID, Key: name, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteClientKeyStages(w.ctx, sqlcgen.DeleteClientKeyStagesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID}); err != nil {
		return err
	}
	for i, stage := range row.StageKeys {
		if err := w.q.PutClientKeyStage(w.ctx, sqlcgen.PutClientKeyStageParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID, Ordinal: int64(i), ApiID: stage.ID, StageName: stage.Name}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteClientKey(key domain.ClientKey) error {
	return w.q.DeleteClientKey(w.ctx, sqlcgen.DeleteClientKeyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID})
}
