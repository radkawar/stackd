package glue

import (
	"encoding/json"
	"time"

	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
)

func (r reader) Connection(key domain.ResourceKey) (domain.ConnectionRecord, error) {
	v, err := r.q.GetGlueConnection(r.ctx, sqlcgen.GetGlueConnectionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
	if err != nil {
		return domain.ConnectionRecord{}, crawlerMissing(err)
	}
	return decodeConnection(v)
}
func (r reader) Connections(scope domain.Scope) ([]domain.ConnectionRecord, error) {
	rows, err := r.q.ListGlueConnections(r.ctx, sqlcgen.ListGlueConnectionsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ConnectionRecord, 0, len(rows))
	for _, v := range rows {
		row, err := decodeConnection(v)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}
func decodeConnection(v sqlcgen.GlueConnection) (domain.ConnectionRecord, error) {
	row := domain.ConnectionRecord{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Password: v.Password, PasswordCipher: v.PasswordCipher, Connection: api.Connection{Name: new(api.NameString(v.Name)), ConnectionType: new(api.ConnectionType(v.ConnectionType)), Description: crawlerPointer[api.DescriptionString](v.Description), ConnectionSchemaVersion: new(api.ConnectionSchemaVersion(1)), CreationTime: new(time.Unix(0, v.CreatedAt).UTC()), LastUpdatedTime: new(time.Unix(0, v.UpdatedAt).UTC())}}
	if v.LastUpdatedBy != "" {
		row.Connection.LastUpdatedBy = new(api.NameString(v.LastUpdatedBy))
	}
	for _, field := range []struct {
		raw string
		dst any
	}{{v.Properties, &row.Connection.ConnectionProperties}, {v.MatchCriteria, &row.Connection.MatchCriteria}, {v.PhysicalRequirements, &row.Connection.PhysicalConnectionRequirements}, {v.AthenaProperties, &row.Connection.AthenaProperties}, {v.SparkProperties, &row.Connection.SparkProperties}, {v.PythonProperties, &row.Connection.PythonProperties}, {v.Tags, &row.Tags}} {
		if err := json.Unmarshal([]byte(field.raw), field.dst); err != nil {
			return domain.ConnectionRecord{}, err
		}
	}
	return row, nil
}
func (w writer) PutConnection(row domain.ConnectionRecord) error {
	c := row.Connection
	v := sqlcgen.PutGlueConnectionParams{Partition: row.Key.Partition, AccountID: row.Key.AccountID, Region: row.Key.Region, Name: row.Key.Name, ConnectionType: string(*c.ConnectionType), Description: crawlerString(c.Description), Password: row.Password, PasswordCipher: row.PasswordCipher, CreatedAt: c.CreationTime.UnixNano(), UpdatedAt: c.LastUpdatedTime.UnixNano()}
	if c.LastUpdatedBy != nil {
		v.LastUpdatedBy = string(*c.LastUpdatedBy)
	}
	if v.PasswordCipher == nil {
		v.PasswordCipher = []byte{}
	}
	for _, field := range []struct {
		src any
		dst *string
	}{{c.ConnectionProperties, &v.Properties}, {c.MatchCriteria, &v.MatchCriteria}, {c.PhysicalConnectionRequirements, &v.PhysicalRequirements}, {c.AthenaProperties, &v.AthenaProperties}, {c.SparkProperties, &v.SparkProperties}, {c.PythonProperties, &v.PythonProperties}, {row.Tags, &v.Tags}} {
		encoded, err := crawlerJSON(field.src)
		if err != nil {
			return err
		}
		*field.dst = encoded
	}
	return w.q.PutGlueConnection(w.ctx, v)
}
func (w writer) DeleteConnection(key domain.ResourceKey) error {
	return w.q.DeleteGlueConnection(w.ctx, sqlcgen.DeleteGlueConnectionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
}
func (r reader) ConnectionEncryption(scope domain.Scope) (domain.ConnectionEncryptionRecord, error) {
	v, err := r.q.GetGlueConnectionEncryption(r.ctx, sqlcgen.GetGlueConnectionEncryptionParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return domain.ConnectionEncryptionRecord{}, crawlerMissing(err)
	}
	return domain.ConnectionEncryptionRecord{Scope: scope, KeyID: v.KeyID, ReturnEncrypted: v.ReturnEncrypted != 0}, nil
}
func (w writer) PutConnectionEncryption(v domain.ConnectionEncryptionRecord) error {
	p := sqlcgen.PutGlueConnectionEncryptionParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, KeyID: v.KeyID}
	if v.ReturnEncrypted {
		p.ReturnEncrypted = 1
	}
	return w.q.PutGlueConnectionEncryption(w.ctx, p)
}
