package dynamodb

import (
	"encoding/json"

	api "stackd/internal/awsapi/dynamodb"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) TTLDeletion(databaseID string) (domain.TTLDeletion, error) {
	row, err := r.q.GetTTLDeletion(r.ctx, databaseID)
	if err != nil {
		return domain.TTLDeletion{}, missing(err)
	}
	v := domain.TTLDeletion{Table: domain.TableKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.TableName}, DatabaseID: row.DatabaseID, PhysicalName: row.PhysicalName, StreamARN: row.StreamArn, NativeARN: row.NativeArn, Attribute: api.AttributeName(row.AttributeName), Expiry: row.Expiry, CreatedAt: row.CreatedAt}
	err = json.Unmarshal(row.KeysData, &v.Key)
	return v, err
}

func (w writer) PutTTLDeletion(v domain.TTLDeletion) error {
	keys, err := json.Marshal(v.Key)
	if err != nil {
		return err
	}
	return w.q.PutTTLDeletion(w.ctx, sqlcgen.PutTTLDeletionParams{DatabaseID: v.DatabaseID, Partition: v.Table.Partition, AccountID: v.Table.AccountID, Region: v.Table.Region, TableName: v.Table.Name, PhysicalName: v.PhysicalName, StreamArn: v.StreamARN, NativeArn: v.NativeARN, KeysData: keys, AttributeName: string(v.Attribute), Expiry: v.Expiry, CreatedAt: v.CreatedAt})
}

func (w writer) DeleteTTLDeletion(databaseID string) error {
	return w.q.DeleteTTLDeletion(w.ctx, databaseID)
}
