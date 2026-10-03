package dynamodb

import (
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
	"time"
)

func (r reader) KinesisDestinations() ([]domain.KinesisDestination, error) {
	rows, err := r.q.ListKinesisDestinations(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.KinesisDestination, len(rows))
	for i, v := range rows {
		out[i] = domain.KinesisDestination{ID: v.ID, Table: domain.TableKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TableName}, PhysicalName: v.PhysicalName, StreamARN: v.StreamArn, Status: v.Status, Description: v.Description, Precision: v.Precision, PendingPrecision: v.PendingPrecision, AdmissionFailure: v.AdmissionFailure, Superseded: v.Superseded, Due: v.Due.UTC(), CaptureUntil: v.CaptureUntil.UTC()}
	}
	return out, nil
}
func (w writer) PutKinesisDestination(v domain.KinesisDestination) error {
	return w.q.PutKinesisDestination(w.ctx, sqlcgen.PutKinesisDestinationParams{ID: v.ID, Partition: v.Table.Partition, AccountID: v.Table.AccountID, Region: v.Table.Region, TableName: v.Table.Name, PhysicalName: v.PhysicalName, StreamArn: v.StreamARN, Status: v.Status, Description: v.Description, Precision: v.Precision, PendingPrecision: v.PendingPrecision, AdmissionFailure: v.AdmissionFailure, Superseded: v.Superseded, Due: v.Due.UTC(), CaptureUntil: v.CaptureUntil.UTC()})
}
func (r reader) KinesisDeliveries() ([]domain.KinesisDelivery, error) {
	rows, err := r.q.ListKinesisDeliveries(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.KinesisDelivery, len(rows))
	for i, v := range rows {
		out[i] = domain.KinesisDelivery{ID: v.ID, DestinationID: v.DestinationID, Table: domain.TableKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TableName}, StreamARN: v.StreamArn, PartitionKey: v.PartitionKey, Data: v.Data, ParentEventID: v.ParentEventID, Due: v.Due.UTC(), Attempts: v.Attempts, LastError: v.LastError}
	}
	return out, nil
}
func (w writer) PutKinesisDelivery(v domain.KinesisDelivery) error {
	return w.q.PutKinesisDelivery(w.ctx, sqlcgen.PutKinesisDeliveryParams{ID: v.ID, DestinationID: v.DestinationID, Partition: v.Table.Partition, AccountID: v.Table.AccountID, Region: v.Table.Region, TableName: v.Table.Name, StreamArn: v.StreamARN, PartitionKey: v.PartitionKey, Data: v.Data, ParentEventID: v.ParentEventID, Due: v.Due.UTC(), Attempts: v.Attempts, LastError: v.LastError})
}
func (w writer) DeleteKinesisDelivery(id string) error { return w.q.DeleteKinesisDelivery(w.ctx, id) }

func (r reader) NextKinesisDelivery() (string, time.Time, error) {
	row, err := r.q.NextKinesisDelivery(r.ctx)
	if err != nil {
		return "", time.Time{}, missing(err)
	}
	return row.ID, row.Due.UTC(), nil
}
func (r reader) KinesisDelivery(id string) (domain.KinesisDelivery, error) {
	v, err := r.q.GetKinesisDelivery(r.ctx, id)
	if err != nil {
		return domain.KinesisDelivery{}, missing(err)
	}
	return domain.KinesisDelivery{ID: v.ID, DestinationID: v.DestinationID, Table: domain.TableKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TableName}, StreamARN: v.StreamArn, PartitionKey: v.PartitionKey, Data: v.Data, ParentEventID: v.ParentEventID, Due: v.Due.UTC(), Attempts: v.Attempts, LastError: v.LastError}, nil
}
