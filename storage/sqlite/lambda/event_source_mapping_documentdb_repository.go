package lambda

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) loadDocumentDBMapping(v *domain.EventSourceMappingRecord) error {
	k := v.Key
	row, err := r.q.GetDocumentDBMapping(r.ctx, sqlcgen.GetDocumentDBMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	v.Settings.DocumentDB = &domain.DocumentDBMappingSettings{Database: row.DatabaseName, Collection: row.CollectionName, FullDocument: row.FullDocument, SecretARN: row.SecretArn, StartingPosition: row.StartingPosition, StartingPositionTimestamp: row.StartingPositionTimestamp, Incarnation: row.Incarnation}
	v.Settings.BatchingWindow = time.Duration(row.BatchingWindowNs)
	return nil
}
func (w writer) putDocumentDBMapping(v domain.EventSourceMappingRecord) error {
	d := v.Settings.DocumentDB
	if d == nil {
		return nil
	}
	k := v.Key
	return w.q.PutDocumentDBMapping(w.ctx, sqlcgen.PutDocumentDBMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, DatabaseName: d.Database, CollectionName: d.Collection, FullDocument: d.FullDocument, SecretArn: d.SecretARN, StartingPosition: d.StartingPosition, StartingPositionTimestamp: d.StartingPositionTimestamp, BatchingWindowNs: int64(v.Settings.BatchingWindow), Incarnation: d.Incarnation})
}
func (r reader) DocumentDBCheckpoint(k domain.EventSourceMappingKey) (domain.DocumentDBCheckpoint, error) {
	row, err := r.q.GetDocumentDBCheckpoint(r.ctx, sqlcgen.GetDocumentDBCheckpointParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DocumentDBCheckpoint{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.DocumentDBCheckpoint{}, err
	}
	return domain.DocumentDBCheckpoint{Mapping: k, Incarnation: row.Incarnation, ResumeToken: row.ResumeToken, StartSeconds: uint32(row.StartSeconds), StartIncrement: uint32(row.StartIncrement)}, nil
}
func (w writer) PutDocumentDBCheckpoint(v domain.DocumentDBCheckpoint) error {
	k := v.Mapping
	token := v.ResumeToken
	if token == nil {
		token = []byte{}
	}
	return w.q.PutDocumentDBCheckpoint(w.ctx, sqlcgen.PutDocumentDBCheckpointParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, Incarnation: v.Incarnation, ResumeToken: token, StartSeconds: int64(v.StartSeconds), StartIncrement: int64(v.StartIncrement)})
}
func (w writer) DeleteDocumentDBCheckpoint(k domain.EventSourceMappingKey) error {
	return w.q.DeleteDocumentDBCheckpoint(w.ctx, sqlcgen.DeleteDocumentDBCheckpointParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
}
