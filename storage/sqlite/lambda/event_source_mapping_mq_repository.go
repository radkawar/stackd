package lambda

import (
	"database/sql"
	"errors"
	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
	"time"
)

func (r reader) loadMQMapping(v *domain.EventSourceMappingRecord) error {
	k := v.Key
	row, err := r.q.GetMQMapping(r.ctx, sqlcgen.GetMQMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	v.Settings.MQ = &domain.MQMappingSettings{Queue: row.QueueName, VirtualHost: row.VirtualHost, VirtualHostSet: row.VirtualHostSet, SecretARN: row.SecretArn, Identity: domain.MQIdentity{BrokerID: row.BrokerID, Engine: row.Engine}}
	v.Settings.BatchingWindow = time.Duration(row.BatchingWindowNs)
	return nil
}
func (w writer) putMQMapping(v domain.EventSourceMappingRecord) error {
	d := v.Settings.MQ
	if d == nil {
		return nil
	}
	k := v.Key
	return w.q.PutMQMapping(w.ctx, sqlcgen.PutMQMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, QueueName: d.Queue, VirtualHost: d.VirtualHost, VirtualHostSet: d.VirtualHostSet, SecretArn: d.SecretARN, BrokerID: d.Identity.BrokerID, Engine: d.Identity.Engine, BatchingWindowNs: int64(v.Settings.BatchingWindow)})
}
