package s3

import (
	"database/sql"
	"errors"

	"stackd/internal/scheduler"
	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) AccessLogDelivery(id string) (domain.AccessLogDelivery, error) {
	row, err := r.q.GetAccessLogDelivery(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AccessLogDelivery{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AccessLogDelivery{}, err
	}
	return r.accessLogDelivery(row)
}

func (r reader) NextAccessLogDelivery() (scheduler.Job, bool, error) {
	row, err := r.q.NextAccessLogDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	return scheduler.Job{Key: row.ID, Due: row.Due}, err == nil, err
}

func (r reader) accessLogDelivery(row sqlcgen.S3AccessLogDelivery) (domain.AccessLogDelivery, error) {
	out := domain.AccessLogDelivery{
		ID: row.ID, Source: domain.BucketKey{Partition: row.Partition, Name: row.BucketName},
		AccountID: row.AccountID, Region: row.Region,
		Destination: domain.LoggingConfiguration{
			TargetBucket: row.TargetBucket, TargetPrefix: row.TargetPrefix, KeyFormat: row.KeyFormat,
		},
		Record: row.Record, At: row.At, Due: row.Due,
	}
	if !row.HasGrants {
		return out, nil
	}
	grants, err := r.q.GetAccessLogDeliveryGrants(r.ctx, row.ID)
	if err != nil {
		return domain.AccessLogDelivery{}, err
	}
	out.Destination.Grants = make([]domain.ACLGrant, len(grants))
	for i, grant := range grants {
		out.Destination.Grants[i] = domain.ACLGrant{Type: grant.GranteeType, ID: grant.GranteeID, URI: grant.GranteeUri, Permission: grant.Permission}
	}
	return out, nil
}

func (w writer) PutAccessLogDelivery(delivery domain.AccessLogDelivery) error {
	inserted, err := w.q.InsertAccessLogDelivery(w.ctx, sqlcgen.InsertAccessLogDeliveryParams{
		ID: delivery.ID, Partition: delivery.Source.Partition, BucketName: delivery.Source.Name,
		AccountID: delivery.AccountID, Region: delivery.Region,
		TargetBucket: delivery.Destination.TargetBucket, TargetPrefix: delivery.Destination.TargetPrefix,
		KeyFormat: delivery.Destination.KeyFormat, HasGrants: delivery.Destination.Grants != nil,
		Record: delivery.Record, At: delivery.At.UTC(), Due: delivery.Due.UTC(),
	})
	if err != nil {
		return err
	}
	if inserted == 0 {
		return w.q.UpdateAccessLogDeliveryDue(w.ctx, sqlcgen.UpdateAccessLogDeliveryDueParams{ID: delivery.ID, Due: delivery.Due.UTC()})
	}
	for position, grant := range delivery.Destination.Grants {
		if err := w.q.PutAccessLogDeliveryGrant(w.ctx, sqlcgen.PutAccessLogDeliveryGrantParams{
			DeliveryID: delivery.ID, Position: int64(position), GranteeType: grant.Type,
			GranteeID: grant.ID, GranteeUri: grant.URI, Permission: grant.Permission,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteAccessLogDelivery(id string) error {
	return w.q.DeleteAccessLogDelivery(w.ctx, id)
}
