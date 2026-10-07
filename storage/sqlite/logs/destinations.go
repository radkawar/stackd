package logs

import (
	domain "stackd/storage/logs"
	"stackd/storage/sqlite/logs/internal/sqlcgen"
)

func (r reader) destination(v sqlcgen.LogsDestination) (domain.DestinationRecord, error) {
	out := domain.DestinationRecord{
		CFNOwner:  v.CfnOwner,
		Key:       domain.DestinationKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name},
		TargetARN: v.TargetArn, RoleARN: v.RoleArn, AccessPolicy: v.AccessPolicy, Created: v.Created,
	}
	tags, err := r.q.ListDestinationTags(r.ctx, sqlcgen.ListDestinationTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DestinationName: v.Name})
	if err != nil {
		return out, err
	}
	out.Tags = make(map[string]string, len(tags))
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	return out, nil
}

func (r reader) Destination(k domain.DestinationKey) (domain.DestinationRecord, error) {
	v, err := r.q.GetDestination(r.ctx, sqlcgen.GetDestinationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.DestinationRecord{}, notFound(err)
	}
	return r.destination(v)
}

func (r reader) Destinations(q domain.DestinationQuery) ([]domain.DestinationRecord, error) {
	rows, err := r.q.ListDestinations(r.ctx, sqlcgen.ListDestinationsParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, Prefix: q.Prefix, AfterName: q.After, PageLimit: int64(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DestinationRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.destination(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (w writer) PutDestination(v domain.DestinationRecord) error {
	if err := w.q.PutDestination(w.ctx, sqlcgen.PutDestinationParams{CfnOwner: v.CFNOwner, Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, TargetArn: v.TargetARN, RoleArn: v.RoleARN, AccessPolicy: v.AccessPolicy, Created: v.Created}); err != nil {
		return err
	}
	if err := w.q.DeleteDestinationTags(w.ctx, sqlcgen.DeleteDestinationTagsParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, DestinationName: v.Key.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutDestinationTag(w.ctx, sqlcgen.PutDestinationTagParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, DestinationName: v.Key.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteDestination(k domain.DestinationKey) error {
	return w.q.DeleteDestination(w.ctx, sqlcgen.DeleteDestinationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
