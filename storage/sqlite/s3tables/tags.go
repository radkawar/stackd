package s3tables

import (
	"errors"

	domain "stackd/storage/s3tables"
	"stackd/storage/sqlite/s3tables/internal/sqlcgen"
)

func (r reader) TableByARN(sc domain.Scope, arn string) (domain.Table, error) {
	row, err := r.q.GetTableByARN(r.ctx, sqlcgen.GetTableByARNParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: arn})
	return table(row), missing(err)
}

func (r reader) resourceExists(sc domain.Scope, arn string) error {
	if _, err := r.Bucket(sc, arn); err != nil {
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		_, err = r.TableByARN(sc, arn)
		return err
	}
	return nil
}

func (r reader) ResourceTags(sc domain.Scope, arn string) (domain.Tags, error) {
	if err := r.resourceExists(sc, arn); err != nil {
		return nil, err
	}
	rows, err := r.q.ListResourceTags(r.ctx, sqlcgen.ListResourceTagsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ResourceArn: arn})
	if err != nil {
		return nil, err
	}
	tags := make(domain.Tags, len(rows))
	for _, row := range rows {
		tags[row.Key] = row.Value
	}
	return tags, nil
}

func (w writer) PutResourceTags(sc domain.Scope, arn string, tags domain.Tags) error {
	if err := w.resourceExists(sc, arn); err != nil {
		return err
	}
	if err := w.q.DeleteResourceTags(w.ctx, sqlcgen.DeleteResourceTagsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ResourceArn: arn}); err != nil {
		return err
	}
	for key, value := range tags {
		if err := w.q.PutResourceTag(w.ctx, sqlcgen.PutResourceTagParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ResourceArn: arn, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
