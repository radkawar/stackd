package ecs

import (
	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) Tags(k domain.TagKey) (domain.TagRecord, error) {
	out := domain.TagRecord{Key: k}
	present, err := r.q.GetTagSet(r.ctx, sqlcgen.GetTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN})
	if err != nil {
		return out, missing(err)
	}
	if !present {
		return out, nil
	}
	rows, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN})
	if err != nil {
		return out, err
	}
	out.Tags = make(api.Tags, len(rows))
	for i, row := range rows {
		out.Tags[i] = api.Tag{Key: stringPointer[api.TagKey](row.Key), Value: stringPointer[api.TagValue](row.Value)}
	}
	return out, nil
}
func (w writer) PutTags(v domain.TagRecord) error {
	k := v.Key
	if err := w.q.PutTagSet(w.ctx, sqlcgen.PutTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN, TagsPresent: v.Tags != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN}); err != nil {
		return err
	}
	for i, tag := range v.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}
