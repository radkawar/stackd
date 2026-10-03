package dynamodb

import (
	api "stackd/internal/awsapi/dynamodb"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) Tags(k domain.TableKey) (domain.TagRecord, error) {
	row, err := r.q.GetTagSet(r.ctx, sqlcgen.GetTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.TagRecord{}, missing(err)
	}
	out := domain.TagRecord{Key: k}
	if !row.TagsPresent {
		return out, nil
	}
	tags, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return out, err
	}
	out.Tags = make(api.TagList, len(tags))
	for i, tag := range tags {
		out.Tags[i] = api.Tag{Key: stringPointer[api.TagKeyString](tag.Key), Value: stringPointer[api.TagValueString](tag.Value)}
	}
	return out, nil
}

func (w writer) PutTags(v domain.TagRecord) error {
	k := v.Key
	if err := w.q.PutTagSet(w.ctx, sqlcgen.PutTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, TagsPresent: v.Tags != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for i, tag := range v.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}
