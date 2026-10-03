package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) NetworkCreation(key domain.NetworkCreationKey) (domain.NetworkCreationRecord, error) {
	row, err := r.q.GetNetworkCreation(r.ctx, sqlcgen.GetNetworkCreationParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Action: key.Action, Token: key.Token})
	if err != nil {
		return domain.NetworkCreationRecord{}, missing(err)
	}
	out := domain.NetworkCreationRecord{Key: key, VPCID: row.VpcID, ResourceID: row.ResourceID}
	if row.TagsPresent {
		tags, err := r.q.ListNetworkCreationTags(r.ctx, sqlcgen.ListNetworkCreationTagsParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Action: key.Action, Token: key.Token})
		if err != nil {
			return out, err
		}
		out.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Tags[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	return out, nil
}

func (w writer) PutNetworkCreation(record domain.NetworkCreationRecord) error {
	key := record.Key
	if err := w.q.PutNetworkCreation(w.ctx, sqlcgen.PutNetworkCreationParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Action: key.Action, Token: key.Token, VpcID: record.VPCID, ResourceID: record.ResourceID, TagsPresent: record.Tags != nil}); err != nil {
		return err
	}
	for i, tag := range record.Tags {
		if err := w.q.PutNetworkCreationTag(w.ctx, sqlcgen.PutNetworkCreationTagParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Action: key.Action, Token: key.Token, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}
