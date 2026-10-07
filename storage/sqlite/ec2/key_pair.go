package ec2

import (
	"database/sql"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) KeyPair(k domain.ResourceKey) (domain.KeyPairRecord, error) {
	row, err := r.q.GetKeyPair(r.ctx, sqlcgen.GetKeyPairParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.KeyPairRecord{}, missing(err)
	}
	return r.keyPair(row)
}

func (r reader) KeyPairs(scope domain.Scope) ([]domain.KeyPairRecord, error) {
	rows, err := r.q.ListKeyPairs(r.ctx, sqlcgen.ListKeyPairsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.KeyPairRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.keyPair(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) keyPair(row sqlcgen.Ec2KeyPair) (domain.KeyPairRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.KeyPairRecord{Key: k, Data: api.KeyPairInfo{
		KeyPairId:      stringPointer[api.String](row.KeyPairID),
		KeyName:        stringPointer[api.String](row.KeyName),
		KeyFingerprint: stringPointer[api.String](row.KeyFingerprint),
		KeyType:        stringPointer[api.KeyType](row.KeyType),
		PublicKey:      stringPointer[api.String](row.PublicKey),
	}}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	if row.CreateTime.Valid {
		out.Data.CreateTime = new(api.MillisecondDateTime(row.CreateTime.Time))
	}
	if row.TagsPresent {
		tags, err := r.q.ListKeyPairTags(r.ctx, sqlcgen.ListKeyPairTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		out.Data.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Data.Tags[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	return out, nil
}

func (w writer) PutKeyPair(v domain.KeyPairRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutKeyPairParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		KeyPairID: nullableString(d.KeyPairId), KeyName: nullableString(d.KeyName), KeyFingerprint: nullableString(d.KeyFingerprint),
		KeyType: nullableString(d.KeyType), PublicKey: nullableString(d.PublicKey), TagsPresent: d.Tags != nil,
	}
	if d.CreateTime != nil {
		params.CreateTime = sql.NullTime{Time: *d.CreateTime, Valid: true}
	}
	if err := w.q.PutKeyPair(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.DeleteKeyPairTags(w.ctx, sqlcgen.DeleteKeyPairTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, tag := range d.Tags {
		if err := w.q.PutKeyPairTag(w.ctx, sqlcgen.PutKeyPairTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteKeyPair(k domain.ResourceKey) error {
	return deleted(w.q.DeleteKeyPair(w.ctx, sqlcgen.DeleteKeyPairParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
