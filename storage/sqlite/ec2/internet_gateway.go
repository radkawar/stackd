package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) InternetGateway(k domain.ResourceKey) (domain.InternetGatewayRecord, error) {
	row, err := r.q.GetInternetGateway(r.ctx, sqlcgen.GetInternetGatewayParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.InternetGatewayRecord{}, missing(err)
	}
	return r.internetGateway(row)
}

func (r reader) InternetGateways(scope domain.Scope) ([]domain.InternetGatewayRecord, error) {
	rows, err := r.q.ListInternetGateways(r.ctx, sqlcgen.ListInternetGatewaysParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.InternetGatewayRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.internetGateway(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) internetGateway(row sqlcgen.Ec2InternetGateway) (domain.InternetGatewayRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.InternetGatewayRecord{Key: k, Data: api.InternetGateway{InternetGatewayId: stringPointer[api.String](row.InternetGatewayID), OwnerId: stringPointer[api.String](row.OwnerID)}}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	if row.AttachmentsPresent {
		attachments, err := r.q.ListInternetGatewayAttachments(r.ctx, sqlcgen.ListInternetGatewayAttachmentsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		out.Data.Attachments = make(api.InternetGatewayAttachmentList, len(attachments))
		for i, attachment := range attachments {
			out.Data.Attachments[i] = api.InternetGatewayAttachment{State: stringPointer[api.AttachmentStatus](attachment.State), VpcId: stringPointer[api.String](attachment.VpcID)}
		}
	}
	if row.TagsPresent {
		tags, err := r.q.ListInternetGatewayTags(r.ctx, sqlcgen.ListInternetGatewayTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
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

func (w writer) PutInternetGateway(v domain.InternetGatewayRecord) error {
	k, d := v.Key, &v.Data
	if err := w.q.PutInternetGateway(w.ctx, sqlcgen.PutInternetGatewayParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		InternetGatewayID: nullableString(d.InternetGatewayId), OwnerID: nullableString(d.OwnerId), AttachmentsPresent: d.Attachments != nil, TagsPresent: d.Tags != nil,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteInternetGatewayAttachments(w.ctx, sqlcgen.DeleteInternetGatewayAttachmentsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, attachment := range d.Attachments {
		if err := w.q.PutInternetGatewayAttachment(w.ctx, sqlcgen.PutInternetGatewayAttachmentParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), State: nullableString(attachment.State), VpcID: nullableString(attachment.VpcId)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInternetGatewayTags(w.ctx, sqlcgen.DeleteInternetGatewayTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, tag := range d.Tags {
		if err := w.q.PutInternetGatewayTag(w.ctx, sqlcgen.PutInternetGatewayTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteInternetGateway(k domain.ResourceKey) error {
	return deleted(w.q.DeleteInternetGateway(w.ctx, sqlcgen.DeleteInternetGatewayParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
