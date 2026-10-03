package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) PublicAddress(k domain.ResourceKey) (domain.PublicAddressRecord, error) {
	row, err := r.q.GetPublicAddress(r.ctx, sqlcgen.GetPublicAddressParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.PublicAddressRecord{}, missing(err)
	}
	return r.publicAddress(row)
}
func (r reader) PublicAddresses(scope domain.Scope) ([]domain.PublicAddressRecord, error) {
	rows, err := r.q.ListPublicAddresses(r.ctx, sqlcgen.ListPublicAddressesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PublicAddressRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.publicAddress(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) PublicIPv4Reservations() ([]string, error) {
	rows, err := r.q.ListPublicIPv4Reservations(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, ip := range rows {
		out = append(out, ip.String)
	}
	return out, nil
}
func (r reader) publicAddress(row sqlcgen.Ec2PublicAddress) (domain.PublicAddressRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.PublicAddressRecord{Key: k, Automatic: row.Automatic, Data: api.Address{
		PublicIp: stringPointer[api.String](row.PublicIp), AssociationId: stringPointer[api.String](row.AssociationID), NetworkInterfaceId: stringPointer[api.String](row.NetworkInterfaceID), PrivateIpAddress: stringPointer[api.String](row.PrivateIpAddress), NetworkBorderGroup: new(api.String(row.NetworkBorderGroup)), Domain: new(api.DomainType("vpc")), PublicIpv4Pool: new(api.String("amazon")),
	}}
	if !out.Automatic {
		out.Data.AllocationId = new(api.String(k.ID))
	}
	if row.TagsPresent {
		tags, err := r.q.ListPublicAddressTags(r.ctx, sqlcgen.ListPublicAddressTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
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
func (w writer) PutPublicAddress(v domain.PublicAddressRecord) error {
	k, d := v.Key, &v.Data
	if err := w.q.PutPublicAddress(w.ctx, sqlcgen.PutPublicAddressParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Automatic: v.Automatic, PublicIp: nullableString(d.PublicIp), AssociationID: nullableString(d.AssociationId), NetworkInterfaceID: nullableString(d.NetworkInterfaceId), PrivateIpAddress: nullableString(d.PrivateIpAddress), NetworkBorderGroup: nullableString(d.NetworkBorderGroup).String, TagsPresent: d.Tags != nil}); err != nil {
		return err
	}
	if err := w.q.DeletePublicAddressTags(w.ctx, sqlcgen.DeletePublicAddressTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, tag := range d.Tags {
		if err := w.q.PutPublicAddressTag(w.ctx, sqlcgen.PutPublicAddressTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeletePublicAddress(k domain.ResourceKey) error {
	return deleted(w.q.DeletePublicAddress(w.ctx, sqlcgen.DeletePublicAddressParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
