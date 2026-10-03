package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) NetworkInterfaceCreation(k domain.NetworkInterfaceCreationKey) (domain.NetworkInterfaceCreationRecord, error) {
	row, err := r.q.GetNetworkInterfaceCreation(r.ctx, sqlcgen.GetNetworkInterfaceCreationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token})
	if err != nil {
		return domain.NetworkInterfaceCreationRecord{}, missing(err)
	}
	out := domain.NetworkInterfaceCreationRecord{Key: k, ResourceID: row.ResourceID, Input: api.CreateNetworkInterfaceRequest{
		SubnetId:                       stringPointer[api.SubnetId](row.SubnetID),
		Description:                    stringPointer[api.String](row.Description),
		InterfaceType:                  stringPointer[api.NetworkInterfaceCreationType](row.InterfaceType),
		PrivateIpAddress:               stringPointer[api.String](row.PrivateIpAddress),
		SecondaryPrivateIpAddressCount: integerPointer[api.Integer](row.SecondaryPrivateIpAddressCount),
	}}
	if row.GroupsPresent {
		groups, err := r.q.ListNetworkInterfaceCreationGroups(r.ctx, sqlcgen.ListNetworkInterfaceCreationGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token})
		if err != nil {
			return out, err
		}
		out.Input.Groups = make(api.SecurityGroupIdStringList, len(groups))
		for i, group := range groups {
			out.Input.Groups[i] = api.SecurityGroupId(group.GroupID)
		}
	}
	if row.PrivateIpAddressesPresent {
		addresses, err := r.q.ListNetworkInterfaceCreationPrivateIPs(r.ctx, sqlcgen.ListNetworkInterfaceCreationPrivateIPsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token})
		if err != nil {
			return out, err
		}
		out.Input.PrivateIpAddresses = make(api.PrivateIpAddressSpecificationList, len(addresses))
		for i, address := range addresses {
			out.Input.PrivateIpAddresses[i] = api.PrivateIpAddressSpecification{PrivateIpAddress: stringPointer[api.String](address.PrivateIpAddress), Primary: boolPointer[api.Boolean](address.IsPrimary)}
		}
	}
	return out, nil
}

func (w writer) PutNetworkInterfaceCreation(v domain.NetworkInterfaceCreationRecord) error {
	k, d := v.Key, &v.Input
	if err := w.q.PutNetworkInterfaceCreation(w.ctx, sqlcgen.PutNetworkInterfaceCreationParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token, ResourceID: v.ResourceID,
		SubnetID:                       nullableString(d.SubnetId),
		Description:                    nullableString(d.Description),
		InterfaceType:                  nullableString(d.InterfaceType),
		PrivateIpAddress:               nullableString(d.PrivateIpAddress),
		SecondaryPrivateIpAddressCount: nullableInteger(d.SecondaryPrivateIpAddressCount),
		GroupsPresent:                  d.Groups != nil,
		PrivateIpAddressesPresent:      d.PrivateIpAddresses != nil,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteNetworkInterfaceCreationGroups(w.ctx, sqlcgen.DeleteNetworkInterfaceCreationGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token}); err != nil {
		return err
	}
	for i, group := range d.Groups {
		if err := w.q.PutNetworkInterfaceCreationGroup(w.ctx, sqlcgen.PutNetworkInterfaceCreationGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token, Position: int64(i), GroupID: string(group)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteNetworkInterfaceCreationPrivateIPs(w.ctx, sqlcgen.DeleteNetworkInterfaceCreationPrivateIPsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token}); err != nil {
		return err
	}
	for i, address := range d.PrivateIpAddresses {
		if err := w.q.PutNetworkInterfaceCreationPrivateIP(w.ctx, sqlcgen.PutNetworkInterfaceCreationPrivateIPParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Token: k.Token, Position: int64(i),
			PrivateIpAddress: nullableString(address.PrivateIpAddress), IsPrimary: nullableBool(address.Primary),
		}); err != nil {
			return err
		}
	}
	return nil
}
