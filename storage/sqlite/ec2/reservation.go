package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) Reservation(k domain.ResourceKey) (domain.ReservationRecord, error) {
	row, err := r.q.GetInstanceReservation(r.ctx, sqlcgen.GetInstanceReservationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.ReservationRecord{}, missing(err)
	}
	return r.reservation(row)
}

func (r reader) InstanceReservationsByToken(scope domain.Scope, token string) ([]domain.ReservationRecord, error) {
	rows, err := r.q.InstanceReservationsByToken(r.ctx, sqlcgen.InstanceReservationsByTokenParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, ClientToken: token})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReservationRecord, 0, len(rows))
	for _, row := range rows {
		record, err := r.reservation(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (r reader) reservation(row sqlcgen.Ec2Reservation) (domain.ReservationRecord, error) {
	out := domain.ReservationRecord{
		Key:         domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID},
		ClientToken: row.ClientToken, TokenZone: row.TokenZone, RequesterID: row.RequesterID, LaunchPrincipalARN: row.LaunchPrincipalArn, LaunchPrincipalID: row.LaunchPrincipalID,
		Input: api.RunInstancesRequest{
			ImageId: stringPointer[api.ImageId](row.ImageID), InstanceType: stringPointer[api.InstanceType](row.InstanceType), MinCount: integerPointer[api.Integer](row.MinCount), MaxCount: integerPointer[api.Integer](row.MaxCount),
			KeyName: stringPointer[api.KeyPairName](row.KeyName), SubnetId: stringPointer[api.SubnetId](row.SubnetID), PrivateIpAddress: stringPointer[api.String](row.PrivateIpAddress),
			DisableApiStop: boolPointer[api.Boolean](row.DisableApiStop), DisableApiTermination: boolPointer[api.Boolean](row.DisableApiTermination), EbsOptimized: boolPointer[api.Boolean](row.EbsOptimized), InstanceInitiatedShutdownBehavior: stringPointer[api.ShutdownBehavior](row.ShutdownBehavior),
		},
	}
	d := &out.Input
	if row.UserData != nil {
		d.UserData = new(api.RunInstancesUserData(string(row.UserData)))
	}
	if err := unmarshalFields(jsonReadField{row.CpuOptions, &d.CpuOptions}, jsonReadField{row.CreditSpecification, &d.CreditSpecification}, jsonReadField{row.IamInstanceProfile, &d.IamInstanceProfile}, jsonReadField{row.MetadataOptions, &d.MetadataOptions}, jsonReadField{row.Monitoring, &d.Monitoring}, jsonReadField{row.Placement, &d.Placement}, jsonReadField{row.LaunchTemplate, &d.LaunchTemplate}); err != nil {
		return out, err
	}
	// Admission rejects populated unsupported sets, but permits explicit empty
	// sets. Preserve those distinctions for the original idempotency comparison.
	if row.ElasticGpuSpecificationPresent {
		d.ElasticGpuSpecification = api.ElasticGpuSpecifications{}
	}
	if row.ElasticInferenceAcceleratorsPresent {
		d.ElasticInferenceAccelerators = api.ElasticInferenceAccelerators{}
	}
	if row.Ipv6AddressesPresent {
		d.Ipv6Addresses = api.InstanceIpv6AddressList{}
	}
	if row.LicenseSpecificationsPresent {
		d.LicenseSpecifications = api.LicenseSpecificationListRequest{}
	}
	if row.SecondaryInterfacesPresent {
		d.SecondaryInterfaces = api.InstanceSecondaryInterfaceSpecificationListRequest{}
	}
	if row.SecurityGroupsPresent {
		d.SecurityGroups = api.SecurityGroupStringList{}
	}
	if err := r.reservationChildren(row, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (w writer) PutReservation(v domain.ReservationRecord) error {
	k, d := v.Key, &v.Input
	p := sqlcgen.PutInstanceReservationParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		ClientToken: v.ClientToken, TokenZone: v.TokenZone, RequesterID: v.RequesterID, LaunchPrincipalArn: v.LaunchPrincipalARN, LaunchPrincipalID: v.LaunchPrincipalID,
		ImageID: nullableString(d.ImageId), InstanceType: nullableString(d.InstanceType), MinCount: nullableInteger(d.MinCount), MaxCount: nullableInteger(d.MaxCount), KeyName: nullableString(d.KeyName), SubnetID: nullableString(d.SubnetId), PrivateIpAddress: nullableString(d.PrivateIpAddress),
		DisableApiStop: nullableBool(d.DisableApiStop), DisableApiTermination: nullableBool(d.DisableApiTermination), EbsOptimized: nullableBool(d.EbsOptimized), ShutdownBehavior: nullableString(d.InstanceInitiatedShutdownBehavior),
		InstancesPresent: v.InstanceIDs != nil, MappingsPresent: d.BlockDeviceMappings != nil, NetworksPresent: d.NetworkInterfaces != nil, GroupsPresent: d.SecurityGroupIds != nil, TagsPresent: d.TagSpecifications != nil,
		ElasticGpuSpecificationPresent: d.ElasticGpuSpecification != nil, ElasticInferenceAcceleratorsPresent: d.ElasticInferenceAccelerators != nil, Ipv6AddressesPresent: d.Ipv6Addresses != nil, LicenseSpecificationsPresent: d.LicenseSpecifications != nil, SecondaryInterfacesPresent: d.SecondaryInterfaces != nil, SecurityGroupsPresent: d.SecurityGroups != nil,
	}
	if d.UserData != nil {
		p.UserData = []byte(*d.UserData)
	}
	if err := marshalFields(jsonWriteField{&p.CpuOptions, d.CpuOptions}, jsonWriteField{&p.CreditSpecification, d.CreditSpecification}, jsonWriteField{&p.IamInstanceProfile, d.IamInstanceProfile}, jsonWriteField{&p.MetadataOptions, d.MetadataOptions}, jsonWriteField{&p.Monitoring, d.Monitoring}, jsonWriteField{&p.Placement, d.Placement}, jsonWriteField{&p.LaunchTemplate, d.LaunchTemplate}); err != nil {
		return err
	}
	if err := w.q.PutInstanceReservation(w.ctx, p); err != nil {
		return err
	}
	return w.putReservationChildren(v)
}
