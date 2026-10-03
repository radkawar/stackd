package ec2

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) Image(k domain.ResourceKey) (domain.ImageRecord, error) {
	row, err := r.q.GetImage(r.ctx, sqlcgen.GetImageParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.ImageRecord{}, missing(err)
	}
	return r.image(row)
}

func (r reader) RegionalImage(scope domain.Scope, id string) (domain.ImageRecord, error) {
	row, err := r.q.GetRegionalImage(r.ctx, sqlcgen.GetRegionalImageParams{Partition: scope.Partition, Region: scope.Region, ResourceID: id})
	if err != nil {
		return domain.ImageRecord{}, missing(err)
	}
	return r.image(row)
}

func (r reader) Images(scope domain.Scope) ([]domain.ImageRecord, error) {
	rows, err := r.q.ListImages(r.ctx, sqlcgen.ListImagesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.imageRows(rows)
}

func (r reader) RegionalImages(scope domain.Scope) ([]domain.ImageRecord, error) {
	rows, err := r.q.ListRegionalImages(r.ctx, sqlcgen.ListRegionalImagesParams{Partition: scope.Partition, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.imageRows(rows)
}

func (r reader) imageRows(rows []sqlcgen.Ec2Image) ([]domain.ImageRecord, error) {
	out := make([]domain.ImageRecord, 0, len(rows))
	for _, row := range rows {
		image, err := r.image(row)
		if err != nil {
			return nil, err
		}
		out = append(out, image)
	}
	return out, nil
}

func (r reader) ImageReferencingSnapshot(scope domain.Scope, owner, snapshotID string) (string, error) {
	id, err := r.q.ImageReferencingSnapshot(r.ctx, sqlcgen.ImageReferencingSnapshotParams{Partition: scope.Partition, Region: scope.Region, SnapshotOwner: sql.NullString{String: owner, Valid: true}, SnapshotID: sql.NullString{String: snapshotID, Valid: true}})
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (r reader) image(row sqlcgen.Ec2Image) (domain.ImageRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.ImageRecord{Key: k, Data: api.Image{
		ImageId: stringPointer[api.String](row.ImageID), Architecture: stringPointer[api.ArchitectureValues](row.Architecture),
		BootMode: stringPointer[api.BootModeValues](row.BootMode), CreationDate: stringPointer[api.String](row.CreationDate),
		DeprecationTime: stringPointer[api.String](row.DeprecationTime), DeregistrationProtection: stringPointer[api.String](row.DeregistrationProtection),
		Description: stringPointer[api.String](row.Description), EnaSupport: boolPointer[api.Boolean](row.EnaSupport),
		FreeTierEligible: boolPointer[api.Boolean](row.FreeTierEligible), Hypervisor: stringPointer[api.HypervisorType](row.Hypervisor),
		ImageAllowed: boolPointer[api.Boolean](row.ImageAllowed), ImageLocation: stringPointer[api.String](row.ImageLocation),
		ImageOwnerAlias: stringPointer[api.String](row.ImageOwnerAlias), ImageType: stringPointer[api.ImageTypeValues](row.ImageType),
		ImdsSupport: stringPointer[api.ImdsSupportValues](row.ImdsSupport), KernelId: stringPointer[api.String](row.KernelID),
		LastLaunchedTime: stringPointer[api.String](row.LastLaunchedTime), Name: stringPointer[api.String](row.Name),
		OwnerId: stringPointer[api.String](row.OwnerID), Platform: stringPointer[api.PlatformValues](row.Platform),
		PlatformDetails: stringPointer[api.String](row.PlatformDetails), Public: boolPointer[api.Boolean](row.Public),
		PublicSsmParameterName: stringPointer[api.String](row.PublicSsmParameterName), RamdiskId: stringPointer[api.String](row.RamdiskID),
		RootDeviceName: stringPointer[api.String](row.RootDeviceName), RootDeviceType: stringPointer[api.DeviceType](row.RootDeviceType),
		SourceImageId: stringPointer[api.String](row.SourceImageID), SourceImageRegion: stringPointer[api.String](row.SourceImageRegion),
		SourceInstanceId: stringPointer[api.String](row.SourceInstanceID), SriovNetSupport: stringPointer[api.String](row.SriovNetSupport),
		State: stringPointer[api.ImageState](row.State), TpmSupport: stringPointer[api.TpmSupportValues](row.TpmSupport),
		UsageOperation: stringPointer[api.String](row.UsageOperation), VirtualizationType: stringPointer[api.VirtualizationType](row.VirtualizationType),
	}}
	if err := unmarshalFields(jsonReadField{row.InstanceTypeSpecification, &out.Data.InstanceTypeSpecification}, jsonReadField{row.StateReason, &out.Data.StateReason}); err != nil {
		return out, err
	}
	if row.SnapshotOwnersPresent {
		out.SnapshotOwners = map[string]string{}
	}
	if row.MappingsPresent {
		mappings, err := r.q.ListImageMappings(r.ctx, sqlcgen.ListImageMappingsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		out.Data.BlockDeviceMappings = make(api.BlockDeviceMappingList, len(mappings))
		for i, mapping := range mappings {
			out.Data.BlockDeviceMappings[i] = api.BlockDeviceMapping{DeviceName: stringPointer[api.String](mapping.DeviceName), NoDevice: stringPointer[api.String](mapping.NoDevice), VirtualName: stringPointer[api.String](mapping.VirtualName)}
			if mapping.EbsPresent {
				out.Data.BlockDeviceMappings[i].Ebs = &api.EbsBlockDevice{
					AvailabilityZone: stringPointer[api.String](mapping.AvailabilityZone), AvailabilityZoneId: stringPointer[api.String](mapping.AvailabilityZoneID),
					DeleteOnTermination: boolPointer[api.Boolean](mapping.DeleteOnTermination), EbsCardIndex: integerPointer[api.Integer](mapping.EbsCardIndex),
					Encrypted: boolPointer[api.Boolean](mapping.Encrypted), Iops: integerPointer[api.Integer](mapping.Iops),
					KmsKeyId: stringPointer[api.String](mapping.KmsKeyID), OutpostArn: stringPointer[api.String](mapping.OutpostArn),
					SnapshotId: stringPointer[api.SnapshotId](mapping.SnapshotID), Throughput: integerPointer[api.Integer](mapping.Throughput),
					VolumeInitializationRate: integerPointer[api.Integer](mapping.VolumeInitializationRate), VolumeSize: integerPointer[api.Integer](mapping.VolumeSize),
					VolumeType: stringPointer[api.VolumeType](mapping.VolumeType),
				}
			}
			if row.SnapshotOwnersPresent && mapping.SnapshotOwner.Valid && mapping.SnapshotID.Valid {
				out.SnapshotOwners[mapping.SnapshotID.String] = mapping.SnapshotOwner.String
			}
		}
	}
	if err := r.imageChildren(row, &out); err != nil {
		return out, err
	}
	var err error
	out.Create, err = r.imageCreation(k)
	return out, err
}

func (w writer) PutImage(v domain.ImageRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutImageParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		ImageID: nullableString(d.ImageId), Architecture: nullableString(d.Architecture), BootMode: nullableString(d.BootMode),
		CreationDate: nullableString(d.CreationDate), DeprecationTime: nullableString(d.DeprecationTime), DeregistrationProtection: nullableString(d.DeregistrationProtection),
		Description: nullableString(d.Description), EnaSupport: nullableBool(d.EnaSupport), FreeTierEligible: nullableBool(d.FreeTierEligible),
		Hypervisor: nullableString(d.Hypervisor), ImageAllowed: nullableBool(d.ImageAllowed), ImageLocation: nullableString(d.ImageLocation),
		ImageOwnerAlias: nullableString(d.ImageOwnerAlias), ImageType: nullableString(d.ImageType), ImdsSupport: nullableString(d.ImdsSupport),
		KernelID: nullableString(d.KernelId), LastLaunchedTime: nullableString(d.LastLaunchedTime), Name: nullableString(d.Name), OwnerID: nullableString(d.OwnerId),
		Platform: nullableString(d.Platform), PlatformDetails: nullableString(d.PlatformDetails), Public: nullableBool(d.Public),
		PublicSsmParameterName: nullableString(d.PublicSsmParameterName), RamdiskID: nullableString(d.RamdiskId), RootDeviceName: nullableString(d.RootDeviceName),
		RootDeviceType: nullableString(d.RootDeviceType), SourceImageID: nullableString(d.SourceImageId), SourceImageRegion: nullableString(d.SourceImageRegion),
		SourceInstanceID: nullableString(d.SourceInstanceId), SriovNetSupport: nullableString(d.SriovNetSupport), State: nullableString(d.State),
		TpmSupport: nullableString(d.TpmSupport), UsageOperation: nullableString(d.UsageOperation), VirtualizationType: nullableString(d.VirtualizationType),
		MappingsPresent: d.BlockDeviceMappings != nil, TagsPresent: d.Tags != nil, PermissionsPresent: v.LaunchPermissions != nil,
		SnapshotOwnersPresent: v.SnapshotOwners != nil, ProductsPresent: d.ProductCodes != nil, WatermarksPresent: d.ImageWatermarks != nil,
	}
	if err := marshalFields(jsonWriteField{&params.InstanceTypeSpecification, d.InstanceTypeSpecification}, jsonWriteField{&params.StateReason, d.StateReason}); err != nil {
		return err
	}
	if err := w.q.PutImage(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.DeleteImageMappings(w.ctx, sqlcgen.DeleteImageMappingsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, mapping := range d.BlockDeviceMappings {
		p := sqlcgen.PutImageMappingParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			DeviceName: nullableString(mapping.DeviceName), NoDevice: nullableString(mapping.NoDevice), VirtualName: nullableString(mapping.VirtualName), EbsPresent: mapping.Ebs != nil}
		if ebs := mapping.Ebs; ebs != nil {
			p.AvailabilityZone, p.AvailabilityZoneID = nullableString(ebs.AvailabilityZone), nullableString(ebs.AvailabilityZoneId)
			p.DeleteOnTermination, p.EbsCardIndex = nullableBool(ebs.DeleteOnTermination), nullableInteger(ebs.EbsCardIndex)
			p.Encrypted, p.Iops = nullableBool(ebs.Encrypted), nullableInteger(ebs.Iops)
			p.KmsKeyID, p.OutpostArn = nullableString(ebs.KmsKeyId), nullableString(ebs.OutpostArn)
			p.SnapshotID, p.Throughput = nullableString(ebs.SnapshotId), nullableInteger(ebs.Throughput)
			p.VolumeInitializationRate, p.VolumeSize, p.VolumeType = nullableInteger(ebs.VolumeInitializationRate), nullableInteger(ebs.VolumeSize), nullableString(ebs.VolumeType)
			if owner, ok := v.SnapshotOwners[p.SnapshotID.String]; ok {
				p.SnapshotOwner = sql.NullString{String: owner, Valid: true}
			}
		}
		if err := w.q.PutImageMapping(w.ctx, p); err != nil {
			return err
		}
	}
	if err := w.putImageChildren(v); err != nil {
		return err
	}
	return w.putImageCreation(k, v.Create)
}

func (w writer) DeleteImage(k domain.ResourceKey) error {
	return deleted(w.q.DeleteImage(w.ctx, sqlcgen.DeleteImageParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
