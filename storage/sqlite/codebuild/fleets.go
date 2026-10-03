package codebuild

import (
	api "stackd/internal/awsapi/codebuild"
	domain "stackd/storage/codebuild"
	"stackd/storage/sqlite/codebuild/internal/sqlcgen"
)

func (r reader) Fleet(k domain.FleetKey) (domain.FleetRecord, error) {
	row, err := r.q.GetFleet(r.ctx, sqlcgen.GetFleetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, FleetName: k.Name})
	if err != nil {
		return domain.FleetRecord{}, missing(err)
	}
	return r.fleet(row)
}

func (r reader) Fleets(k domain.Scope) ([]domain.FleetRecord, error) {
	rows, err := r.q.ListFleets(r.ctx, sqlcgen.ListFleetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.FleetRecord, len(rows))
	for i, row := range rows {
		out[i], err = r.fleet(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) AllFleets() ([]domain.FleetRecord, error) {
	rows, err := r.q.ListAllFleets(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.FleetRecord, len(rows))
	for i, row := range rows {
		out[i], err = r.fleet(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) fleet(row sqlcgen.CodebuildFleet) (domain.FleetRecord, error) {
	out := domain.FleetRecord{
		Key: domain.FleetKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.FleetName},
		Data: api.Fleet{
			Arn: stringPointer[api.NonEmptyString](row.Arn), Name: stringPointer[api.FleetName](row.Name), Id: stringPointer[api.NonEmptyString](row.FleetID),
			BaseCapacity: integerPointer[api.FleetCapacity](row.BaseCapacity), ComputeType: stringPointer[api.ComputeType](row.ComputeType),
			Created: timePointer(row.Created), EnvironmentType: stringPointer[api.EnvironmentType](row.EnvironmentType),
			FleetServiceRole: stringPointer[api.NonEmptyString](row.FleetServiceRole), ImageId: stringPointer[api.NonEmptyString](row.ImageID),
			LastModified: timePointer(row.LastModified), OverflowBehavior: stringPointer[api.FleetOverflowBehavior](row.OverflowBehavior),
		},
	}
	if err := unmarshalFields(
		jsonReadField{row.ComputeConfiguration, &out.Data.ComputeConfiguration}, jsonReadField{row.ProxyConfiguration, &out.Data.ProxyConfiguration},
		jsonReadField{row.ScalingConfiguration, &out.Data.ScalingConfiguration}, jsonReadField{row.Status, &out.Data.Status},
		jsonReadField{row.VpcConfig, &out.Data.VpcConfig},
	); err != nil {
		return domain.FleetRecord{}, err
	}
	if row.TagsPresent {
		tags, err := r.q.ListFleetTags(r.ctx, sqlcgen.ListFleetTagsParams{Partition: out.Key.Partition, AccountID: out.Key.AccountID, Region: out.Key.Region, FleetName: out.Key.Name})
		if err != nil {
			return domain.FleetRecord{}, err
		}
		out.Data.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Data.Tags[i] = api.Tag{Key: stringPointer[api.KeyInput](tag.TagKey), Value: stringPointer[api.ValueInput](tag.TagValue)}
		}
	}
	return out, nil
}

func (w writer) PutFleet(v domain.FleetRecord) error {
	k, d := v.Key, v.Data
	row := sqlcgen.PutFleetParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, FleetName: k.Name,
		Arn: nullableString(d.Arn), Name: nullableString(d.Name), FleetID: nullableString(d.Id), BaseCapacity: nullableInteger(d.BaseCapacity),
		ComputeType: nullableString(d.ComputeType), Created: nullableTime(d.Created), EnvironmentType: nullableString(d.EnvironmentType),
		FleetServiceRole: nullableString(d.FleetServiceRole), ImageID: nullableString(d.ImageId), LastModified: nullableTime(d.LastModified),
		OverflowBehavior: nullableString(d.OverflowBehavior), TagsPresent: d.Tags != nil,
	}
	if err := marshalFields(
		jsonWriteField{&row.ComputeConfiguration, d.ComputeConfiguration}, jsonWriteField{&row.ProxyConfiguration, d.ProxyConfiguration},
		jsonWriteField{&row.ScalingConfiguration, d.ScalingConfiguration}, jsonWriteField{&row.Status, d.Status},
		jsonWriteField{&row.VpcConfig, d.VpcConfig},
	); err != nil {
		return err
	}
	if err := w.q.PutFleet(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteFleetTags(w.ctx, sqlcgen.DeleteFleetTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, FleetName: k.Name}); err != nil {
		return err
	}
	for i, tag := range d.Tags {
		if err := w.q.PutFleetTag(w.ctx, sqlcgen.PutFleetTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, FleetName: k.Name, Position: int64(i), TagKey: nullableString(tag.Key), TagValue: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteFleet(k domain.FleetKey) error {
	return w.q.DeleteFleet(w.ctx, sqlcgen.DeleteFleetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, FleetName: k.Name})
}
