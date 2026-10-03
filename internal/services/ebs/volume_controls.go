package ebs

import (
	"context"
	"errors"
	"maps"
	"strconv"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
)

func volumeARN(key VolumeKey) string {
	return "arn:" + key.Partition + ":ec2:" + key.Region + ":" + key.AccountID + ":volume/" + key.ID
}

func volumeMissing(id string) *awswire.Error {
	return ec2Failure("InvalidVolume.NotFound", "The volume '"+id+"' does not exist.")
}

func ownedVolume(r Reader, id string) (VolumeRecord, error) {
	v, err := r.Volume(VolumeKey{Scope: scopeFor(r.Context()), ID: id})
	if errors.Is(err, ErrNotFound) || err == nil && v.Status == api.VolumeStateDeleted {
		return VolumeRecord{}, volumeMissing(id)
	}
	return v, err
}

func (s *Service) volumeAuthorization(ctx context.Context, action string, v VolumeRecord, conditions map[string][]string) authorization.Request {
	conditions = maps.Clone(conditions)
	if conditions == nil {
		conditions = make(map[string][]string)
	}
	conditions["ec2:Region"] = []string{scopeFor(ctx).Region}
	resource := "*"
	if v.Key.ID != "" {
		resource = volumeARN(v.Key)
		for key, value := range v.Tags {
			conditions["aws:ResourceTag/"+key] = []string{value}
			conditions["ec2:ResourceTag/"+key] = []string{value}
		}
		conditions["ec2:AvailabilityZone"] = []string{v.ZoneName}
		conditions["ec2:AvailabilityZoneID"] = []string{v.ZoneID}
		conditions["ec2:VolumeSize"] = []string{strconv.FormatInt(int64(v.Configuration.Size), 10)}
		conditions["ec2:VolumeType"] = []string{string(v.Configuration.Type)}
		conditions["ec2:Encrypted"] = []string{strconv.FormatBool(v.Encrypted)}
		conditions["ec2:VolumeIops"] = []string{strconv.FormatInt(int64(v.Configuration.Iops), 10)}
	}
	now := s.clock.Now()
	return authorization.Request{Action: "ec2:" + action, ResourceARN: resource, ResourceAccountID: v.Key.AccountID, Context: conditions, EvaluationTime: &now}
}

func (s *Service) authorizeVolume(ctx context.Context, action string, v VolumeRecord, conditions map[string][]string) error {
	if rejected := s.authorizer.Authorize(ctx, s.volumeAuthorization(ctx, action, v, conditions)); rejected != nil {
		return rejected
	}
	return nil
}

func volumeProjection(v VolumeRecord) api.Volume {
	out := api.Volume{
		VolumeId: new(api.String(v.Key.ID)), Size: new(api.Integer(v.Configuration.Size)),
		VolumeType: new(v.Configuration.Type), SnapshotId: new(api.String(v.SnapshotID)),
		CreateTime: new(v.Created), State: new(v.Status), Encrypted: new(api.Boolean(v.Encrypted)),
		AvailabilityZone: new(api.String(v.ZoneName)), AvailabilityZoneId: new(api.String(v.ZoneID)),
		MultiAttachEnabled: new(api.Boolean(v.Configuration.MultiAttach)), Tags: ec2Tags(v.Tags),
	}
	if v.Configuration.Iops != 0 {
		out.Iops = new(api.Integer(v.Configuration.Iops))
	}
	if v.Configuration.Throughput != 0 {
		out.Throughput = new(api.Integer(v.Configuration.Throughput))
	}
	if v.InitializationRate != 0 {
		out.VolumeInitializationRate = new(api.Integer(v.InitializationRate))
	}
	if v.KMSKeyARN != "" {
		out.KmsKeyId = new(api.String(v.KMSKeyARN))
	}
	return out
}

func (s *Service) DescribeVolumes(ctx context.Context, in *api.DescribeVolumesRequest) (*api.DescribeVolumesResult, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	var out *api.DescribeVolumesResult
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorizeVolume(r.Context(), "DescribeVolumes", VolumeRecord{}, nil); err != nil {
			return err
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		if len(in.VolumeIds) > 0 && (in.MaxResults != nil || value(in.NextToken) != "") {
			_, err := ec2.SelectVolumePage(r.Context(), in, nil)
			return err
		}
		for _, id := range in.VolumeIds {
			if id == "" {
				return ec2Failure("MissingParameter", "The request must contain the parameter volumes")
			}
			if !validControlVolumeID(string(id)) {
				return ec2Failure("InvalidParameterValue", "Value ("+string(id)+") for parameter volumes is invalid. Expected: 'vol-...'.")
			}
		}
		records, err := r.Volumes(scopeFor(r.Context()))
		if err != nil {
			return err
		}
		rows := make(api.VolumeList, 0, len(records))
		for _, v := range records {
			if v.Status == api.VolumeStateDeleted {
				continue
			}
			row := volumeProjection(v)
			row.Attachments, err = s.volumeAttachments(r.Context(), v)
			if err != nil {
				return err
			}
			if len(row.Attachments) > 0 {
				row.State = new(api.VolumeStateIn_use)
			}
			row.OwnerId = new(api.String(v.Key.AccountID))
			row.VolumeArn = new(api.String(volumeARN(v.Key)))
			row.Operator = &api.OperatorResponse{Managed: new(api.Boolean(false)), HiddenByDefault: new(api.Boolean(false))}
			rows = append(rows, row)
		}
		out, err = ec2.SelectVolumePage(r.Context(), in, rows)
		return err
	})
	return out, err
}

func (s *Service) VolumeTags(ctx context.Context, action, id string) (api.TagList, authorization.Request, error) {
	if err := s.advance(ctx); err != nil {
		return nil, authorization.Request{}, err
	}
	var tags api.TagList
	var request authorization.Request
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := ownedVolume(r, id)
		if err != nil {
			return err
		}
		tags = ec2Tags(v.Tags)
		request = s.volumeAuthorization(r.Context(), action, v, nil)
		return nil
	})
	return tags, request, err
}

func (s *Service) SetVolumeTags(ctx context.Context, id string, tags api.TagList) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		v, err := ownedVolume(tx, id)
		if err != nil {
			return err
		}
		v.Tags = make(map[string]string, len(tags))
		for _, tag := range tags {
			v.Tags[value(tag.Key)] = value(tag.Value)
		}
		return tx.PutVolume(v)
	})
}

func (s *Service) ListVolumeTags(ctx context.Context) (api.TagDescriptionList, error) {
	out := api.TagDescriptionList{}
	err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Volumes(scopeFor(r.Context()))
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.Status == api.VolumeStateDeleted {
				continue
			}
			for _, tag := range ec2Tags(v.Tags) {
				out = append(out, api.TagDescription{ResourceId: new(api.String(v.Key.ID)), ResourceType: new(api.ResourceType("volume")), Key: tag.Key, Value: tag.Value})
			}
		}
		return nil
	})
	return out, err
}
