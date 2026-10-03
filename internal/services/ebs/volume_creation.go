package ebs

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	ebsapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
)

// VolumeCreationDelay and VolumeDeletionDelay are deterministic emulator timing,
// not promises about AWS provisioning or physical cleanup latency.
const VolumeCreationDelay = time.Second
const VolumeDeletionDelay = time.Second

func volumeZone(ctx context.Context, in *api.CreateVolumeRequest, catalogue func(context.Context) (api.AvailabilityZoneList, error)) (ec2.AvailabilityZone, error) {
	name, id := value(in.AvailabilityZone), value(in.AvailabilityZoneId)
	if name == "" && id == "" {
		return ec2.AvailabilityZone{}, ec2Failure("MissingParameter", "The request must contain the parameter zone")
	}
	if name != "" && id != "" {
		return ec2.AvailabilityZone{}, ec2Failure("InvalidParameterCombination", "AvailabilityZone and AvailabilityZoneId can't be used together. Specify only one of these parameters.")
	}
	zones, err := catalogue(ctx)
	if err != nil {
		return ec2.AvailabilityZone{}, err
	}
	for _, zone := range zones {
		if name != "" && value(zone.ZoneName) != name || id != "" && value(zone.ZoneId) != id {
			continue
		}
		if value(zone.ZoneType) != "availability-zone" {
			// TODO: Comeback implement volume placement with Local Zone, Wavelength
			// and Outpost owners rather than inventing a regional disk placement.
			return ec2.AvailabilityZone{}, ec2Failure("UnsupportedOperation", "Volume placement outside regional Availability Zones is not implemented.")
		}
		return ec2.AvailabilityZone{Name: value(zone.ZoneName), ID: value(zone.ZoneId)}, nil
	}
	if name == "" {
		name = id
	}
	return ec2.AvailabilityZone{}, ec2Failure("InvalidZone.NotFound", "The zone '"+name+"' does not exist.")
}

func volumeRequestConditions(tags api.TagList) map[string][]string {
	conditions := make(map[string][]string)
	for _, tag := range tags {
		conditions["aws:RequestTag/"+value(tag.Key)] = []string{value(tag.Value)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], value(tag.Key))
	}
	return conditions
}

func volumeCreationIdentity(in api.CreateVolumeRequest, zone string) []byte {
	in = api.CloneCreateVolumeRequest(in)
	in.ClientToken, in.DryRun, in.AvailabilityZoneId = nil, nil, nil
	in.AvailabilityZone = new(api.AvailabilityZoneName(zone))
	kind := strings.ToLower(value(in.VolumeType))
	if kind == "" {
		kind = "gp2"
	}
	in.VolumeType = new(api.VolumeType(kind))
	if kind == "gp3" && in.Throughput == nil {
		in.Throughput = new(api.Integer(125))
	}
	for i := range in.TagSpecifications {
		slices.SortFunc(in.TagSpecifications[i].Tags, func(a, b api.Tag) int {
			if compare := strings.Compare(value(a.Key), value(b.Key)); compare != 0 {
				return compare
			}
			return strings.Compare(value(a.Value), value(b.Value))
		})
	}
	slices.SortFunc(in.TagSpecifications, func(a, b api.TagSpecification) int {
		return strings.Compare(value(a.ResourceType), value(b.ResourceType))
	})
	encoded, _ := json.Marshal(in)
	return encoded
}

func (s *Service) CreateVolume(ctx context.Context, in *api.CreateVolumeRequest, catalogue func(context.Context) (api.AvailabilityZoneList, error)) (*api.Volume, error) {
	zone, err := volumeZone(ctx, in, catalogue)
	if err != nil {
		return nil, err
	}
	tags, err := ec2.CreationTags(in.TagSpecifications, "volume")
	if err != nil {
		return nil, err
	}
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	var out api.Volume
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		scope := scopeFor(ctx)
		var source *SnapshotRecord
		if id := value(in.SnapshotId); id != "" {
			if err := snapshotControlID(id, false); err != nil {
				return err
			}
			v, err := tx.RegionalSnapshot(scope.Partition, scope.Region, id)
			if errors.Is(err, ErrNotFound) {
				return ec2Failure("InvalidSnapshot.NotFound", "Snapshot does not exist")
			}
			if err != nil {
				return err
			}
			source = &v
			s.observeSnapshot(ctx, v)
			visible, err := s.ec2Visible(tx, *source)
			if err != nil {
				return err
			}
			if !visible || source.Deleted {
				return ec2Failure("InvalidSnapshot.NotFound", "Snapshot does not exist")
			}
		}
		var sourceSize int64
		if source != nil {
			sourceSize = source.VolumeSize
		}
		configuration, err := volumeConfiguration(in, sourceSize)
		if err != nil {
			return err
		}
		defaults, err := s.encryptionDefault(tx)
		if err != nil {
			return err
		}
		encrypted := defaults.Enabled || source != nil && source.KMSKeyARN != "" || in.Encrypted != nil && bool(*in.Encrypted)
		destination := VolumeRecord{Key: VolumeKey{Scope: scope, ID: "*"}, Configuration: configuration, ZoneName: zone.Name, ZoneID: zone.ID, Encrypted: encrypted}
		conditions := volumeRequestConditions(tags)
		if err := s.authorizeVolume(ctx, "CreateVolume", destination, conditions); err != nil {
			return err
		}
		if source != nil {
			authority := *source
			if authority.Key.AccountID != scope.AccountID {
				authority.Tags, err = tx.SharedTags(SharedTagsKey{Snapshot: source.Key, AccountID: scope.AccountID})
				if err != nil {
					return err
				}
			}
			if err := s.authorize(ctx, "ec2", "CreateVolume", authority, nil); err != nil {
				return err
			}
		}
		if len(tags) > 0 {
			conditions["ec2:CreateAction"] = []string{"CreateVolume"}
			if err := s.authorizeVolume(ctx, "CreateTags", destination, conditions); err != nil {
				return err
			}
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		if err := volumeMultiAttachConfiguration(configuration); err != nil {
			return err
		}
		if in.OutpostArn != nil || in.Operator != nil {
			// TODO: Comeback connect Outpost and service-managed volume creation to
			// their actual owners; ordinary volumes never impersonate those resources.
			return ec2Failure("UnsupportedOperation", "Outpost and service-managed volumes are not implemented.")
		}
		if len(value(in.ClientToken)) > 64 {
			return ec2Failure("InvalidParameterValue", "Client token must be less than or equal to 64 characters.")
		}
		if token := value(in.ClientToken); token != "" {
			prior, err := tx.VolumeByToken(scope, token)
			if err == nil {
				if string(volumeCreationIdentity(prior.CreationInput, prior.ZoneName)) != string(volumeCreationIdentity(*in, zone.Name)) {
					return ec2Failure("IdempotentParameterMismatch", "Parameters on this idempotent request are inconsistent with parameters used in previous request(s).")
				}
				if prior.Status == api.VolumeStateDeleting || prior.Status == api.VolumeStateDeleted {
					return ec2Failure("IdempotentParameterMismatch", "The client token '"+token+"' is associated with resource '"+prior.Key.ID+"' which has already been deleted. Please use a different client token.")
				}
				out = volumeCreationProjection(prior, source)
				return nil
			}
			if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		if source != nil {
			if source.Status != ebsapi.StatusCOMPLETED {
				return ec2Failure("IncorrectState", "Snapshot is in invalid state - "+string(source.Status))
			}
			if in.Encrypted != nil && !bool(*in.Encrypted) && source.KMSKeyARN != "" {
				return ec2Failure("InvalidParameterCombination", "Encrypted snapshots must be used to create encrypted volumes.")
			}
		}
		if in.KmsKeyId != nil && (in.Encrypted == nil || !bool(*in.Encrypted)) {
			return ec2Failure("InvalidParameterDependency", "The parameter KmsKeyId requires the parameter Encrypted to be set.")
		}
		id, err := tx.NextVolumeID(scope)
		if err != nil {
			return err
		}
		destination.Key.ID = id
		destination.Created = s.clock.Now()
		destination.Status = api.VolumeStateCreating
		destination.TransitionAt = destination.Created.Add(VolumeCreationDelay)
		destination.CreationInput = api.CloneCreateVolumeRequest(*in)
		destination.InitializationRate = int32(number(in.VolumeInitializationRate))
		destination.Tags = make(map[string]string, len(tags))
		for _, tag := range tags {
			destination.Tags[value(tag.Key)] = value(tag.Value)
		}
		metadata := awsctx.FromContext(ctx)
		destination.RequestID, destination.ParentEventID = metadata.RequestID, apievents.EventID(ctx)
		destination.LineageID = id
		if source != nil {
			destination.SnapshotID, destination.LineageID = source.Key.ID, source.LineageID
		}
		var material BlockKeyMaterial
		if encrypted {
			if s.ec2Keys == nil {
				return errors.New("EC2 volume encryption is not configured")
			}
			keyID := value(in.KmsKeyId)
			if keyID == "" && source != nil && source.Key.AccountID == scope.AccountID {
				keyID = source.KMSKeyARN
			}
			if keyID == "" {
				keyID = defaults.KMSKeyID
			}
			var rejected *awswire.Error
			if keyID == "" || keyID == "alias/aws/ebs" {
				keyID, rejected = s.ec2Keys.EnsureServiceKey(ctx, "ebs")
			}
			if strings.HasPrefix(keyID, "arn:") && strings.Contains(keyID, ":key/") {
				destination.KMSKeyARN = keyID
			}
			if rejected == nil {
				material, rejected = s.ec2Keys.PrepareVolume(ctx, source, destination, keyID)
			}
			defer clear(material.SourcePlaintext)
			defer clear(material.DestinationPlaintext)
			if material.KMSKeyARN != "" {
				destination.KMSKeyARN = material.KMSKeyARN
			}
			if rejected != nil {
				destination.StateMessage = rejected.Message
			} else {
				destination.KMSKeyARN, destination.WrappedKey = material.KMSKeyARN, material.WrappedKey
				destination.ServiceGrantID = material.ServiceGrantID
			}
		}
		if destination.StateMessage == "" && source != nil {
			destination.Creation = &VolumeCreation{
				Source: source.Key, SourceWrappedKey: material.SourceWrappedKey,
				ReuseSourceCiphertext: material.ReuseSourceCiphertext, RetireGrant: true,
			}
		}
		if err := tx.PutVolume(destination); err != nil {
			return err
		}
		out = volumeCreationProjection(destination, source)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.jobs.Wake()
	return &out, nil
}

func volumeCreationProjection(v VolumeRecord, source *SnapshotRecord) api.Volume {
	out := volumeProjection(v)
	out.CreateTime = new(v.Created.Truncate(time.Second))
	if out.Tags == nil {
		out.Tags = api.TagList{}
	}
	if v.CreationInput.KmsKeyId == nil && (source == nil || source.Key.AccountID != v.Key.AccountID || source.KMSKeyARN == "") {
		out.KmsKeyId = nil
	}
	return out
}
