package ec2

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
)

func registerInstanceProfiles(s *Service) {
	register(s, "AssociateIamInstanceProfile", s.associateIamInstanceProfile)
	register(s, "DisassociateIamInstanceProfile", s.disassociateIamInstanceProfile)
	register(s, "ReplaceIamInstanceProfileAssociation", s.replaceIamInstanceProfileAssociation)
	register(s, "DescribeIamInstanceProfileAssociations", s.describeIamInstanceProfileAssociations)
}

func (s *Service) resolveAssociationProfile(ctx context.Context, specification *api.IamInstanceProfileSpecification) (iamapi.InstanceProfile, error) {
	if specification == nil || str(specification.Arn) == "" && str(specification.Name) == "" {
		return iamapi.InstanceProfile{}, failure("MissingParameter", "The request must contain the parameter iamInstanceProfile.arn or iamInstanceProfile.name")
	}
	if s.instanceProfiles == nil {
		return iamapi.InstanceProfile{}, unsupported("IAM instance-profile credentials are not configured.")
	}
	return s.instanceProfiles.ResolveInstanceProfile(ctx, *specification)
}

func (s *Service) authorizeAssociationProfile(ctx context.Context, action string, instance InstanceRecord, profile iamapi.InstanceProfile) error {
	conditions := instanceProfileConditions(instance)
	conditions["ec2:NewInstanceProfile"] = []string{str(profile.Arn)}
	if err := s.authorizeWith(ctx, action, "instance", instance.Key.ID, instance.Data.Tags, conditions); err != nil {
		return err
	}
	for _, role := range profile.Roles {
		now := s.clock.Now()
		if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: str(role.Arn), ResourceAccountID: instance.Key.Scope.AccountID, Context: map[string][]string{"iam:PassedToService": {"ec2.amazonaws.com"}, "iam:AssociatedResourceArn": {resourceARN(instance.Key.Scope, "instance", "*")}, "iam:RoleName": {str(role.RoleName)}}, EvaluationTime: &now}); denied != nil {
			return denied
		}
	}
	return nil
}

func instanceProfileConditions(instance InstanceRecord) map[string][]string {
	d := &instance.Data
	conditions := map[string][]string{"ec2:InstanceID": {instance.Key.ID}, "ec2:InstanceType": {str(d.InstanceType)}, "ec2:RootDeviceType": {str(d.RootDeviceType)}, "ec2:ebsOptimized": {strconv.FormatBool(boolValue(d.EbsOptimized))}, "ec2:InstanceMarketType": {"on-demand"}}
	if d.IamInstanceProfile != nil {
		conditions["ec2:InstanceProfile"] = []string{str(d.IamInstanceProfile.Arn)}
	}
	if d.Placement != nil {
		conditions["ec2:AvailabilityZone"] = []string{str(d.Placement.AvailabilityZone)}
		conditions["ec2:AvailabilityZoneId"] = []string{str(d.Placement.AvailabilityZoneId)}
		conditions["ec2:Tenancy"] = []string{str(d.Placement.Tenancy)}
	}
	if d.MetadataOptions != nil {
		conditions["ec2:MetadataHttpTokens"] = []string{str(d.MetadataOptions.HttpTokens)}
		conditions["ec2:MetadataHttpEndpoint"] = []string{str(d.MetadataOptions.HttpEndpoint)}
		conditions["ec2:InstanceMetadataTags"] = []string{str(d.MetadataOptions.InstanceMetadataTags)}
		if d.MetadataOptions.HttpPutResponseHopLimit != nil {
			conditions["ec2:MetadataHttpPutResponseHopLimit"] = []string{strconv.Itoa(int(*d.MetadataOptions.HttpPutResponseHopLimit))}
		}
	}
	return conditions
}

func activeInstanceProfileAssociation(tx Reader, instance ResourceKey) (InstanceProfileAssociationRecord, bool, error) {
	associations, err := tx.InstanceProfileAssociations(instance.Scope)
	if err != nil {
		return InstanceProfileAssociationRecord{}, false, err
	}
	for _, association := range associations {
		if association.InstanceID == instance.ID && association.State != api.IamInstanceProfileAssociationStateDISASSOCIATED {
			return association, true, nil
		}
	}
	return InstanceProfileAssociationRecord{}, false, nil
}

func validInstanceProfileAssociationID(id string) bool {
	// TODO: Comeback validate native opaque association-ID encoding; lexical
	// validity alone cannot distinguish malformed long IDs from absent IDs.
	return strings.HasPrefix(id, "iip-assoc-") && len(id) == len("iip-assoc-")+17 && strings.Trim(id[len("iip-assoc-"):], "0123456789abcdef") == ""
}

func loadInstanceProfileAssociation(ctx context.Context, tx Reader, id string) (InstanceProfileAssociationRecord, error) {
	if id == "" {
		return InstanceProfileAssociationRecord{}, failure("MissingParameter", "The request must contain the parameter associationId")
	}
	if !validInstanceProfileAssociationID(id) {
		return InstanceProfileAssociationRecord{}, failure("InvalidParameterValue", "Invalid Id: "+id)
	}
	record, err := tx.InstanceProfileAssociation(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return record, failure("InvalidAssociationID.NotFound", "An association for '"+id+"' is not found")
	}
	return record, err
}

func (s *Service) admitInstanceProfileAssociation(ctx context.Context, tx Transaction, instance *InstanceRecord, profile *api.IamInstanceProfile) (InstanceProfileAssociationRecord, error) {
	id, err := tx.NextID(instance.Key.Scope, "iip-assoc")
	if err != nil {
		return InstanceProfileAssociationRecord{}, err
	}
	record := InstanceProfileAssociationRecord{Key: key(ctx, id), InstanceID: instance.Key.ID, ProfileARN: str(profile.Arn), ProfileID: str(profile.Id), State: api.IamInstanceProfileAssociationStateASSOCIATING, Timestamp: s.clock.Now(), NextActionAt: s.clock.Now().Add(time.Second)}
	return record, tx.PutInstanceProfileAssociation(record)
}

func (s *Service) associateIamInstanceProfile(ctx context.Context, tx Transaction, in *api.AssociateIamInstanceProfileRequest) (*api.AssociateIamInstanceProfileResult, error) {
	if str(in.InstanceId) == "" {
		return nil, failure("MissingParameter", "The request must contain the parameter instanceId")
	}
	instance, err := loadInstance(ctx, tx, str(in.InstanceId))
	if err != nil {
		return nil, err
	}
	profile, err := s.resolveAssociationProfile(ctx, in.IamInstanceProfile)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeAssociationProfile(ctx, "AssociateIamInstanceProfile", instance, profile); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if state := instanceState(instance); state != "running" && state != "stopped" {
		return nil, failure("IncorrectInstanceState", "The instance '"+instance.Key.ID+"' is not in the 'running' or 'stopped' states.")
	}
	if _, present, err := activeInstanceProfileAssociation(tx, instance.Key); err != nil {
		return nil, err
	} else if present {
		return nil, failure("IncorrectState", "There is an existing association for instance "+instance.Key.ID)
	}
	record, err := s.admitInstanceProfileAssociation(ctx, tx, &instance, &api.IamInstanceProfile{Arn: new(api.String(str(profile.Arn))), Id: new(api.String(str(profile.InstanceProfileId)))})
	if err != nil {
		return nil, err
	}
	instance.Data.IamInstanceProfile = record.profile()
	if err := tx.PutInstance(instance); err != nil {
		return nil, err
	}
	out := record.wire()
	return &api.AssociateIamInstanceProfileResult{IamInstanceProfileAssociation: &out}, nil
}

func (s *Service) disassociateIamInstanceProfile(ctx context.Context, tx Transaction, in *api.DisassociateIamInstanceProfileRequest) (*api.DisassociateIamInstanceProfileResult, error) {
	record, err := loadInstanceProfileAssociation(ctx, tx, str(in.AssociationId))
	if err != nil {
		return nil, err
	}
	instance, err := tx.Instance(ResourceKey{Scope: record.Key.Scope, ID: record.InstanceID})
	if err != nil {
		return nil, err
	}
	if err := s.authorizeWith(ctx, "DisassociateIamInstanceProfile", "instance", instance.Key.ID, instance.Data.Tags, instanceProfileConditions(instance)); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if instanceState(instance) == "stopped" {
		record.State = api.IamInstanceProfileAssociationStateDISASSOCIATED
		if err := tx.DeleteInstanceProfileAssociation(record.Key); err != nil {
			return nil, err
		}
		if profile := instance.Data.IamInstanceProfile; profile != nil && str(profile.Id) == record.ProfileID && str(profile.Arn) == record.ProfileARN {
			instance.Data.IamInstanceProfile = nil
			if err := tx.PutInstance(instance); err != nil {
				return nil, err
			}
		}
		out := record.wire()
		return &api.DisassociateIamInstanceProfileResult{IamInstanceProfileAssociation: &out}, nil
	}
	if record.State != api.IamInstanceProfileAssociationStateDISASSOCIATED && record.State != api.IamInstanceProfileAssociationStateDISASSOCIATING {
		record.State = api.IamInstanceProfileAssociationStateDISASSOCIATING
		record.NextActionAt = s.clock.Now().Add(time.Second)
		if err := tx.PutInstanceProfileAssociation(record); err != nil {
			return nil, err
		}
	}
	out := record.wire()
	return &api.DisassociateIamInstanceProfileResult{IamInstanceProfileAssociation: &out}, nil
}

func (s *Service) replaceIamInstanceProfileAssociation(ctx context.Context, tx Transaction, in *api.ReplaceIamInstanceProfileAssociationRequest) (*api.ReplaceIamInstanceProfileAssociationResult, error) {
	record, err := loadInstanceProfileAssociation(ctx, tx, str(in.AssociationId))
	if err != nil {
		return nil, err
	}
	instance, err := tx.Instance(ResourceKey{Scope: record.Key.Scope, ID: record.InstanceID})
	if err != nil {
		return nil, err
	}
	profile, err := s.resolveAssociationProfile(ctx, in.IamInstanceProfile)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeAssociationProfile(ctx, "ReplaceIamInstanceProfileAssociation", instance, profile); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if instanceState(instance) != "running" {
		return nil, failure("IncorrectState", "The instance '"+instance.Key.ID+"' is not in the 'running' state.")
	}
	if record.State != api.IamInstanceProfileAssociationStateASSOCIATED {
		return nil, failure("IncorrectState", "The association is not in the associated state.")
	}
	if record.ProfileID == str(profile.InstanceProfileId) {
		out := record.wire()
		return &api.ReplaceIamInstanceProfileAssociationResult{IamInstanceProfileAssociation: &out}, nil
	}
	record.State = api.IamInstanceProfileAssociationStateDISASSOCIATING
	record.NextActionAt = s.clock.Now().Add(time.Second)
	if err := tx.PutInstanceProfileAssociation(record); err != nil {
		return nil, err
	}
	replacement, err := s.admitInstanceProfileAssociation(ctx, tx, &instance, &api.IamInstanceProfile{Arn: new(api.String(str(profile.Arn))), Id: new(api.String(str(profile.InstanceProfileId)))})
	if err != nil {
		return nil, err
	}
	out := replacement.wire()
	return &api.ReplaceIamInstanceProfileAssociationResult{IamInstanceProfileAssociation: &out}, nil
}

func (s *Service) describeIamInstanceProfileAssociations(ctx context.Context, tx Transaction, in *api.DescribeIamInstanceProfileAssociationsRequest) (*api.DescribeIamInstanceProfileAssociationsResult, error) {
	if err := s.authorize(ctx, "DescribeIamInstanceProfileAssociations", "*", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.MaxResults != nil && *in.MaxResults <= 0 {
		return nil, failure("InvalidParameterValue", "MaxResults must be a positive integer.")
	}
	for _, filter := range in.Filters {
		if len(filter.Values) == 0 {
			return nil, failure("InvalidParameterValue", "A filter must contain at least one value.")
		}
		for _, value := range filter.Values {
			switch str(filter.Name) {
			case "state":
				if value != "associated" && value != "associating" && value != "disassociating" {
					return nil, failure("InvalidParameterValue", "Only 'associated', 'associating' and 'disassociating' are allowed")
				}
			case "instance-id":
				if err := validateInstanceID(string(value)); err != nil {
					return nil, failure("InvalidParameterValue", "A filter with an invalid instance-id was given")
				}
			}
		}
	}
	records, err := tx.InstanceProfileAssociations(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]InstanceProfileAssociationRecord, len(records))
	for _, record := range records {
		items = append(items, pageItem{ID: record.Key.ID, Fields: map[string][]string{"instance-id": {record.InstanceID}, "state": {string(record.State)}}})
		byID[record.Key.ID] = record
	}
	for _, id := range in.AssociationIds {
		if !validInstanceProfileAssociationID(string(id)) {
			return nil, failure("InvalidParameterValue", "Invalid value for association-id.")
		}
		if _, ok := byID[string(id)]; !ok {
			return nil, failure("InvalidAssociationID.NotFound", "An invalid association-id of '"+string(id)+"' was given")
		}
	}
	// TODO: Comeback capture native multi-page association cursor binding and
	// encoding; continuation currently uses the shared scoped EC2 cursor owner.
	selected, token, err := selectPageItems(ctx, "DescribeIamInstanceProfileAssociations", stringsOf(in.AssociationIds), in.Filters, maxResults(in.MaxResults), (*api.String)(in.NextToken), items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeIamInstanceProfileAssociationsResult{IamInstanceProfileAssociations: api.IamInstanceProfileAssociationSet{}, NextToken: (*api.NextToken)(token)}
	for _, id := range selected {
		out.IamInstanceProfileAssociations = append(out.IamInstanceProfileAssociations, byID[id].wire())
	}
	return out, nil
}
