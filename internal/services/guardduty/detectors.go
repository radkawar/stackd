package guardduty

import (
	"maps"
	"slices"
	"time"

	api "stackd/internal/awsapi/guardduty"
)

func registerDetectors(s *Service) {
	register(s, "CreateDetector", s.createDetector)
	register(s, "GetDetector", s.getDetector)
	register(s, "ListDetectors", s.listDetectors)
	register(s, "UpdateDetector", s.updateDetector)
	register(s, "DeleteDetector", s.deleteDetector)
}
func (s *Service) createDetector(tx Transaction, in *api.CreateDetectorInput) (*api.CreateDetectorOutput, error) {
	ctx := tx.Context()
	sc := scopeFor(ctx)
	tags := stringTags(in.Tags)
	if err := s.authorize(ctx, "CreateDetector", "*", nil, tags, slices.Sorted(maps.Keys(tags))); err != nil {
		return nil, err
	}
	if in.Enable == nil {
		return nil, invalid("enable is required")
	}
	rows, err := tx.AllDetectors()
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if v.Scope == sc {
			if token := value(in.ClientToken); token != "" && token == v.ClientToken {
				if err := checkCloudFormationOwnership(ctx, v.CFNOwnership); err != nil {
					return nil, err
				}
				out := &api.CreateDetectorOutput{}
				text(&out.DetectorId, v.ID)
				return out, nil
			}
			return nil, invalid("The request is rejected because a detector already exists for the current account.")
		}
	}
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	id := newID()
	v := Detector{Scope: sc, ID: id, ARN: detectorARN(sc, id), Status: "DISABLED", Frequency: "SIX_HOURS", ClientToken: value(in.ClientToken), Created: now, Updated: now, Tags: tags}
	v.CFNOwnership = creationOwnership(ctx)
	if bool(*in.Enable) {
		v.Status = "ENABLED"
	}
	if in.FindingPublishingFrequency != nil {
		v.Frequency = value(in.FindingPublishingFrequency)
	}
	if err := validateFrequency(v.Frequency); err != nil {
		return nil, err
	}
	v.Features = defaultFeatures(now)
	if err := applyFeatures(&v, in.Features, in.DataSources, now); err != nil {
		return nil, err
	}
	if s.roles == nil {
		return nil, failure("InternalServerErrorException", "GuardDuty IAM role owner is unavailable", 500)
	}
	if err := s.roles.EnsureServiceLinkedRole(ctx, ServicePrincipal); err != nil {
		return nil, err
	}
	v.ServiceRole = "arn:" + sc.Partition + ":iam::" + sc.AccountID + ":role/aws-service-role/" + ServicePrincipal + "/" + ServiceRoleName
	if err := tx.PutDetector(v); err != nil {
		return nil, err
	}
	out := &api.CreateDetectorOutput{}
	text(&out.DetectorId, id)
	return out, nil
}
func (s *Service) getDetector(tx Transaction, in *api.GetDetectorInput) (*api.GetDetectorOutput, error) {
	v, err := s.loadDetector(tx, value(in.DetectorId), "GetDetector")
	if err != nil {
		return nil, err
	}
	out := &api.GetDetectorOutput{Tags: outputTags(v.Tags), DataSources: detectorDataSources(v)}
	text(&out.CreatedAt, v.Created.Format(time.RFC3339Nano))
	text(&out.UpdatedAt, v.Updated.Format(time.RFC3339Nano))
	text(&out.Status, v.Status)
	text(&out.ServiceRole, v.ServiceRole)
	text(&out.FindingPublishingFrequency, v.Frequency)
	for _, f := range v.Features {
		row := api.DetectorFeatureConfigurationResult{AdditionalConfiguration: api.DetectorAdditionalConfigurationResults{}}
		text(&row.Name, f.Name)
		text(&row.Status, f.Status)
		at := api.Timestamp(f.Updated)
		row.UpdatedAt = &at
		for _, a := range f.Additional {
			item := api.DetectorAdditionalConfigurationResult{}
			text(&item.Name, a.Name)
			text(&item.Status, a.Status)
			at := api.Timestamp(a.Updated)
			item.UpdatedAt = &at
			row.AdditionalConfiguration = append(row.AdditionalConfiguration, item)
		}
		out.Features = append(out.Features, row)
	}
	return out, nil
}
func (s *Service) listDetectors(tx Transaction, in *api.ListDetectorsInput) (*api.ListDetectorsOutput, error) {
	if err := s.authorize(tx.Context(), "ListDetectors", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	// A regional account has at most one detector. Native ignores NextToken.
	if in.MaxResults != nil && (*in.MaxResults < 1 || *in.MaxResults > 50) {
		return nil, invalid("maxResults must be between 1 and 50")
	}
	rows, err := tx.AllDetectors()
	if err != nil {
		return nil, err
	}
	out := &api.ListDetectorsOutput{DetectorIds: api.DetectorIds{}}
	sc := scopeFor(tx.Context())
	for _, v := range rows {
		if v.Scope == sc {
			out.DetectorIds = append(out.DetectorIds, api.DetectorId(v.ID))
		}
	}
	return out, nil
}
func (s *Service) updateDetector(tx Transaction, in *api.UpdateDetectorInput) (*api.UpdateDetectorOutput, error) {
	v, err := s.loadDetector(tx, value(in.DetectorId), "UpdateDetector")
	if err != nil {
		return nil, err
	}
	if in.Enable != nil {
		v.Status = "DISABLED"
		if bool(*in.Enable) {
			v.Status = "ENABLED"
		}
	}
	if in.FindingPublishingFrequency != nil {
		v.Frequency = value(in.FindingPublishingFrequency)
	}
	if err := validateFrequency(v.Frequency); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	if err := applyFeatures(&v, in.Features, in.DataSources, now); err != nil {
		return nil, err
	}
	v.Updated = now
	if err := tx.PutDetector(v); err != nil {
		return nil, err
	}
	return &api.UpdateDetectorOutput{}, nil
}
func (s *Service) deleteDetector(tx Transaction, in *api.DeleteDetectorInput) (*api.DeleteDetectorOutput, error) {
	v, err := s.loadDetector(tx, value(in.DetectorId), "DeleteDetector")
	if err != nil {
		return nil, err
	}
	lists, err := tx.IPLists(v.Scope, v.ID)
	if err != nil {
		return nil, err
	}
	for _, list := range lists {
		if list.Status == "DELETED" {
			continue
		}
		if s.ipLists == nil {
			return nil, failure("InternalServerErrorException", "GuardDuty IP list source is unavailable", 500)
		}
		if err := s.ipLists.DeletePolicy(tx.Context(), list); err != nil {
			return nil, err
		}
	}
	if err := tx.DeleteDetector(v.Scope, v.ID); err != nil {
		return nil, err
	}
	return &api.DeleteDetectorOutput{}, nil
}
func validateFrequency(v string) error {
	switch v {
	case "FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS":
		return nil
	default:
		return invalid("Invalid findingPublishingFrequency")
	}
}
