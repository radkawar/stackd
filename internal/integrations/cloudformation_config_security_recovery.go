package integrations

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	config "stackd/internal/services/configservice"
)

// A claim mismatch certifies only that this candidate is not the requested
// incarnation. Authorization/dependency errors never certify non-admission.
func cfnSecurityClaimMismatch(err error) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && wire.Message == "The control belongs to another resource incarnation."
}
func cfnSecurityCreateOwned(ctx context.Context, r cloudformation.ResourceRequest, create func(context.Context, cloudformation.ResourceRequest) (cloudformation.ResourceResult, error), recover func(context.Context, cloudformation.ResourceRequest) (cloudformation.ResourceResult, error)) (cloudformation.ResourceResult, error) {
	// Cloud Control CREATE also claims and observes the admitted incarnation.
	r.CloudControl = false
	result, err := create(ctx, r)
	if err != nil && result.PhysicalID == "" {
		if admitted, lookupErr := recover(ctx, r); lookupErr == nil {
			result = admitted
		}
	}
	return result, err
}
func (h cfnConfigRecorder) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnConfigCreateContext(ctx, r)
	ctx = config.WithRecorderStartOnCreate(ctx, r.Properties["StartedOnCreate"] != false && r.Properties["StartedOnCreate"] != "false")
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnConfigChannel) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnConfigCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnConfigRule) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnConfigCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnConfigAggregator) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnConfigCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnConfigAuthorization) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnConfigCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnGuardDutyDetector) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnGuardDutyFilter) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnGuardDutyIPSet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnGuardDutyThreatIntelSet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnGuardDutyDestination) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	return cfnSecurityCreateOwned(ctx, r, h.create, h.RecoverCreation)
}
func (h cfnConfigRecorder) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	v, err := h.load(cfnConfigCreateContext(ctx, r), r)
	if cfnSecurityMissing(err) || cfnSecurityClaimMismatch(err) {
		return cloudformation.ResourceResult{}, cfnSecurityNotFound()
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(v), nil
}
func (h cfnConfigChannel) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	v, err := h.load(cfnConfigCreateContext(ctx, r), r)
	if cfnSecurityMissing(err) || cfnSecurityClaimMismatch(err) {
		return cloudformation.ResourceResult{}, cfnSecurityNotFound()
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnSecurityResult(cfnComputeValue(v.Name), cfnComputeValue(v.Name), nil), nil
}
func (h cfnConfigRule) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	v, err := h.load(cfnConfigCreateContext(ctx, r), r)
	if cfnSecurityMissing(err) || cfnSecurityClaimMismatch(err) {
		return cloudformation.ResourceResult{}, cfnSecurityNotFound()
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(v), nil
}
func (h cfnConfigAggregator) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	v, err := h.load(cfnConfigCreateContext(ctx, r), r)
	if cfnSecurityMissing(err) || cfnSecurityClaimMismatch(err) {
		return cloudformation.ResourceResult{}, cfnSecurityNotFound()
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(v), nil
}
func (h cfnConfigAuthorization) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	v, err := h.load(cfnConfigCreateContext(ctx, r), r)
	if cfnSecurityMissing(err) || cfnSecurityClaimMismatch(err) {
		return cloudformation.ResourceResult{}, cfnSecurityNotFound()
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(v), nil
}
func (h cfnGuardDutyDetector) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	r.CloudControl = false
	ids, err := cfnGuardDetectors(ctx, h.c)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	for _, id := range ids {
		r.PhysicalID = id
		if _, err := h.load(ctx, r); err == nil {
			return h.result(id), nil
		} else if !cfnSecurityClaimMismatch(err) && !cfnGuardMissing(err) {
			return cloudformation.ResourceResult{}, err
		}
	}
	return cloudformation.ResourceResult{}, cfnSecurityNotFound()
}
func (h cfnGuardDutyFilter) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	r.CloudControl = false
	r.PhysicalID = cfnComputeString(r.Properties, "DetectorId") + "|" + cfnComputeString(r.Properties, "Name")
	_, err := h.load(ctx, r)
	if cfnGuardMissing(err) || cfnSecurityClaimMismatch(err) {
		return cloudformation.ResourceResult{}, cfnSecurityNotFound()
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(r), nil
}
func (h cfnGuardDutyIPSet) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	r.CloudControl = false
	detector := cfnComputeString(r.Properties, "DetectorId")
	next := ""
	for {
		in := map[string]any{"DetectorId": detector}
		if next != "" {
			in["NextToken"] = next
		}
		rows, err := cfnComputeCall[api.ListIPSetsResponse](ctx, h.c, "guardduty", "ListIPSets", in)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		for _, id := range rows.IpSetIds {
			r.PhysicalID = detector + "|" + string(id)
			if _, err := h.load(ctx, r); err == nil {
				return h.result(r), nil
			} else if !cfnSecurityClaimMismatch(err) && !cfnGuardMissing(err) {
				return cloudformation.ResourceResult{}, err
			}
		}
		next = cfnComputeValue(rows.NextToken)
		if next == "" {
			break
		}
	}
	return cloudformation.ResourceResult{}, cfnSecurityNotFound()
}
func (h cfnGuardDutyThreatIntelSet) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	r.CloudControl = false
	detector := cfnComputeString(r.Properties, "DetectorId")
	next := ""
	for {
		in := map[string]any{"DetectorId": detector}
		if next != "" {
			in["NextToken"] = next
		}
		rows, err := cfnComputeCall[api.ListThreatIntelSetsResponse](ctx, h.c, "guardduty", "ListThreatIntelSets", in)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		for _, id := range rows.ThreatIntelSetIds {
			r.PhysicalID = detector + "|" + string(id)
			if _, err := h.load(ctx, r); err == nil {
				return h.result(r), nil
			} else if !cfnSecurityClaimMismatch(err) && !cfnGuardMissing(err) {
				return cloudformation.ResourceResult{}, err
			}
		}
		next = cfnComputeValue(rows.NextToken)
		if next == "" {
			break
		}
	}
	return cloudformation.ResourceResult{}, cfnSecurityNotFound()
}
func (h cfnGuardDutyDestination) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnGuardCreateContext(ctx, r)
	r.CloudControl = false
	detector := cfnComputeString(r.Properties, "DetectorId")
	next := ""
	for {
		in := map[string]any{"DetectorId": detector}
		if next != "" {
			in["NextToken"] = next
		}
		rows, err := cfnComputeCall[api.ListPublishingDestinationsResponse](ctx, h.c, "guardduty", "ListPublishingDestinations", in)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		for _, id := range rows.Destinations {
			r.PhysicalID = detector + "|" + cfnComputeValue(id.DestinationId)
			if _, err := h.load(ctx, r); err == nil {
				return h.result(r), nil
			} else if !cfnSecurityClaimMismatch(err) && !cfnGuardMissing(err) {
				return cloudformation.ResourceResult{}, err
			}
		}
		next = cfnComputeValue(rows.NextToken)
		if next == "" {
			break
		}
	}
	return cloudformation.ResourceResult{}, cfnSecurityNotFound()
}
