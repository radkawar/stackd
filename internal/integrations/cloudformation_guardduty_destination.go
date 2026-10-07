package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/services/cloudformation"
)

type cfnGuardDutyDestination struct{ c StepFunctionsCommands }

func (h cfnGuardDutyDestination) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "DetectorId", "DestinationType", "DestinationProperties", "Tags"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "DetectorId", "DestinationType", "DestinationProperties")
}
func (h cfnGuardDutyDestination) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DetectorId"), nil
}
func (h cfnGuardDutyDestination) load(ctx context.Context, r cloudformation.ResourceRequest) (*api.DescribePublishingDestinationResponse, error) {
	d, id := cfnGuardKey(r)
	return cfnComputeCall[api.DescribePublishingDestinationResponse](cfnGuardContext(ctx, r), h.c, "guardduty", "DescribePublishingDestination", map[string]any{"DetectorId": d, "DestinationId": id})
}
func (h cfnGuardDutyDestination) result(r cloudformation.ResourceRequest) cloudformation.ResourceResult {
	_, id := cfnGuardKey(r)
	return cfnSecurityResult(r.PhysicalID, id, map[string]any{"Id": id})
}
func (h cfnGuardDutyDestination) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnComputeCopy(r.Properties, "DestinationType", "DestinationProperties")
	d := cfnComputeString(r.Properties, "DetectorId")
	p["DetectorId"] = d
	p["ClientToken"] = cfnMessagingHash(r.Token)
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p["Tags"] = t
	o, e := cfnComputeCall[api.CreatePublishingDestinationResponse](ctx, h.c, "guardduty", "CreatePublishingDestination", p)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = d + "|" + cfnComputeValue(o.DestinationId)
	_, e = h.load(ctx, r)
	return h.result(r), e
}
func (h cfnGuardDutyDestination) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p := cfnComputeCopy(r.Properties, "DestinationProperties")
	d, id := cfnGuardKey(r)
	p["DetectorId"] = d
	p["DestinationId"] = id
	if e = cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "UpdatePublishingDestination", p); e != nil {
		return h.result(r), e
	}
	e = cfnGuardUpdateTags(ctx, h.c, r, cfnGuardARN(r, d, "publishingdestination", id), v.Tags)
	return h.result(r), e
}
func (h cfnGuardDutyDestination) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		res, e := h.RecoverCreation(ctx, r)
		if e != nil {
			return cfnGuardAbsent(e)
		}
		r.PhysicalID = res.PhysicalID
	}
	if _, e := h.load(ctx, r); e != nil {
		return cfnGuardAbsent(e)
	}
	d, id := cfnGuardKey(r)
	return cfnGuardAbsent(cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "DeletePublishingDestination", map[string]any{"DetectorId": d, "DestinationId": id}))
}
func (h cfnGuardDutyDestination) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	p := cfnSecuritySelect(v, "DestinationType", "DestinationProperties")
	d, id := cfnGuardKey(r)
	p["DetectorId"] = d
	p["Id"] = id
	p["Status"] = cfnComputeValue(v.Status)
	if v.PublishingFailureStartTimestamp != nil {
		p["PublishingFailureStartTimestamp"] = *v.PublishingFailureStartTimestamp
	}
	p["Tags"] = cfnSecurityUserTags(v.Tags)
	return p, nil
}
func (h cfnGuardDutyDestination) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ds, e := cfnGuardDetectors(ctx, h.c)
	if e != nil {
		return nil, e
	}
	out := []cloudformation.ResourceDescription{}
	for _, d := range ds {
		next := ""
		for {
			in := map[string]any{"DetectorId": d}
			if next != "" {
				in["NextToken"] = next
			}
			o, e := cfnComputeCall[api.ListPublishingDestinationsResponse](ctx, h.c, "guardduty", "ListPublishingDestinations", in)
			if e != nil {
				return nil, e
			}
			for _, id := range o.Destinations {
				r.PhysicalID = d + "|" + cfnComputeValue(id.DestinationId)
				p, e := h.Read(ctx, r)
				if e != nil {
					return nil, e
				}
				out = append(out, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
			}
			next = cfnComputeValue(o.NextToken)
			if next == "" {
				break
			}
		}
	}
	return out, nil
}
func (h cfnGuardDutyDestination) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return false, e
	}
	if cfnComputeValue(v.Status) == "PUBLISHING" {
		return true, nil
	}
	return false, fmt.Errorf("GuardDuty publishing destination is %s", cfnComputeValue(v.Status))
}
func (h cfnGuardDutyDestination) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	res := h.result(r)
	res.Attributes["Status"] = cfnComputeValue(v.Status)
	if v.PublishingFailureStartTimestamp != nil {
		res.Attributes["PublishingFailureStartTimestamp"] = *v.PublishingFailureStartTimestamp
	}
	return res, nil
}
