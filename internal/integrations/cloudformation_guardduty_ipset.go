package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/services/cloudformation"
)

type cfnGuardDutyIPSet struct{ c StepFunctionsCommands }

func (h cfnGuardDutyIPSet) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "DetectorId", "Name", "Location", "ExpectedBucketOwner", "Activate", "Format", "Tags"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "DetectorId", "Name", "Location", "Activate", "Format")
}
func (h cfnGuardDutyIPSet) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DetectorId", "Format"), nil
}
func (h cfnGuardDutyIPSet) load(ctx context.Context, r cloudformation.ResourceRequest) (*api.GetIPSetResponse, error) {
	d, id := cfnGuardKey(r)
	return cfnComputeCall[api.GetIPSetResponse](cfnGuardContext(ctx, r), h.c, "guardduty", "GetIPSet", map[string]any{"DetectorId": d, "IpSetId": id})
}
func (h cfnGuardDutyIPSet) result(r cloudformation.ResourceRequest) cloudformation.ResourceResult {
	_, id := cfnGuardKey(r)
	return cfnSecurityResult(r.PhysicalID, id, map[string]any{"Id": id})
}
func (h cfnGuardDutyIPSet) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnComputeCopy(r.Properties, "Name", "Location", "ExpectedBucketOwner", "Activate", "Format")
	d := cfnComputeString(r.Properties, "DetectorId")
	p["DetectorId"] = d
	p["ClientToken"] = cfnMessagingHash(r.Token)
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p["Tags"] = t
	o, e := cfnComputeCall[api.CreateIPSetResponse](ctx, h.c, "guardduty", "CreateIPSet", p)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = d + "|" + cfnComputeValue(o.IpSetId)
	_, e = h.load(ctx, r)
	return h.result(r), e
}
func (h cfnGuardDutyIPSet) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p := cfnComputeCopy(r.Properties, "Name", "Location", "ExpectedBucketOwner", "Activate")
	d, id := cfnGuardKey(r)
	p["DetectorId"] = d
	p["IpSetId"] = id
	if e = cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "UpdateIPSet", p); e != nil {
		return h.result(r), e
	}
	e = cfnGuardUpdateTags(ctx, h.c, r, cfnGuardARN(r, d, "ipset", id), v.Tags)
	return h.result(r), e
}
func (h cfnGuardDutyIPSet) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
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
	return cfnGuardAbsent(cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "DeleteIPSet", map[string]any{"DetectorId": d, "IpSetId": id}))
}
func (h cfnGuardDutyIPSet) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	p := cfnSecuritySelect(v, "Name", "Location", "ExpectedBucketOwner", "Format")
	d, id := cfnGuardKey(r)
	p["DetectorId"] = d
	p["Id"] = id
	p["Activate"] = cfnComputeValue(v.Status) == "ACTIVE" || cfnComputeValue(v.Status) == "ACTIVATING"
	if cfnComputeValue(v.Status) == "DELETED" {
		return nil, cfnSecurityNotFound()
	}
	p["Tags"] = cfnSecurityUserTags(v.Tags)
	return p, nil
}
func (h cfnGuardDutyIPSet) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
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
			o, e := cfnComputeCall[api.ListIPSetsResponse](ctx, h.c, "guardduty", "ListIPSets", in)
			if e != nil {
				return nil, e
			}
			for _, id := range o.IpSetIds {
				r.PhysicalID = d + "|" + string(id)
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

func (h cfnGuardDutyIPSet) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return false, e
	}
	switch cfnComputeValue(v.Status) {
	case "ACTIVE", "INACTIVE":
		return true, nil
	case "ERROR":
		return false, fmt.Errorf("GuardDuty source activation failed")
	case "DELETED":
		return false, cfnSecurityNotFound()
	default:
		return false, nil
	}
}
func (h cfnGuardDutyIPSet) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, e := h.load(ctx, r)
	if cfnGuardMissing(e) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	return cfnComputeValue(v.Status) == "DELETED", nil
}
