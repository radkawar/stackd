package integrations

import (
	"context"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/services/cloudformation"
)

type cfnGuardDutyFilter struct{ c StepFunctionsCommands }

func (h cfnGuardDutyFilter) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "DetectorId", "Action", "Description", "FindingCriteria", "Rank", "Name", "Tags"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "DetectorId", "Name", "FindingCriteria")
}
func (h cfnGuardDutyFilter) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DetectorId", "Name"), nil
}
func (h cfnGuardDutyFilter) load(ctx context.Context, r cloudformation.ResourceRequest) (*api.GetFilterResponse, error) {
	d, id := cfnGuardKey(r)
	return cfnComputeCall[api.GetFilterResponse](cfnGuardContext(ctx, r), h.c, "guardduty", "GetFilter", map[string]any{"DetectorId": d, "FilterName": id})
}
func (h cfnGuardDutyFilter) result(r cloudformation.ResourceRequest) cloudformation.ResourceResult {
	_, id := cfnGuardKey(r)
	return cfnSecurityResult(r.PhysicalID, id, nil)
}
func (h cfnGuardDutyFilter) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnComputeCopy(r.Properties, "Action", "Description", "FindingCriteria", "Rank", "Name")
	d := cfnComputeString(r.Properties, "DetectorId")
	p["DetectorId"] = d
	p["ClientToken"] = cfnMessagingHash(r.Token)
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p["Tags"] = t
	o, e := cfnComputeCall[api.CreateFilterResponse](ctx, h.c, "guardduty", "CreateFilter", p)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = d + "|" + cfnComputeValue(o.Name)
	_, e = h.load(ctx, r)
	return h.result(r), e
}
func (h cfnGuardDutyFilter) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p := cfnComputeCopy(r.Properties, "Action", "Description", "FindingCriteria", "Rank")
	d, id := cfnGuardKey(r)
	p["DetectorId"] = d
	p["FilterName"] = id
	if p["Action"] == nil {
		p["Action"] = "NOOP"
	}
	if p["Description"] == nil {
		p["Description"] = ""
	}
	if p["Rank"] == nil {
		p["Rank"] = 1
	}
	if e = cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "UpdateFilter", p); e != nil {
		return h.result(r), e
	}
	e = cfnGuardUpdateTags(ctx, h.c, r, cfnGuardARN(r, d, "filter", id), v.Tags)
	return h.result(r), e
}
func (h cfnGuardDutyFilter) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
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
	return cfnGuardAbsent(cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "DeleteFilter", map[string]any{"DetectorId": d, "FilterName": id}))
}
func (h cfnGuardDutyFilter) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	p := cfnSecuritySelect(v, "Action", "Description", "FindingCriteria", "Rank")
	d, id := cfnGuardKey(r)
	p["DetectorId"] = d
	p["Name"] = id
	p["Tags"] = cfnSecurityUserTags(v.Tags)
	return p, nil
}
func (h cfnGuardDutyFilter) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
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
			o, e := cfnComputeCall[api.ListFiltersResponse](ctx, h.c, "guardduty", "ListFilters", in)
			if e != nil {
				return nil, e
			}
			for _, id := range o.FilterNames {
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
