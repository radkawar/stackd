package integrations

import (
	"context"
	api "stackd/internal/awsapi/configservice"
	"stackd/internal/services/cloudformation"
	"strings"
)

type cfnConfigAuthorization struct{ c StepFunctionsCommands }

func (h cfnConfigAuthorization) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "AuthorizedAccountId", "AuthorizedAwsRegion", "Tags"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "AuthorizedAccountId", "AuthorizedAwsRegion")
}
func (h cfnConfigAuthorization) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "AuthorizedAccountId", "AuthorizedAwsRegion"), nil
}
func cfnConfigAuthorizationKey(r cloudformation.ResourceRequest) (string, string) {
	if r.PhysicalID != "" {
		a, b, _ := strings.Cut(r.PhysicalID, "|")
		return a, b
	}
	return cfnComputeString(r.Properties, "AuthorizedAccountId"), cfnComputeString(r.Properties, "AuthorizedAwsRegion")
}
func (h cfnConfigAuthorization) load(ctx context.Context, r cloudformation.ResourceRequest) (api.AggregationAuthorization, error) {
	a, b := cfnConfigAuthorizationKey(r)
	next := ""
	for {
		in := map[string]any{}
		if next != "" {
			in["NextToken"] = next
		}
		o, e := cfnComputeCall[api.DescribeAggregationAuthorizationsOutput](ctx, h.c, "configservice", "DescribeAggregationAuthorizations", in)
		if e != nil {
			return api.AggregationAuthorization{}, e
		}
		for _, v := range o.AggregationAuthorizations {
			if cfnComputeValue(v.AuthorizedAccountId) == a && cfnComputeValue(v.AuthorizedAwsRegion) == b {
				if e := cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.AggregationAuthorizationArn)); e != nil {
					return api.AggregationAuthorization{}, e
				}
				return v, nil
			}
		}
		next = cfnComputeValue(o.NextToken)
		if next == "" {
			break
		}
	}
	return api.AggregationAuthorization{}, cfnSecurityNotFound()
}
func (h cfnConfigAuthorization) result(v api.AggregationAuthorization) cloudformation.ResourceResult {
	arn := cfnComputeValue(v.AggregationAuthorizationArn)
	return cfnSecurityResult(cfnComputeValue(v.AuthorizedAccountId)+"|"+cfnComputeValue(v.AuthorizedAwsRegion), arn, map[string]any{"AggregationAuthorizationArn": arn})
}
func (h cfnConfigAuthorization) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	a, b := cfnConfigAuthorizationKey(r)
	o, e := cfnComputeCall[api.PutAggregationAuthorizationOutput](cfnConfigContext(ctx, r), h.c, "configservice", "PutAggregationAuthorization", map[string]any{"AuthorizedAccountId": a, "AuthorizedAwsRegion": b, "Tags": cfnConfigTagInput(t)})
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return h.result(*o.AggregationAuthorization), nil
}
func (h cfnConfigAuthorization) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	arn := cfnComputeValue(v.AggregationAuthorizationArn)
	if e = cfnConfigOwned(ctx, h.c, r, arn); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return h.result(v), cfnConfigUpdateTags(ctx, h.c, r, arn)
}
func (h cfnConfigAuthorization) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, e := h.load(ctx, r)
	if e != nil {
		return cfnSecurityAbsent(e)
	}
	if e = cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.AggregationAuthorizationArn)); e != nil {
		return e
	}
	a, b := cfnConfigAuthorizationKey(r)
	return cfnSecurityAbsent(cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "DeleteAggregationAuthorization", map[string]any{"AuthorizedAccountId": a, "AuthorizedAwsRegion": b}))
}
func (h cfnConfigAuthorization) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	p := cfnSecuritySelect(v, "AuthorizedAccountId", "AuthorizedAwsRegion", "AggregationAuthorizationArn")
	t, e := cfnConfigTags(ctx, h.c, cfnComputeValue(v.AggregationAuthorizationArn))
	if e != nil {
		return nil, e
	}
	p["Tags"] = cfnSecurityUserTags(t)
	return p, nil
}
func (h cfnConfigAuthorization) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out := []cloudformation.ResourceDescription{}
	next := ""
	for {
		in := map[string]any{}
		if next != "" {
			in["NextToken"] = next
		}
		o, e := cfnComputeCall[api.DescribeAggregationAuthorizationsOutput](ctx, h.c, "configservice", "DescribeAggregationAuthorizations", in)
		if e != nil {
			return nil, e
		}
		for _, v := range o.AggregationAuthorizations {
			r.PhysicalID = cfnComputeValue(v.AuthorizedAccountId) + "|" + cfnComputeValue(v.AuthorizedAwsRegion)
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
	return out, nil
}
