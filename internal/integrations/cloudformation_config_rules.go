package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/configservice"
	"stackd/internal/services/cloudformation"
)

type cfnConfigRule struct{ c StepFunctionsCommands }

func (h cfnConfigRule) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "ConfigRuleName", "Description", "Scope", "MaximumExecutionFrequency", "Source", "InputParameters", "EvaluationModes"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "Source")
}
func (h cfnConfigRule) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ConfigRuleName"), nil
}
func (h cfnConfigRule) load(ctx context.Context, r cloudformation.ResourceRequest) (api.ConfigRule, error) {
	o, e := cfnComputeCall[api.DescribeConfigRulesOutput](ctx, h.c, "configservice", "DescribeConfigRules", map[string]any{"ConfigRuleNames": []string{cfnSecurityName(r, "ConfigRuleName")}})
	if e != nil {
		return api.ConfigRule{}, e
	}
	if len(o.ConfigRules) == 0 {
		return api.ConfigRule{}, cfnSecurityNotFound()
	}
	v := o.ConfigRules[0]
	if e := cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.ConfigRuleArn)); e != nil {
		return api.ConfigRule{}, e
	}
	return v, nil
}
func (h cfnConfigRule) result(v api.ConfigRule) cloudformation.ResourceResult {
	return cfnSecurityResult(cfnComputeValue(v.ConfigRuleName), cfnComputeValue(v.ConfigRuleName), map[string]any{"Arn": cfnComputeValue(v.ConfigRuleArn), "ConfigRuleId": cfnComputeValue(v.ConfigRuleId)})
}
func (h cfnConfigRule) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnComputeCopy(r.Properties, "Description", "Scope", "MaximumExecutionFrequency", "Source", "InputParameters", "EvaluationModes")
	name := cfnSecurityName(r, "ConfigRuleName")
	p["ConfigRuleName"] = name
	if v, ok := p["InputParameters"]; ok {
		doc, e := cfnComputeDocument(v)
		if e != nil {
			return cloudformation.ResourceResult{}, e
		}
		p["InputParameters"] = doc
	}
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if e = cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "PutConfigRule", map[string]any{"ConfigRule": p, "Tags": cfnConfigTagInput(t)}); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	v, e := h.load(ctx, r)
	if e != nil {
		return cfnSecurityResult(name, name, nil), e
	}
	return h.result(v), nil
}
func (h cfnConfigRule) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if e = cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.ConfigRuleArn)); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	res, e := h.create(ctx, r)
	if e != nil {
		return res, e
	}
	return res, e
}
func (h cfnConfigRule) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, e := h.load(ctx, r)
	if e != nil {
		return cfnSecurityAbsent(e)
	}
	if e = cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.ConfigRuleArn)); e != nil {
		return e
	}
	return cfnSecurityAbsent(cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "DeleteConfigRule", map[string]any{"ConfigRuleName": cfnSecurityName(r, "ConfigRuleName")}))
}
func (h cfnConfigRule) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	p := cfnSecuritySelect(v, "ConfigRuleName", "Description", "Scope", "MaximumExecutionFrequency", "Source", "InputParameters", "EvaluationModes")
	p["Arn"] = cfnComputeValue(v.ConfigRuleArn)
	p["ConfigRuleId"] = cfnComputeValue(v.ConfigRuleId)
	if v.InputParameters != nil {
		var parameters map[string]any
		if e := json.Unmarshal([]byte(*v.InputParameters), &parameters); e != nil {
			return nil, e
		}
		p["InputParameters"] = parameters
	}
	return p, nil
}
func (h cfnConfigRule) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out := []cloudformation.ResourceDescription{}
	next := ""
	for {
		in := map[string]any{}
		if next != "" {
			in["NextToken"] = next
		}
		o, e := cfnComputeCall[api.DescribeConfigRulesOutput](ctx, h.c, "configservice", "DescribeConfigRules", in)
		if e != nil {
			return nil, e
		}
		for _, v := range o.ConfigRules {
			r.PhysicalID = cfnComputeValue(v.ConfigRuleName)
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

type cfnConfigAggregator struct{ c StepFunctionsCommands }

func (h cfnConfigAggregator) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "ConfigurationAggregatorName", "AccountAggregationSources", "OrganizationAggregationSource", "Tags"); e != nil {
		return e
	}
	if p["OrganizationAggregationSource"] != nil {
		return fmt.Errorf("organization aggregation has no implemented owner")
	}
	return cfnComputeRequired(p, "AccountAggregationSources")
}
func (h cfnConfigAggregator) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ConfigurationAggregatorName"), nil
}
func (h cfnConfigAggregator) load(ctx context.Context, r cloudformation.ResourceRequest) (api.ConfigurationAggregator, error) {
	o, e := cfnComputeCall[api.DescribeConfigurationAggregatorsOutput](ctx, h.c, "configservice", "DescribeConfigurationAggregators", map[string]any{"ConfigurationAggregatorNames": []string{cfnSecurityName(r, "ConfigurationAggregatorName")}})
	if e != nil {
		return api.ConfigurationAggregator{}, e
	}
	if len(o.ConfigurationAggregators) == 0 {
		return api.ConfigurationAggregator{}, cfnSecurityNotFound()
	}
	v := o.ConfigurationAggregators[0]
	if e := cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.ConfigurationAggregatorArn)); e != nil {
		return api.ConfigurationAggregator{}, e
	}
	return v, nil
}
func (h cfnConfigAggregator) result(v api.ConfigurationAggregator) cloudformation.ResourceResult {
	return cfnSecurityResult(cfnComputeValue(v.ConfigurationAggregatorName), cfnComputeValue(v.ConfigurationAggregatorName), map[string]any{"ConfigurationAggregatorArn": cfnComputeValue(v.ConfigurationAggregatorArn)})
}
func (h cfnConfigAggregator) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnComputeCopy(r.Properties, "AccountAggregationSources", "OrganizationAggregationSource")
	name := cfnSecurityName(r, "ConfigurationAggregatorName")
	p["ConfigurationAggregatorName"] = name
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p["Tags"] = cfnConfigTagInput(t)
	if e = cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "PutConfigurationAggregator", p); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	v, e := h.load(ctx, r)
	if e != nil {
		return cfnSecurityResult(name, name, nil), e
	}
	return h.result(v), nil
}
func (h cfnConfigAggregator) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if e = cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.ConfigurationAggregatorArn)); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	res, e := h.create(ctx, r)
	if e != nil {
		return res, e
	}
	e = cfnConfigUpdateTags(ctx, h.c, r, cfnComputeValue(v.ConfigurationAggregatorArn))
	return res, e
}
func (h cfnConfigAggregator) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, e := h.load(ctx, r)
	if e != nil {
		return cfnSecurityAbsent(e)
	}
	if e = cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.ConfigurationAggregatorArn)); e != nil {
		return e
	}
	return cfnSecurityAbsent(cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "DeleteConfigurationAggregator", map[string]any{"ConfigurationAggregatorName": cfnSecurityName(r, "ConfigurationAggregatorName")}))
}
func (h cfnConfigAggregator) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	p := cfnSecuritySelect(v, "ConfigurationAggregatorName", "AccountAggregationSources", "OrganizationAggregationSource")
	p["ConfigurationAggregatorArn"] = cfnComputeValue(v.ConfigurationAggregatorArn)
	t, e := cfnConfigTags(ctx, h.c, cfnComputeValue(v.ConfigurationAggregatorArn))
	if e != nil {
		return nil, e
	}
	p["Tags"] = cfnSecurityUserTags(t)
	return p, nil
}
func (h cfnConfigAggregator) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out := []cloudformation.ResourceDescription{}
	next := ""
	for {
		in := map[string]any{}
		if next != "" {
			in["NextToken"] = next
		}
		o, e := cfnComputeCall[api.DescribeConfigurationAggregatorsOutput](ctx, h.c, "configservice", "DescribeConfigurationAggregators", in)
		if e != nil {
			return nil, e
		}
		for _, v := range o.ConfigurationAggregators {
			r.PhysicalID = cfnComputeValue(v.ConfigurationAggregatorName)
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
