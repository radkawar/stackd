package integrations

import (
	"context"
	"fmt"
	"stackd/internal/services/cloudformation"
)

func CloudFormationAPIGatewayV2DomainHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{"AWS::ApiGatewayV2::DomainName": cfnV2Domain{commands}, "AWS::ApiGatewayV2::ApiMapping": cfnV2Mapping{commands}}
}

type cfnV2Domain struct{ commands StepFunctionsCommands }
type cfnV2Mapping struct{ commands StepFunctionsCommands }

func (h cfnV2Domain) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "DomainName", "DomainNameConfigurations", "MutualTlsAuthentication", "RoutingMode", "Tags"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "DomainName"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "DomainName", "RoutingMode"); e != nil {
		return e
	}
	if mode := cfnComputeString(p, "RoutingMode"); mode != "" && mode != "API_MAPPING_ONLY" {
		return fmt.Errorf("only API_MAPPING_ONLY routing is supported")
	}
	if raw := p["DomainNameConfigurations"]; raw != nil {
		rows, ok := raw.([]any)
		if !ok || len(rows) != 1 {
			return fmt.Errorf("exactly one domain configuration is required")
		}
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("domain configuration must be an object")
			}
			if e := cfnComputeProperties(row, "CertificateArn", "CertificateName", "EndpointType", "SecurityPolicy", "OwnershipVerificationCertificateArn", "IpAddressType"); e != nil {
				return e
			}
			if e := cfnComputeStrings(row, "CertificateArn", "CertificateName", "EndpointType", "SecurityPolicy", "OwnershipVerificationCertificateArn", "IpAddressType"); e != nil {
				return e
			}
			if e := cfnComputeRequired(row, "CertificateArn"); e != nil {
				return e
			}
		}
	}
	if raw := p["MutualTlsAuthentication"]; raw != nil {
		row, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("MutualTlsAuthentication must be an object")
		}
		if e := cfnComputeProperties(row, "TruststoreUri", "TruststoreVersion"); e != nil {
			return e
		}
		if e := cfnComputeStrings(row, "TruststoreUri", "TruststoreVersion"); e != nil {
			return e
		}
	}
	_, e := cfnGatewayV2Tags(p)
	return e
}
func (h cfnV2Domain) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DomainName"), h.Validate(b)
}
func cfnV2DomainModel(out map[string]any) cloudformation.Properties {
	p := cfnGatewayV2Projection(out, map[string]any{}, "DomainName", "RoutingMode", "Tags", "DomainNameArn")
	configs := []any{}
	if rows, ok := out["DomainNameConfigurations"].([]any); ok {
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			configs = append(configs, cfnComputeCopy(row, "CertificateArn", "CertificateName", "EndpointType", "SecurityPolicy", "OwnershipVerificationCertificateArn", "IpAddressType"))
			if endpoint, ok := row["ApiGatewayDomainName"]; ok {
				p["RegionalDomainName"] = endpoint
			}
			if zone, ok := row["HostedZoneId"]; ok {
				p["RegionalHostedZoneId"] = zone
			}
		}
	}
	p["DomainNameConfigurations"] = configs
	if row, ok := out["MutualTlsAuthentication"].(map[string]any); ok {
		p["MutualTlsAuthentication"] = cfnComputeCopy(row, "TruststoreUri", "TruststoreVersion")
	}
	return p
}
func cfnV2DomainResult(out map[string]any) cloudformation.ResourceResult {
	name := cfnComputeString(out, "DomainName")
	p := cfnV2DomainModel(out)
	return cfnGatewayV2Result([]string{"DomainName"}, map[string]any{"DomainName": name}, name, cfnComputeCopy(p, "RegionalDomainName", "RegionalHostedZoneId", "DomainNameArn"))
}
func (h cfnV2Domain) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	in := cfnComputeCopy(r.Properties, "DomainName", "DomainNameConfigurations", "MutualTlsAuthentication", "RoutingMode")
	tags, e := cfnGatewayV2Tags(r.Properties)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	in["Tags"] = tags
	out, e := cfnGatewayV2Call(cfnGatewayV2Context(ctx, r), h.commands, "CreateDomainName", in)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnV2DomainResult(out), nil
}
func (h cfnV2Domain) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ids, e := cfnGatewayV2Identifier(r, "DomainName")
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	in := cfnComputeCopy(r.Properties, "DomainNameConfigurations", "MutualTlsAuthentication", "RoutingMode")
	in["DomainName"] = ids["DomainName"]
	if in["RoutingMode"] == nil {
		in["RoutingMode"] = "API_MAPPING_ONLY"
	}
	if in["MutualTlsAuthentication"] == nil && r.Previous["MutualTlsAuthentication"] != nil {
		in["MutualTlsAuthentication"] = map[string]any{"TruststoreUri": ""}
	}
	ctx = cfnGatewayV2Context(ctx, r)
	out, e := cfnGatewayV2Call(ctx, h.commands, "UpdateDomainName", in)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	result := cfnV2DomainResult(out)
	if e = cfnGatewayV2SyncTags(ctx, h.commands, r, "/domainnames/"+cfnComputeString(ids, "DomainName")); e != nil {
		return result, e
	}
	return result, nil
}
func (h cfnV2Domain) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, e := cfnGatewayV2Identifier(r, "DomainName")
	if e != nil {
		return e
	}
	_, e = cfnGatewayV2Call(cfnGatewayV2Context(ctx, r), h.commands, "DeleteDomainName", ids)
	return cfnGatewayV2Absent(e)
}
func (h cfnV2Domain) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, e := cfnGatewayV2Identifier(r, "DomainName")
	if e != nil {
		return nil, e
	}
	out, e := cfnGatewayV2Call(ctx, h.commands, "GetDomainName", ids)
	if e != nil {
		return nil, e
	}
	return cfnV2DomainModel(out), nil
}
func (h cfnV2Domain) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, e := cfnGatewayV2Pages(ctx, h.commands, "GetDomainNames", map[string]any{})
	if e != nil {
		return nil, e
	}
	result := []cloudformation.ResourceDescription{}
	for _, out := range rows {
		result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeString(out, "DomainName"), Properties: cfnV2DomainModel(out)})
	}
	return result, nil
}
func (h cfnV2Mapping) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "DomainName", "ApiId", "Stage", "ApiMappingKey"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "DomainName", "ApiId", "Stage"); e != nil {
		return e
	}
	return cfnComputeStrings(p, "DomainName", "ApiId", "Stage", "ApiMappingKey")
}
func (h cfnV2Mapping) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DomainName"), h.Validate(b)
}
func cfnV2MappingResult(out map[string]any, name string) cloudformation.ResourceResult {
	id := cfnComputeString(out, "ApiMappingId")
	return cfnGatewayV2Result([]string{"ApiMappingId", "DomainName"}, map[string]any{"DomainName": name, "ApiMappingId": id}, id, map[string]any{"ApiMappingId": id})
}
func (h cfnV2Mapping) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnGatewayV2Call(cfnGatewayV2Context(ctx, r), h.commands, "CreateApiMapping", map[string]any(r.Properties))
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnV2MappingResult(out, cfnComputeString(r.Properties, "DomainName")), nil
}
func (h cfnV2Mapping) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ids, e := cfnGatewayV2Identifier(r, "ApiMappingId", "DomainName")
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	in := cfnComputeCopy(r.Properties, "ApiId", "Stage", "ApiMappingKey")
	for k, v := range ids {
		in[k] = v
	}
	if in["ApiMappingKey"] == nil {
		in["ApiMappingKey"] = ""
	}
	out, e := cfnGatewayV2Call(cfnGatewayV2Context(ctx, r), h.commands, "UpdateApiMapping", in)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnV2MappingResult(out, cfnComputeString(ids, "DomainName")), nil
}
func (h cfnV2Mapping) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, e := cfnGatewayV2Identifier(r, "ApiMappingId", "DomainName")
	if e != nil {
		return e
	}
	_, e = cfnGatewayV2Call(cfnGatewayV2Context(ctx, r), h.commands, "DeleteApiMapping", ids)
	return cfnGatewayV2Absent(e)
}
func (h cfnV2Mapping) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, e := cfnGatewayV2Identifier(r, "ApiMappingId", "DomainName")
	if e != nil {
		return nil, e
	}
	out, e := cfnGatewayV2Call(ctx, h.commands, "GetApiMapping", ids)
	if e != nil {
		return nil, e
	}
	return cfnGatewayV2Projection(out, ids, "ApiId", "Stage", "ApiMappingKey"), nil
}
func (h cfnV2Mapping) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	domains, e := cfnGatewayV2Pages(ctx, h.commands, "GetDomainNames", map[string]any{})
	if e != nil {
		return nil, e
	}
	result := []cloudformation.ResourceDescription{}
	for _, domain := range domains {
		name := cfnComputeString(domain, "DomainName")
		rows, e := cfnGatewayV2Pages(ctx, h.commands, "GetApiMappings", map[string]any{"DomainName": name})
		if e != nil {
			return nil, e
		}
		for _, out := range rows {
			record := cfnV2MappingResult(out, name)
			result = append(result, cloudformation.ResourceDescription{Identifier: record.PhysicalID, Properties: cfnGatewayV2Projection(out, map[string]any{"DomainName": name}, "ApiMappingId", "ApiId", "Stage", "ApiMappingKey")})
		}
	}
	return result, nil
}
