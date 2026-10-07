package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-securityconfiguration.html
type cfnGlueSecurityConfiguration struct{ commands StepFunctionsCommands }

func (h cfnGlueSecurityConfiguration) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "EncryptionConfiguration", "Name"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::SecurityConfiguration", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueSecurityConfiguration) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "EncryptionConfiguration"), h.Validate(b)
}
func (h cfnGlueSecurityConfiguration) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnAnalyticsContext(ctx, r, "glue", "SecurityConfiguration")
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(name, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := map[string]any{"EncryptionConfiguration": cfnGlueEncryptionInput(r.Properties["EncryptionConfiguration"])}
	input["Name"] = name
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateSecurityConfiguration", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(name, name, nil), nil
}
func (h cfnGlueSecurityConfiguration) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "EncryptionConfiguration", "Name") {
		return cloudformation.ResourceResult{}, fmt.Errorf("security configurations are immutable and require replacement")
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, nil), nil
}
func (h cfnGlueSecurityConfiguration) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnAnalyticsContext(ctx, r, "glue", "SecurityConfiguration")
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteSecurityConfiguration", map[string]any{"Name": name}))
}
func (h cfnGlueSecurityConfiguration) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", "SecurityConfiguration")
	out, err := cfnComputeCall[api.GetSecurityConfigurationOutput](ctx, h.commands, "glue", "GetSecurityConfiguration", map[string]any{"Name": name})
	if err != nil {
		return nil, err
	}
	p, err := cfnAnalyticsProject(out.SecurityConfiguration, "EncryptionConfiguration", "Name")
	if err == nil {
		if c, ok := cfnComputeObject(p["EncryptionConfiguration"]); ok {
			if v, found := c["S3Encryption"]; found {
				c["S3Encryptions"] = v
				delete(c, "S3Encryption")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}
func (h cfnGlueSecurityConfiguration) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.GetSecurityConfigurationsOutput](ctx, h.commands, "glue", "GetSecurityConfigurations", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.SecurityConfigurations {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["NextToken"] = out.NextToken
	}
	return cfnAnalyticsSort(rows), nil
}
