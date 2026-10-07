package integrations

import (
	"context"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-samlprovider.html
// Private keys remain write-only IAM inputs; no read model contains key material.
type cfnIAMSAML struct{ commands StepFunctionsCommands }

func (h cfnIAMSAML) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "SamlMetadataDocument", "Tags", "AssertionEncryptionMode", "AddPrivateKey", "RemovePrivateKey"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SamlMetadataDocument"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "SamlMetadataDocument", "AssertionEncryptionMode", "AddPrivateKey", "RemovePrivateKey"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnIAMSAML) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "AddPrivateKey", "RemovePrivateKey"), h.Validate(b)
}
func cfnIAMSAMLARN(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return "arn:" + r.Scope.Partition + ":iam::" + r.Scope.Account + ":saml-provider/" + cfnComputeName(r, "Name", 128)
}
func (h cfnIAMSAML) owned(ctx context.Context, r cloudformation.ResourceRequest, arn string) (*api.GetSAMLProviderOutput, error) {
	ctx = cfnIAMContext(ctx, r)
	out, err := cfnComputeCall[api.GetSAMLProviderOutput](ctx, h.commands, "iam", "GetSAMLProvider", map[string]any{"SAMLProviderArn": arn})
	return out, err
}
func cfnIAMSAMLResult(arn, uuid string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"Arn": arn, "SamlProviderUUID": uuid}}
}
func (h cfnIAMSAML) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnIAMSAMLARN(r)
	existing, err := h.owned(ctx, r, arn)
	if err == nil {
		return cfnIAMSAMLResult(arn, cfnComputeValue(existing.SAMLProviderUUID)), nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "AssertionEncryptionMode", "AddPrivateKey")
	in["Name"] = cfnComputeName(r, "Name", 128)
	in["SAMLMetadataDocument"] = r.Properties["SamlMetadataDocument"]
	in["Tags"] = cfnComputeTagList(cfnIAMCustomerTags(r))
	out, err := cfnComputeCall[api.CreateSAMLProviderOutput](ctx, h.commands, "iam", "CreateSAMLProvider", in)
	if err != nil {
		return cfnIAMCreationFailure(ctx, r, h, err)
	}
	arn = cfnComputeValue(out.SAMLProviderArn)
	result := cfnIAMSAMLResult(arn, "")
	if key := cfnComputeString(r.Properties, "RemovePrivateKey"); key != "" {
		if err := cfnComputeRun(ctx, h.commands, "iam", "UpdateSAMLProvider", map[string]any{"SAMLProviderArn": arn, "RemovePrivateKey": key}); err != nil {
			return result, err
		}
	}
	existing, err = h.owned(ctx, r, arn)
	if err != nil {
		return result, err
	}
	return cfnIAMSAMLResult(arn, cfnComputeValue(existing.SAMLProviderUUID)), nil
}
func (h cfnIAMSAML) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMSAMLResult(r.PhysicalID, cfnComputeValue(out.SAMLProviderUUID))
	in := map[string]any{"SAMLProviderArn": r.PhysicalID, "SAMLMetadataDocument": r.Properties["SamlMetadataDocument"], "AssertionEncryptionMode": cfnComputeDefault(r.Properties, "AssertionEncryptionMode", "Allowed")}
	if err := cfnComputeRun(ctx, h.commands, "iam", "UpdateSAMLProvider", in); err != nil {
		return result, err
	}
	return result, cfnIAMUpdateTags(ctx, h.commands, r, "SAMLProvider", "SAMLProviderArn", r.PhysicalID, cfnIAMTags(out.Tags))
}
func (h cfnIAMSAML) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnIAMContext(ctx, r)
	arn := cfnIAMSAMLARN(r)
	if _, err := h.owned(ctx, r, arn); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteSAMLProvider", map[string]any{"SAMLProviderArn": arn}))
}
func (h cfnIAMSAML) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(r.PhysicalID, "saml-provider/", 2)
	name := ""
	if len(parts) == 2 {
		name = parts[1]
	}
	return cloudformation.Properties{"Arn": r.PhysicalID, "Name": name, "SamlMetadataDocument": cfnComputeValue(out.SAMLMetadataDocument), "AssertionEncryptionMode": cfnComputeValue(out.AssertionEncryptionMode), "SamlProviderUUID": cfnComputeValue(out.SAMLProviderUUID), "Tags": cfnIAMUserTags(out.Tags)}, nil
}
func (h cfnIAMSAML) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out, err := cfnComputeCall[api.ListSAMLProvidersOutput](ctx, h.commands, "iam", "ListSAMLProviders", map[string]any{})
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, v := range out.SAMLProviderList {
		rr := r
		rr.PhysicalID = cfnComputeValue(v.Arn)
		p, e := h.Read(ctx, rr)
		if e != nil {
			if !r.CloudControl {
				continue
			}
			return nil, e
		}
		result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
	}
	return result, nil
}
