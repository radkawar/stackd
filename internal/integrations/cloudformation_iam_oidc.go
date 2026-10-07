package integrations

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-oidcprovider.html
type cfnIAMOIDC struct{ commands StepFunctionsCommands }

func (h cfnIAMOIDC) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Url", "ClientIdList", "ThumbprintList", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Url"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Url"); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "ClientIdList"); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "ThumbprintList"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnIAMOIDC) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Url"), h.Validate(b)
}
func cfnIAMOIDCARN(r cloudformation.ResourceRequest) (string, error) {
	if r.PhysicalID != "" {
		return r.PhysicalID, nil
	}
	u, err := url.Parse(cfnComputeString(r.Properties, "Url"))
	if err != nil || u.Hostname() == "" || u.Scheme != "https" {
		return "", fmt.Errorf("url must be an HTTPS issuer URL")
	}
	return "arn:" + r.Scope.Partition + ":iam::" + r.Scope.Account + ":oidc-provider/" + u.Hostname() + u.EscapedPath(), nil
}
func (h cfnIAMOIDC) owned(ctx context.Context, r cloudformation.ResourceRequest, arn string) (*api.GetOpenIDConnectProviderOutput, error) {
	ctx = cfnIAMContext(ctx, r)
	out, err := cfnComputeCall[api.GetOpenIDConnectProviderOutput](ctx, h.commands, "iam", "GetOpenIDConnectProvider", map[string]any{"OpenIDConnectProviderArn": arn})
	return out, err
}
func cfnIAMOIDCResult(arn string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"Arn": arn}}
}
func (h cfnIAMOIDC) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn, err := cfnIAMOIDCARN(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	_, err = h.owned(ctx, r, arn)
	if err == nil {
		return cfnIAMOIDCResult(arn), nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Url", "ThumbprintList")
	if clients, ok := r.Properties["ClientIdList"]; ok {
		in["ClientIDList"] = clients
	}
	in["Tags"] = cfnComputeTagList(cfnIAMCustomerTags(r))
	out, err := cfnComputeCall[api.CreateOpenIDConnectProviderOutput](ctx, h.commands, "iam", "CreateOpenIDConnectProvider", in)
	if err != nil {
		return cfnIAMCreationFailure(ctx, r, h, err)
	}
	return cfnIAMOIDCResult(cfnComputeValue(out.OpenIDConnectProviderArn)), nil
}
func (h cfnIAMOIDC) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMOIDCResult(r.PhysicalID)
	desired, _ := cfnComputeStringList(r.Properties, "ClientIdList")
	current := []string{}
	for _, id := range out.ClientIDList {
		current = append(current, string(id))
	}
	for _, id := range desired {
		if !slices.Contains(current, id) {
			if err := cfnComputeRun(ctx, h.commands, "iam", "AddClientIDToOpenIDConnectProvider", map[string]any{"OpenIDConnectProviderArn": r.PhysicalID, "ClientID": id}); err != nil {
				return result, err
			}
		}
	}
	for _, id := range current {
		if !slices.Contains(desired, id) {
			if err := cfnComputeRun(ctx, h.commands, "iam", "RemoveClientIDFromOpenIDConnectProvider", map[string]any{"OpenIDConnectProviderArn": r.PhysicalID, "ClientID": id}); err != nil {
				return result, err
			}
		}
	}
	if prints, ok := r.Properties["ThumbprintList"]; ok {
		if err := cfnComputeRun(ctx, h.commands, "iam", "UpdateOpenIDConnectProviderThumbprint", map[string]any{"OpenIDConnectProviderArn": r.PhysicalID, "ThumbprintList": prints}); err != nil {
			return result, err
		}
	}
	return result, cfnIAMUpdateTags(ctx, h.commands, r, "OpenIDConnectProvider", "OpenIDConnectProviderArn", r.PhysicalID, cfnIAMTags(out.Tags))
}
func (h cfnIAMOIDC) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnIAMContext(ctx, r)
	arn, err := cfnIAMOIDCARN(r)
	if err != nil {
		return err
	}
	if _, err := h.owned(ctx, r, arn); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteOpenIDConnectProvider", map[string]any{"OpenIDConnectProviderArn": arn}))
}
func (h cfnIAMOIDC) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	clients := []string{}
	prints := []string{}
	for _, v := range out.ClientIDList {
		clients = append(clients, string(v))
	}
	for _, v := range out.ThumbprintList {
		prints = append(prints, string(v))
	}
	return cloudformation.Properties{"Arn": r.PhysicalID, "Url": "https://" + cfnComputeValue(out.Url), "ClientIdList": clients, "ThumbprintList": prints, "Tags": cfnIAMUserTags(out.Tags)}, nil
}
func (h cfnIAMOIDC) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out, err := cfnComputeCall[api.ListOpenIDConnectProvidersOutput](ctx, h.commands, "iam", "ListOpenIDConnectProviders", map[string]any{})
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, v := range out.OpenIDConnectProviderList {
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
