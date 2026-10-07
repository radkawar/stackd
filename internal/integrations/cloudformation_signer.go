package integrations

import (
	"context"
	"fmt"
	"strings"

	signerapi "stackd/internal/awsapi/signer"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/signer"
)

// AWS::Signer::SigningProfile
// Contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-signer-signingprofile.html
// Wire: https://docs.aws.amazon.com/signer/latest/api/API_PutSigningProfile.html
// Deletion cancels the profile (https://docs.aws.amazon.com/signer/latest/api/API_CancelSigningProfile.html);
// the Signer owner retains canceled profiles and their signing authority for
// signatures already issued, and refuses to reuse the name.
type cfnSignerProfile struct{ commands StepFunctionsCommands }

const cfnSignerLambdaPlatform = "AWSLambda-SHA384-ECDSA"

func (cfnSignerProfile) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PlatformId", "ProfileName", "SignatureValidityPeriod", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "PlatformId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "PlatformId", "ProfileName"); err != nil {
		return err
	}
	if cfnComputeString(p, "PlatformId") != cfnSignerLambdaPlatform {
		return fmt.Errorf("PlatformId must be %s; other signing platforms have no owner", cfnSignerLambdaPlatform)
	}
	if _, err := cfnSignerValidity(p); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func cfnSignerValidity(p map[string]any) (*signerapi.SignatureValidityPeriod, error) {
	if p["SignatureValidityPeriod"] == nil {
		return nil, nil
	}
	period, ok := cfnComputeObject(p["SignatureValidityPeriod"])
	if !ok {
		return nil, fmt.Errorf("SignatureValidityPeriod must be an object")
	}
	if err := cfnComputeProperties(period, "Type", "Value"); err != nil {
		return nil, fmt.Errorf("SignatureValidityPeriod: %w", err)
	}
	if err := cfnComputeRequired(period, "Type", "Value"); err != nil {
		return nil, fmt.Errorf("SignatureValidityPeriod: %w", err)
	}
	if err := cfnComputeStrings(period, "Type"); err != nil {
		return nil, err
	}
	value, err := cfnTrustInt(period["Value"], "SignatureValidityPeriod.Value")
	if err != nil {
		return nil, err
	}
	return &signerapi.SignatureValidityPeriod{Type: new(signerapi.ValidityType(cfnComputeString(period, "Type"))), Value: new(signerapi.Integer(value))}, nil
}
func (h cfnSignerProfile) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "ProfileName", "PlatformId", "SignatureValidityPeriod"), nil
}

// cfnSignerName generates a profile name within the documented [0-9a-zA-Z_]{2,64}.
func cfnSignerName(r cloudformation.ResourceRequest) string {
	if name := cfnComputeString(r.Properties, "ProfileName"); name != "" {
		return name
	}
	var safe strings.Builder
	for _, ch := range r.StackName + "_" + r.LogicalID {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' {
			safe.WriteRune(ch)
		}
	}
	prefix := safe.String()
	if len(prefix) > 39 {
		prefix = prefix[:39]
	}
	return prefix + "_" + cfnComputeHash(r.StackID+"/"+r.LogicalID+"/"+r.Token)
}
func cfnSignerProfileName(ctx context.Context, arn string) (string, error) {
	metadata := awsctx.FromContext(ctx)
	prefix := "arn:" + metadata.Partition + ":signer:" + metadata.Region + ":" + metadata.AccountID + ":/signing-profiles/"
	if metadata.Partition == "" || metadata.Region == "" || metadata.AccountID == "" || !strings.HasPrefix(arn, prefix) {
		return "", cfnTrustNotFound("signing profile ARN is outside the request scope")
	}
	name := strings.TrimPrefix(arn, prefix)
	if name == "" || strings.ContainsAny(name, "/:") {
		return "", fmt.Errorf("invalid signing profile ARN %q", arn)
	}
	return name, nil
}
func (h cfnSignerProfile) get(ctx context.Context, name string) (*signerapi.GetSigningProfileOutput, error) {
	return cfnTrustTyped[signerapi.GetSigningProfileOutput](ctx, h.commands, "signer", "GetSigningProfile", &signerapi.GetSigningProfileInput{ProfileName: new(signerapi.ProfileName(name))})
}
func cfnSignerTags(tags signerapi.TagMap) map[string]string {
	out := make(map[string]string, len(tags))
	for key, value := range tags {
		out[string(key)] = string(value)
	}
	return out
}
func cfnSignerTagMap(tags map[string]string) signerapi.TagMap {
	out := make(signerapi.TagMap, len(tags))
	for key, value := range tags {
		out[signerapi.TagKey(key)] = signerapi.TagValue(value)
	}
	return out
}
func cfnSignerResult(p *signerapi.GetSigningProfileOutput) cloudformation.ResourceResult {
	arn := cfnComputeValue(p.Arn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"Arn": arn, "ProfileName": cfnComputeValue(p.ProfileName), "ProfileVersion": cfnComputeValue(p.ProfileVersion), "ProfileVersionArn": cfnComputeValue(p.ProfileVersionArn)}}
}
func cfnTrustCustomerTags(r cloudformation.ResourceRequest) map[string]string {
	tags, _ := cfnComputeTags(r.Properties)
	for key, value := range r.Tags {
		if !strings.HasPrefix(strings.ToLower(key), cfnComputeTagPrefix) {
			if _, exists := tags[key]; !exists {
				tags[key] = value
			}
		}
	}
	return tags
}
func cfnSignerOwnership(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return signer.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "signerprofile"), true, nil)
}
func (h cfnSignerProfile) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	rows := map[string]string{}
	p, err := h.get(signer.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "signerprofile"), true, rows), cfnSignerName(r))
	if err != nil {
		for arn := range rows {
			return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"Arn": arn, "ProfileName": cfnSignerName(r)}}, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnSignerResult(p), nil
}
func (h cfnSignerProfile) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnSignerName(r)
	ctx = signer.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "signerprofile"), true, nil)
	existing, err := h.get(ctx, name)
	if err == nil {
		if cfnComputeValue(existing.Status) != "Active" {
			return cfnSignerResult(existing), fmt.Errorf("signing profile %s for this incarnation is %s", name, cfnComputeValue(existing.Status))
		}
		return cfnSignerResult(existing), nil
	}
	if !cfnComputeMissing(err) {
		if recovered, _ := h.RecoverCreation(ctx, r); recovered.PhysicalID != "" {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	validity, _ := cfnSignerValidity(r.Properties)
	in := &signerapi.PutSigningProfileInput{ProfileName: new(signerapi.ProfileName(name)), PlatformId: new(signerapi.PlatformId(cfnSignerLambdaPlatform)), SignatureValidityPeriod: validity, Tags: cfnSignerTagMap(cfnTrustCustomerTags(r))}
	admitted, err := cfnTrustTyped[signerapi.PutSigningProfileOutput](ctx, h.commands, "signer", "PutSigningProfile", in)
	if err != nil {
		// An error response may have been lost after admission. Only recover
		// the exact incarnation, never an unrelated profile with this name.
		if recovered, _ := h.RecoverCreation(ctx, r); recovered.PhysicalID != "" {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnComputeValue(admitted.Arn)
	result := cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"Arn": arn, "ProfileName": name, "ProfileVersion": cfnComputeValue(admitted.ProfileVersion), "ProfileVersionArn": cfnComputeValue(admitted.ProfileVersionArn)}}
	created, err := h.get(ctx, name)
	if err != nil {
		return result, err
	}
	return cfnSignerResult(created), nil
}

// current returns the active profile; canceled profiles no longer exist for CloudFormation.
func (h cfnSignerProfile) current(ctx context.Context, r cloudformation.ResourceRequest) (*signerapi.GetSigningProfileOutput, error) {
	name, err := cfnSignerProfileName(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	if cfnComputeValue(p.Arn) != r.PhysicalID {
		return nil, cfnTrustNotFound("signing profile ARN does not identify the current native profile")
	}
	if cfnComputeValue(p.Status) == "Canceled" {
		return nil, cfnTrustNotFound("signing profile " + name + " is canceled")
	}
	return p, nil
}
func (h cfnSignerProfile) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::Signer::SigningProfile", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSignerOwnership(ctx, r)
	p, err := h.current(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	current := cfnSignerTags(p.Tags)
	desired := cfnTrustCustomerTags(r)
	arn := cfnComputeValue(p.Arn)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		keys := make(signerapi.TagKeyList, 0, len(removed))
		for _, key := range removed {
			keys = append(keys, signerapi.TagKey(key))
		}
		if _, err := cfnTrustTyped[signerapi.UntagResourceOutput](ctx, h.commands, "signer", "UntagResource", &signerapi.UntagResourceInput{ResourceArn: new(signerapi.String(arn)), TagKeys: keys}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if len(desired) > 0 {
		if _, err := cfnTrustTyped[signerapi.TagResourceOutput](ctx, h.commands, "signer", "TagResource", &signerapi.TagResourceInput{ResourceArn: new(signerapi.String(arn)), Tags: cfnSignerTagMap(desired)}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	return cfnSignerResult(p), nil
}
func (h cfnSignerProfile) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnSignerOwnership(ctx, r)
	p, err := h.current(ctx, r)
	if err != nil {
		if r.CloudControl {
			return err
		}
		return cfnComputeAbsent(err)
	}
	return cfnComputeRun(ctx, h.commands, "signer", "CancelSigningProfile", map[string]any{"ProfileName": cfnComputeValue(p.ProfileName)})
}
func cfnSignerProperties(arn, name, version, versionARN, platform string, validity *signerapi.SignatureValidityPeriod, tags map[string]string) cloudformation.Properties {
	p := cloudformation.Properties{"Arn": arn, "ProfileName": name, "ProfileVersion": version, "ProfileVersionArn": versionARN, "PlatformId": platform}
	if validity != nil {
		p["SignatureValidityPeriod"] = map[string]any{"Type": cfnComputeValue(validity.Type), "Value": int64(cfnSignerInteger(validity.Value))}
	}
	if public := cfnResourcePublicTags(tags); len(public) > 0 {
		p["Tags"] = public
	}
	return p
}
func cfnSignerInteger(v *signerapi.Integer) signerapi.Integer {
	if v == nil {
		return 0
	}
	return *v
}
func (h cfnSignerProfile) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	r.CloudControl = true
	p, err := h.current(ctx, r)
	if err != nil {
		return nil, err
	}
	return cfnSignerProperties(cfnComputeValue(p.Arn), cfnComputeValue(p.ProfileName), cfnComputeValue(p.ProfileVersion), cfnComputeValue(p.ProfileVersionArn), cfnComputeValue(p.PlatformId), p.SignatureValidityPeriod, cfnSignerTags(p.Tags)), nil
}
func (h cfnSignerProfile) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	in := &signerapi.ListSigningProfilesInput{}
	for {
		page, err := cfnTrustTyped[signerapi.ListSigningProfilesOutput](ctx, h.commands, "signer", "ListSigningProfiles", in)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Profiles {
			arn := cfnComputeValue(p.Arn)
			out = append(out, cloudformation.ResourceDescription{Identifier: arn, Properties: cfnSignerProperties(arn, cfnComputeValue(p.ProfileName), cfnComputeValue(p.ProfileVersion), cfnComputeValue(p.ProfileVersionArn), cfnComputeValue(p.PlatformId), p.SignatureValidityPeriod, cfnSignerTags(p.Tags))})
		}
		if page.NextToken == nil || cfnComputeValue(page.NextToken) == "" {
			return out, nil
		}
		in = &signerapi.ListSigningProfilesInput{NextToken: page.NextToken}
	}
}
