package integrations

import (
	"context"
	"fmt"
	"strings"

	sesapi "stackd/internal/awsapi/sesv2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sesv2"
)

// AWS::SES::EmailIdentity and AWS::SES::ConfigurationSet use the SES v2 owner.
// Contracts: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-emailidentity.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-configurationset.html
// Wire: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateEmailIdentity.html
// https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateConfigurationSet.html
// Email address identities complete verification only when the recipient opens
// the link in the owner's captured verification message; as on AWS, creation
// does not wait for verification. Mail is captured locally, never sent.

func cfnSESMissing(err error) bool {
	return cfnTrustCode(err) == "NotFoundException" || cfnComputeMissing(err)
}
func cfnSESAbsent(r cloudformation.ResourceRequest, err error) error {
	if !r.CloudControl && cfnSESMissing(err) {
		return nil
	}
	return err
}
func cfnSESOwnership(ctx context.Context, r cloudformation.ResourceRequest, kind string) context.Context {
	if r.CloudControl {
		return ctx
	}
	return sesv2.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, kind), true, nil)
}
func cfnSESARN(r cloudformation.ResourceRequest, kind, name string) string {
	return "arn:" + r.Scope.Partition + ":ses:" + r.Scope.Region + ":" + r.Scope.Account + ":" + kind + "/" + name
}
func cfnSESTags(tags sesapi.TagList) map[string]string {
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		out[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return out
}
func cfnSESTagList(tags map[string]string) sesapi.TagList {
	out := make(sesapi.TagList, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		out = append(out, sesapi.Tag{Key: new(sesapi.TagKey(key)), Value: new(sesapi.TagValue(tags[key]))})
	}
	return out
}

// cfnSESRetag converges customer tags; private claims never travel through tags.
func cfnSESRetag(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnTrustCustomerTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		keys := make(sesapi.TagKeyList, 0, len(removed))
		for _, key := range removed {
			keys = append(keys, sesapi.TagKey(key))
		}
		if _, err := cfnTrustTyped[sesapi.UntagResourceOutput](ctx, c, "sesv2", "UntagResource", &sesapi.UntagResourceInput{ResourceArn: new(sesapi.AmazonResourceName(arn)), TagKeys: keys}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	_, err := cfnTrustTyped[sesapi.TagResourceOutput](ctx, c, "sesv2", "TagResource", &sesapi.TagResourceInput{ResourceArn: new(sesapi.AmazonResourceName(arn)), Tags: cfnSESTagList(desired)})
	return err
}

type cfnSESEmailIdentity struct{ commands StepFunctionsCommands }

func (cfnSESEmailIdentity) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "EmailIdentity", "ConfigurationSetAttributes", "DkimSigningAttributes", "DkimAttributes", "MailFromAttributes", "FeedbackAttributes", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "EmailIdentity"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "EmailIdentity"); err != nil {
		return err
	}
	if !strings.Contains(cfnComputeString(p, "EmailIdentity"), "@") {
		return fmt.Errorf("domain identities require DKIM and DNS verification owners; specify an email address")
	}
	for _, key := range []string{"DkimSigningAttributes", "DkimAttributes", "MailFromAttributes"} {
		if cfnTrustPresent(p, key) {
			return fmt.Errorf("%s has no SES owner", key)
		}
	}
	if p["FeedbackAttributes"] != nil {
		feedback, ok := cfnComputeObject(p["FeedbackAttributes"])
		if !ok {
			return fmt.Errorf("FeedbackAttributes must be an object")
		}
		if err := cfnComputeProperties(feedback, "EmailForwardingEnabled"); err != nil {
			return fmt.Errorf("FeedbackAttributes: %w", err)
		}
		if v, ok := feedback["EmailForwardingEnabled"]; ok && v != nil {
			enabled, err := cfnTrustBool(v, "FeedbackAttributes.EmailForwardingEnabled")
			if err != nil {
				return err
			}
			if !enabled {
				return fmt.Errorf("disabling feedback forwarding requires bounce and complaint notification owners")
			}
		}
	}
	if _, err := cfnSESIdentityConfiguration(p); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func cfnSESIdentityConfiguration(p map[string]any) (string, error) {
	if p["ConfigurationSetAttributes"] == nil {
		return "", nil
	}
	attributes, ok := cfnComputeObject(p["ConfigurationSetAttributes"])
	if !ok {
		return "", fmt.Errorf("ConfigurationSetAttributes must be an object")
	}
	if err := cfnComputeProperties(attributes, "ConfigurationSetName"); err != nil {
		return "", fmt.Errorf("ConfigurationSetAttributes: %w", err)
	}
	if err := cfnComputeStrings(attributes, "ConfigurationSetName"); err != nil {
		return "", err
	}
	return cfnComputeString(attributes, "ConfigurationSetName"), nil
}
func (h cfnSESEmailIdentity) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeString(a, "EmailIdentity") != cfnComputeString(b, "EmailIdentity"), nil
}
func (h cfnSESEmailIdentity) get(ctx context.Context, name string) (*sesapi.GetEmailIdentityOutput, error) {
	return cfnTrustTyped[sesapi.GetEmailIdentityOutput](ctx, h.commands, "sesv2", "GetEmailIdentity", &sesapi.GetEmailIdentityInput{EmailIdentity: new(sesapi.Identity(name))})
}
func (h cfnSESEmailIdentity) configure(ctx context.Context, name string, current *sesapi.GetEmailIdentityOutput, p map[string]any) error {
	desired, _ := cfnSESIdentityConfiguration(p)
	if cfnComputeValue(current.ConfigurationSetName) == desired {
		return nil
	}
	in := &sesapi.PutEmailIdentityConfigurationSetAttributesInput{EmailIdentity: new(sesapi.Identity(name))}
	if desired != "" {
		in.ConfigurationSetName = new(sesapi.ConfigurationSetName(desired))
	}
	_, err := cfnTrustTyped[sesapi.PutEmailIdentityConfigurationSetAttributesOutput](ctx, h.commands, "sesv2", "PutEmailIdentityConfigurationSetAttributes", in)
	return err
}
func (h cfnSESEmailIdentity) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeString(r.Properties, "EmailIdentity")
	rows := map[string]string{}
	_, err := h.get(sesv2.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "sesidentity"), true, rows), name)
	if err != nil && len(rows) == 0 {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{}}, err
}
func (h cfnSESEmailIdentity) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "EmailIdentity")
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{}}
	ctx = sesv2.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "sesidentity"), true, nil)
	existing, err := h.get(ctx, name)
	if err == nil {
		return result, h.configure(ctx, name, existing, r.Properties)
	}
	if !cfnSESMissing(err) {
		if admitted, _ := h.RecoverCreation(ctx, r); admitted.PhysicalID != "" {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	in := &sesapi.CreateEmailIdentityInput{EmailIdentity: new(sesapi.Identity(name)), Tags: cfnSESTagList(cfnTrustCustomerTags(r))}
	if config, _ := cfnSESIdentityConfiguration(r.Properties); config != "" {
		in.ConfigurationSetName = new(sesapi.ConfigurationSetName(config))
	}
	_, err = cfnTrustTyped[sesapi.CreateEmailIdentityOutput](ctx, h.commands, "sesv2", "CreateEmailIdentity", in)
	if err != nil {
		if admitted, _ := h.RecoverCreation(ctx, r); admitted.PhysicalID != "" {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return result, nil
}
func (h cfnSESEmailIdentity) current(ctx context.Context, r cloudformation.ResourceRequest) (*sesapi.GetEmailIdentityOutput, error) {
	identity, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return identity, nil
}
func (h cfnSESEmailIdentity) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SES::EmailIdentity", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSESOwnership(ctx, r, "sesidentity")
	identity, err := h.current(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.configure(ctx, r.PhysicalID, identity, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnSESRetag(ctx, h.commands, r, cfnSESARN(r, "identity", r.PhysicalID), cfnSESTags(identity.Tags)); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{}}, nil
}
func (h cfnSESEmailIdentity) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnSESOwnership(ctx, r, "sesidentity")
	if _, err := h.current(ctx, r); err != nil {
		return cfnSESAbsent(r, err)
	}
	_, err := cfnTrustTyped[sesapi.DeleteEmailIdentityOutput](ctx, h.commands, "sesv2", "DeleteEmailIdentity", &sesapi.DeleteEmailIdentityInput{EmailIdentity: new(sesapi.Identity(r.PhysicalID))})
	return cfnSESAbsent(r, err)
}
func cfnSESIdentityProperties(name string, identity *sesapi.GetEmailIdentityOutput) cloudformation.Properties {
	p := cloudformation.Properties{"EmailIdentity": name, "FeedbackAttributes": map[string]any{"EmailForwardingEnabled": identity.FeedbackForwardingStatus == nil || bool(*identity.FeedbackForwardingStatus)}}
	if config := cfnComputeValue(identity.ConfigurationSetName); config != "" {
		p["ConfigurationSetAttributes"] = map[string]any{"ConfigurationSetName": config}
	}
	if public := cfnResourcePublicTags(cfnSESTags(identity.Tags)); len(public) > 0 {
		p["Tags"] = public
	}
	return p
}
func (h cfnSESEmailIdentity) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	identity, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return cfnSESIdentityProperties(r.PhysicalID, identity), nil
}
func (h cfnSESEmailIdentity) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	in := &sesapi.ListEmailIdentitiesInput{}
	for {
		page, err := cfnTrustTyped[sesapi.ListEmailIdentitiesOutput](ctx, h.commands, "sesv2", "ListEmailIdentities", in)
		if err != nil {
			return nil, err
		}
		for _, info := range page.EmailIdentities {
			name := cfnComputeValue(info.IdentityName)
			identity, err := h.get(ctx, name)
			if err != nil {
				return nil, err
			}
			out = append(out, cloudformation.ResourceDescription{Identifier: name, Properties: cfnSESIdentityProperties(name, identity)})
		}
		if page.NextToken == nil || cfnComputeValue(page.NextToken) == "" {
			return out, nil
		}
		in = &sesapi.ListEmailIdentitiesInput{NextToken: page.NextToken}
	}
}

type cfnSESConfigurationSet struct{ commands StepFunctionsCommands }

func (cfnSESConfigurationSet) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "TrackingOptions", "DeliveryOptions", "ReputationOptions", "SendingOptions", "SuppressionOptions", "VdmOptions", "ArchivingOptions", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name"); err != nil {
		return err
	}
	for _, key := range []string{"TrackingOptions", "DeliveryOptions", "ReputationOptions", "SuppressionOptions", "VdmOptions", "ArchivingOptions"} {
		if cfnTrustPresent(p, key) {
			return fmt.Errorf("%s has no SES owner; only SendingOptions are owned", key)
		}
	}
	if _, err := cfnSESSending(p); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}

// cfnSESSending returns the sending state; SES enables sending by default.
func cfnSESSending(p map[string]any) (bool, error) {
	if p["SendingOptions"] == nil {
		return true, nil
	}
	options, ok := cfnComputeObject(p["SendingOptions"])
	if !ok {
		return false, fmt.Errorf("SendingOptions must be an object")
	}
	if err := cfnComputeProperties(options, "SendingEnabled"); err != nil {
		return false, fmt.Errorf("SendingOptions: %w", err)
	}
	if options["SendingEnabled"] == nil {
		return true, nil
	}
	return cfnTrustBool(options["SendingEnabled"], "SendingOptions.SendingEnabled")
}
func (h cfnSESConfigurationSet) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "Name"), nil
}
func (h cfnSESConfigurationSet) get(ctx context.Context, name string) (*sesapi.GetConfigurationSetOutput, error) {
	return cfnTrustTyped[sesapi.GetConfigurationSetOutput](ctx, h.commands, "sesv2", "GetConfigurationSet", &sesapi.GetConfigurationSetInput{ConfigurationSetName: new(sesapi.ConfigurationSetName(name))})
}
func (h cfnSESConfigurationSet) sending(ctx context.Context, name string, current *sesapi.GetConfigurationSetOutput, p map[string]any) error {
	enabled, _ := cfnSESSending(p)
	if current.SendingOptions != nil && current.SendingOptions.SendingEnabled != nil && bool(*current.SendingOptions.SendingEnabled) == enabled {
		return nil
	}
	_, err := cfnTrustTyped[sesapi.PutConfigurationSetSendingOptionsOutput](ctx, h.commands, "sesv2", "PutConfigurationSetSendingOptions", &sesapi.PutConfigurationSetSendingOptionsInput{ConfigurationSetName: new(sesapi.ConfigurationSetName(name)), SendingEnabled: new(sesapi.Enabled(enabled))})
	return err
}
func (h cfnSESConfigurationSet) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeName(r, "Name", 64)
	rows := map[string]string{}
	_, err := h.get(sesv2.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "sesconfiguration"), true, rows), name)
	if err != nil && len(rows) == 0 {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{}}, err
}
func (h cfnSESConfigurationSet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 64)
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{}}
	ctx = sesv2.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "sesconfiguration"), true, nil)
	existing, err := h.get(ctx, name)
	if err == nil {
		return result, h.sending(ctx, name, existing, r.Properties)
	}
	if !cfnSESMissing(err) {
		if admitted, _ := h.RecoverCreation(ctx, r); admitted.PhysicalID != "" {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	enabled, _ := cfnSESSending(r.Properties)
	in := &sesapi.CreateConfigurationSetInput{ConfigurationSetName: new(sesapi.ConfigurationSetName(name)), SendingOptions: &sesapi.SendingOptions{SendingEnabled: new(sesapi.Enabled(enabled))}, Tags: cfnSESTagList(cfnTrustCustomerTags(r))}
	_, err = cfnTrustTyped[sesapi.CreateConfigurationSetOutput](ctx, h.commands, "sesv2", "CreateConfigurationSet", in)
	if err != nil {
		if admitted, _ := h.RecoverCreation(ctx, r); admitted.PhysicalID != "" {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return result, nil
}
func (h cfnSESConfigurationSet) current(ctx context.Context, r cloudformation.ResourceRequest) (*sesapi.GetConfigurationSetOutput, error) {
	set, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return set, nil
}
func (h cfnSESConfigurationSet) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SES::ConfigurationSet", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSESOwnership(ctx, r, "sesconfiguration")
	set, err := h.current(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.sending(ctx, r.PhysicalID, set, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnSESRetag(ctx, h.commands, r, cfnSESARN(r, "configuration-set", r.PhysicalID), cfnSESTags(set.Tags)); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{}}, nil
}
func (h cfnSESConfigurationSet) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnSESOwnership(ctx, r, "sesconfiguration")
	if _, err := h.current(ctx, r); err != nil {
		return cfnSESAbsent(r, err)
	}
	_, err := cfnTrustTyped[sesapi.DeleteConfigurationSetOutput](ctx, h.commands, "sesv2", "DeleteConfigurationSet", &sesapi.DeleteConfigurationSetInput{ConfigurationSetName: new(sesapi.ConfigurationSetName(r.PhysicalID))})
	return cfnSESAbsent(r, err)
}
func cfnSESConfigurationProperties(name string, set *sesapi.GetConfigurationSetOutput) cloudformation.Properties {
	enabled := set.SendingOptions == nil || set.SendingOptions.SendingEnabled == nil || bool(*set.SendingOptions.SendingEnabled)
	p := cloudformation.Properties{"Name": name, "SendingOptions": map[string]any{"SendingEnabled": enabled}}
	if public := cfnResourcePublicTags(cfnSESTags(set.Tags)); len(public) > 0 {
		p["Tags"] = public
	}
	return p
}
func (h cfnSESConfigurationSet) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	set, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return cfnSESConfigurationProperties(r.PhysicalID, set), nil
}
func (h cfnSESConfigurationSet) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	in := &sesapi.ListConfigurationSetsInput{}
	for {
		page, err := cfnTrustTyped[sesapi.ListConfigurationSetsOutput](ctx, h.commands, "sesv2", "ListConfigurationSets", in)
		if err != nil {
			return nil, err
		}
		for _, name := range page.ConfigurationSets {
			set, err := h.get(ctx, string(name))
			if err != nil {
				return nil, err
			}
			out = append(out, cloudformation.ResourceDescription{Identifier: string(name), Properties: cfnSESConfigurationProperties(string(name), set)})
		}
		if page.NextToken == nil || cfnComputeValue(page.NextToken) == "" {
			return out, nil
		}
		in = &sesapi.ListConfigurationSetsInput{NextToken: page.NextToken}
	}
}
