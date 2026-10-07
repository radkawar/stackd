package integrations

import (
	"context"
	"fmt"
	"slices"
	"strings"

	acmapi "stackd/internal/awsapi/acm"
	r53 "stackd/internal/awsapi/route53"
	"stackd/internal/services/acm"
	"stackd/internal/services/cloudformation"
)

// AWS::CertificateManager::Certificate
// Contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-certificatemanager-certificate.html
// Wire: https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html
// DNS validation: https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html
// The ACM owner issues from its local authority only after it observes every
// validation CNAME through the configured resolver; this adapter never marks a
// certificate issued. As documented, a DomainValidationOption with HostedZoneId
// makes CloudFormation write the validation CNAME into that Route53 zone; the
// record is shared by all certificates for the domain and is retained on delete.
type cfnACMCertificate struct{ commands StepFunctionsCommands }

var cfnACMRequestAlgorithms = []string{"RSA_2048", "EC_prime256v1", "EC_secp384r1"}

func cfnACMDomain(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }
func cfnACMDomains(p map[string]any, names []string) []string {
	domains := []string{cfnACMDomain(cfnComputeString(p, "DomainName"))}
	for _, name := range names {
		domains = append(domains, cfnACMDomain(name))
	}
	return domains
}

func (cfnACMCertificate) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "CertificateAuthorityArn", "CertificateExport", "CertificateTransparencyLoggingPreference", "DomainName", "DomainValidationOptions", "KeyAlgorithm", "SubjectAlternativeNames", "Tags", "ValidationMethod"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "DomainName"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "CertificateAuthorityArn", "CertificateExport", "CertificateTransparencyLoggingPreference", "DomainName", "KeyAlgorithm", "ValidationMethod"); err != nil {
		return err
	}
	if cfnComputeString(p, "CertificateAuthorityArn") != "" {
		return fmt.Errorf("private certificates require an AWS Private CA owner, which is unavailable")
	}
	// CloudFormation defaults ValidationMethod to EMAIL; only DNS validation has an owner.
	if cfnComputeString(p, "ValidationMethod") != "DNS" {
		return fmt.Errorf("ValidationMethod must be DNS; email and HTTP validation have no owner")
	}
	if v := cfnComputeString(p, "KeyAlgorithm"); v != "" && !slices.Contains(cfnACMRequestAlgorithms, v) {
		return fmt.Errorf("KeyAlgorithm %s cannot be requested; use RSA_2048, EC_prime256v1 or EC_secp384r1", v)
	}
	for _, key := range []string{"CertificateExport", "CertificateTransparencyLoggingPreference"} {
		if v := cfnComputeString(p, key); v != "" && v != "ENABLED" && v != "DISABLED" {
			return fmt.Errorf("%s must be ENABLED or DISABLED", key)
		}
	}
	names, err := cfnComputeStringList(p, "SubjectAlternativeNames")
	if err != nil {
		return err
	}
	if _, err := cfnACMValidationZones(p, cfnACMDomains(p, names)); err != nil {
		return err
	}
	_, err = cfnComputeTags(p)
	return err
}

// cfnACMValidationZones maps certificate domains to the Route53 zone that
// receives their validation CNAME.
func cfnACMValidationZones(p map[string]any, domains []string) (map[string]string, error) {
	zones := map[string]string{}
	if p["DomainValidationOptions"] == nil {
		return zones, nil
	}
	list, ok := p["DomainValidationOptions"].([]any)
	if !ok {
		return nil, fmt.Errorf("DomainValidationOptions must be a list")
	}
	for i, item := range list {
		option, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("DomainValidationOptions[%d] must be an object", i)
		}
		if err := cfnComputeProperties(option, "DomainName", "HostedZoneId", "ValidationDomain"); err != nil {
			return nil, fmt.Errorf("DomainValidationOptions[%d]: %w", i, err)
		}
		if err := cfnComputeStrings(option, "DomainName", "HostedZoneId", "ValidationDomain"); err != nil {
			return nil, fmt.Errorf("DomainValidationOptions[%d]: %w", i, err)
		}
		if option["ValidationDomain"] != nil {
			return nil, fmt.Errorf("DomainValidationOptions[%d].ValidationDomain applies to email validation, which has no owner", i)
		}
		domain := cfnACMDomain(cfnComputeString(option, "DomainName"))
		if !slices.Contains(domains, domain) {
			return nil, fmt.Errorf("DomainValidationOptions[%d].DomainName must be DomainName or a SubjectAlternativeName", i)
		}
		if zone := cfnComputeString(option, "HostedZoneId"); zone != "" {
			zones[domain] = cfnRoute53CleanID(zone)
		}
	}
	return zones, nil
}

func (h cfnACMCertificate) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	if cfnACMDomain(cfnComputeString(a, "DomainName")) != cfnACMDomain(cfnComputeString(b, "DomainName")) {
		return true, nil
	}
	if cfnComputeDefault(a, "KeyAlgorithm", "RSA_2048") != cfnComputeDefault(b, "KeyAlgorithm", "RSA_2048") || cfnComputeDefault(a, "CertificateExport", "DISABLED") != cfnComputeDefault(b, "CertificateExport", "DISABLED") {
		return true, nil
	}
	return cfnComputeChanged(a, b, "SubjectAlternativeNames", "DomainValidationOptions", "CertificateAuthorityArn"), nil
}

func (h cfnACMCertificate) describe(ctx context.Context, arn string) (*acmapi.CertificateDetail, error) {
	out, err := cfnTrustTyped[acmapi.DescribeCertificateResponse](ctx, h.commands, "acm", "DescribeCertificate", &acmapi.DescribeCertificateRequest{CertificateArn: new(acmapi.Arn(arn))})
	if err != nil {
		return nil, err
	}
	if out.Certificate == nil {
		return nil, fmt.Errorf("acm.DescribeCertificate returned no certificate")
	}
	return out.Certificate, nil
}
func (h cfnACMCertificate) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := cfnTrustTyped[acmapi.ListTagsForCertificateResponse](ctx, h.commands, "acm", "ListTagsForCertificate", &acmapi.ListTagsForCertificateRequest{CertificateArn: new(acmapi.Arn(arn))})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.Tags))
	for _, t := range out.Tags {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}
func cfnACMTagList(tags map[string]string) acmapi.TagList {
	out := make(acmapi.TagList, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		out = append(out, acmapi.Tag{Key: new(acmapi.TagKey(key)), Value: new(acmapi.TagValue(tags[key]))})
	}
	return out
}
func cfnACMResult(c *acmapi.CertificateDetail) cloudformation.ResourceResult {
	arn := cfnComputeValue(c.CertificateArn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"CertificateArn": arn, "CertificateStatus": cfnComputeValue(c.Status)}}
}

// validationRecords writes the DNS validation CNAMEs reported by ACM into the
// zones named by DomainValidationOptions, using the caller's Route53 authority.
func (h cfnACMCertificate) validationRecords(ctx context.Context, r cloudformation.ResourceRequest, c *acmapi.CertificateDetail) error {
	names, err := cfnComputeStringList(r.Properties, "SubjectAlternativeNames")
	if err != nil {
		return err
	}
	zones, err := cfnACMValidationZones(r.Properties, cfnACMDomains(r.Properties, names))
	if err != nil || len(zones) == 0 {
		return err
	}
	byZone := map[string][]r53.ResourceRecordSet{}
	seen := map[string]bool{}
	for _, v := range c.DomainValidationOptions {
		zone := zones[cfnACMDomain(cfnComputeValue(v.DomainName))]
		if zone == "" || v.ResourceRecord == nil {
			continue
		}
		name := cfnComputeValue(v.ResourceRecord.Name)
		if seen[zone+"\x00"+name] {
			continue
		}
		seen[zone+"\x00"+name] = true
		byZone[zone] = append(byZone[zone], r53.ResourceRecordSet{Name: new(r53.DNSName(name)), Type: new(r53.RRType(cfnComputeValue(v.ResourceRecord.Type))), TTL: new(r53.TTL(300)), ResourceRecords: r53.ResourceRecords{{Value: new(r53.RData(cfnComputeValue(v.ResourceRecord.Value)))}}})
	}
	ordered := make([]string, 0, len(byZone))
	for zone := range byZone {
		ordered = append(ordered, zone)
	}
	slices.Sort(ordered)
	for _, zone := range ordered {
		if _, err := cfnRoute53Reconcile(ctx, h.commands, zone, "", false, nil, byZone[zone], "ACM DNS validation"); err != nil {
			return err
		}
	}
	return nil
}

func cfnACMOwnership(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return acm.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "acmcertificate"), true, nil)
}
func (h cfnACMCertificate) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	rows := map[string]string{}
	c, err := h.describe(acm.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "acmcertificate"), true, rows), "")
	if err != nil {
		for arn := range rows {
			return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"CertificateArn": arn}}, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnACMResult(c), nil
}
func (h cfnACMCertificate) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = acm.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "acmcertificate"), true, nil)
	p := r.Properties
	in := &acmapi.RequestCertificateRequest{
		DomainName:       new(acmapi.DomainNameString(cfnComputeString(p, "DomainName"))),
		ValidationMethod: new(acmapi.ValidationMethod("DNS")),
		// Native private admission survives the public token's one-hour lifetime.
		IdempotencyToken: new(acmapi.IdempotencyToken(cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)[:24] + "cfn")),
		Tags:             cfnACMTagList(cfnTrustCustomerTags(r)),
		Options:          &acmapi.CertificateOptions{Export: new(acmapi.CertificateExport(cfnComputeDefault(p, "CertificateExport", "DISABLED").(string))), CertificateTransparencyLoggingPreference: new(acmapi.CertificateTransparencyLoggingPreference(cfnComputeDefault(p, "CertificateTransparencyLoggingPreference", "ENABLED").(string)))},
	}
	if v := cfnComputeString(p, "KeyAlgorithm"); v != "" {
		in.KeyAlgorithm = new(acmapi.KeyAlgorithm(v))
	}
	names, _ := cfnComputeStringList(p, "SubjectAlternativeNames")
	for _, name := range names {
		in.SubjectAlternativeNames = append(in.SubjectAlternativeNames, acmapi.DomainNameString(name))
	}
	out, err := cfnTrustTyped[acmapi.RequestCertificateResponse](ctx, h.commands, "acm", "RequestCertificate", in)
	if err != nil {
		if admitted, _ := h.RecoverCreation(ctx, r); admitted.PhysicalID != "" {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnComputeValue(out.CertificateArn)
	result := cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"CertificateArn": arn}}
	c, err := h.describe(ctx, arn)
	if err != nil {
		return result, err
	}
	if err := h.validationRecords(ctx, r, c); err != nil {
		return cfnACMResult(c), err
	}
	return cfnACMResult(c), nil
}

// Stabilize waits for owner-observed DNS validation and issuance, matching the
// documented CREATE_IN_PROGRESS behavior; terminal ACM failures fail the resource.
func (h cfnACMCertificate) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	c, err := h.describe(cfnACMOwnership(ctx, r), r.PhysicalID)
	if err != nil {
		return false, err
	}
	switch status := cfnComputeValue(c.Status); status {
	case "ISSUED":
		return true, nil
	case "PENDING_VALIDATION":
		return false, nil
	default:
		return false, fmt.Errorf("certificate %s is %s %s", r.PhysicalID, status, cfnComputeValue(c.FailureReason))
	}
}
func (h cfnACMCertificate) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	c, err := h.describe(cfnACMOwnership(ctx, r), r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACMResult(c), nil
}
func (h cfnACMCertificate) owned(ctx context.Context, r cloudformation.ResourceRequest) (map[string]string, error) {
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return tags, nil
}
func (h cfnACMCertificate) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::CertificateManager::Certificate", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnACMOwnership(ctx, r)
	current, err := h.owned(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := new(acmapi.Arn(r.PhysicalID))
	// Removing the preference is documented as enabling transparency logging.
	ct := cfnComputeDefault(r.Properties, "CertificateTransparencyLoggingPreference", "ENABLED").(string)
	if c, err := h.describe(ctx, r.PhysicalID); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if c.Options == nil || cfnComputeValue(c.Options.CertificateTransparencyLoggingPreference) != ct {
		if err := cfnComputeRun(ctx, h.commands, "acm", "UpdateCertificateOptions", map[string]any{"CertificateArn": r.PhysicalID, "Options": map[string]any{"CertificateTransparencyLoggingPreference": ct}}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	desired := cfnTrustCustomerTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		keys := make(acmapi.TagList, 0, len(removed))
		for _, key := range removed {
			keys = append(keys, acmapi.Tag{Key: new(acmapi.TagKey(key))})
		}
		if _, err := cfnTrustTyped[acmapi.Unit](ctx, h.commands, "acm", "RemoveTagsFromCertificate", &acmapi.RemoveTagsFromCertificateRequest{CertificateArn: arn, Tags: keys}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if len(desired) > 0 {
		if _, err := cfnTrustTyped[acmapi.Unit](ctx, h.commands, "acm", "AddTagsToCertificate", &acmapi.AddTagsToCertificateRequest{CertificateArn: arn, Tags: cfnACMTagList(desired)}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	c, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACMResult(c), nil
}
func (h cfnACMCertificate) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACMOwnership(ctx, r)
	if _, err := h.owned(ctx, r); err != nil {
		if r.CloudControl {
			return err
		}
		return cfnComputeAbsent(err)
	}
	err := cfnComputeRun(ctx, h.commands, "acm", "DeleteCertificate", map[string]any{"CertificateArn": r.PhysicalID})
	if r.CloudControl {
		return err
	}
	return cfnComputeAbsent(err)
}
func (h cfnACMCertificate) properties(ctx context.Context, c *acmapi.CertificateDetail) (cloudformation.Properties, error) {
	arn := cfnComputeValue(c.CertificateArn)
	domain := cfnComputeValue(c.DomainName)
	p := cloudformation.Properties{"CertificateArn": arn, "DomainName": domain, "KeyAlgorithm": cfnComputeValue(c.KeyAlgorithm), "ValidationMethod": "DNS"}
	var names []any
	for _, name := range c.SubjectAlternativeNames {
		if string(name) != domain {
			names = append(names, string(name))
		}
	}
	if len(names) > 0 {
		p["SubjectAlternativeNames"] = names
	}
	if c.Options != nil {
		p["CertificateExport"] = cfnComputeValue(c.Options.Export)
		p["CertificateTransparencyLoggingPreference"] = cfnComputeValue(c.Options.CertificateTransparencyLoggingPreference)
	}
	tags, err := h.tags(ctx, arn)
	if err != nil {
		return nil, err
	}
	if public := cfnResourcePublicTags(tags); len(public) > 0 {
		p["Tags"] = public
	}
	return p, nil
}
func (h cfnACMCertificate) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	c, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if cfnComputeValue(c.Type) != "AMAZON_ISSUED" {
		return nil, cfnTrustNotFound("certificate " + r.PhysicalID + " is not a requested ACM certificate")
	}
	return h.properties(ctx, c)
}
func (h cfnACMCertificate) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	includes := &acmapi.Filters{}
	for _, algorithm := range cfnACMRequestAlgorithms {
		includes.KeyTypes = append(includes.KeyTypes, acmapi.KeyAlgorithm(algorithm))
	}
	in := &acmapi.ListCertificatesRequest{Includes: includes}
	for {
		page, err := cfnTrustTyped[acmapi.ListCertificatesResponse](ctx, h.commands, "acm", "ListCertificates", in)
		if err != nil {
			return nil, err
		}
		for _, summary := range page.CertificateSummaryList {
			if cfnComputeValue(summary.Type) != "AMAZON_ISSUED" {
				continue
			}
			c, err := h.describe(ctx, cfnComputeValue(summary.CertificateArn))
			if err != nil {
				return nil, err
			}
			p, err := h.properties(ctx, c)
			if err != nil {
				return nil, err
			}
			out = append(out, cloudformation.ResourceDescription{Identifier: cfnComputeValue(c.CertificateArn), Properties: p})
		}
		if page.NextToken == nil || cfnComputeValue(page.NextToken) == "" {
			return out, nil
		}
		in = &acmapi.ListCertificatesRequest{Includes: includes, NextToken: page.NextToken}
	}
}
