package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	r53 "stackd/internal/awsapi/route53"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationTrustDNSHandlers binds the trust, DNS, signing and email control
// resources that have actual ACM, Route53, Signer and SES owners. Every effect is
// an owner command under the caller's authorization; no resource state is kept
// outside the owners.
//
// Not registered because no owner implements the concept: AWS::CertificateManager::Account,
// AcmeDomainValidation, AcmeEndpoint, AcmeExternalAccountBinding; AWS::Route53::CidrCollection,
// DNSSEC, HealthCheck, KeySigningKey; AWS::Signer::ProfilePermission (no grant owner);
// AWS::SES::ConfigurationSetEventDestination (no event publication owner), ContactList,
// CustomVerificationEmailTemplate, DedicatedIpPool, EmailIdentityCertificate, MailManager*,
// MultiRegionEndpoint, ReceiptFilter, ReceiptRule, ReceiptRuleSet, Tenant and VdmAttributes.
func CloudFormationTrustDNSHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::CertificateManager::Certificate": cfnACMCertificate{commands},
		"AWS::Route53::HostedZone":             cfnRoute53HostedZone{commands},
		"AWS::Route53::RecordSet":              cfnRoute53RecordSet{commands},
		"AWS::Route53::RecordSetGroup":         cfnRoute53RecordSetGroup{commands},
		"AWS::Signer::SigningProfile":          cfnSignerProfile{commands},
		"AWS::SES::EmailIdentity":              cfnSESEmailIdentity{commands},
		"AWS::SES::ConfigurationSet":           cfnSESConfigurationSet{commands},
		"AWS::SES::Template":                   cfnSESTemplate{commands},
	}
}

// cfnTrustClaim names one physical incarnation for owners that retain an
// internal claim (Route53 caller references and record owners, SES templates).
func cfnTrustClaim(r cloudformation.ResourceRequest, kind string) string {
	sum := sha256.Sum256([]byte(r.StackID + "\x00" + r.LogicalID + "\x00" + r.Token))
	return "stackd-cfn-" + kind + "-" + hex.EncodeToString(sum[:20])
}

func cfnTrustTyped[T any](ctx context.Context, c StepFunctionsCommands, service, operation string, input any) (*T, error) {
	out, rejected := c.CallTyped(ctx, service, operation, input)
	if rejected != nil {
		return nil, rejected
	}
	typed, ok := out.Output.(*T)
	if !ok {
		return nil, fmt.Errorf("%s.%s returned unexpected output %T", service, operation, out.Output)
	}
	return typed, nil
}

func cfnTrustCode(err error) string {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire.Code
	}
	return ""
}

func cfnTrustNotFound(message string) error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: message, StatusCode: 404}
}

// cfnTrustPresent treats JSON null and empty collections as omitted properties.
func cfnTrustPresent(p map[string]any, key string) bool {
	switch v := p[key].(type) {
	case nil:
		return false
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}

func cfnTrustInt(v any, key string) (int64, error) {
	switch x := v.(type) {
	case float64:
		if x != math.Trunc(x) {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
		return int64(x), nil
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case json.Number:
		return x.Int64()
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
		return n, nil
	}
	return 0, fmt.Errorf("%s must be an integer", key)
}

func cfnTrustBool(v any, key string) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		if x == "true" || x == "false" {
			return x == "true", nil
		}
	}
	return false, fmt.Errorf("%s must be a boolean", key)
}

func cfnRoute53CleanID(id string) string {
	return strings.TrimPrefix(strings.TrimPrefix(id, "/hostedzone/"), "/change/")
}
func cfnRoute53Canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}
func cfnRoute53Missing(err error) bool {
	code := cfnTrustCode(err)
	return code == "NoSuchHostedZone" || cfnComputeMissing(err)
}

func cfnRoute53Zones(ctx context.Context, c StepFunctionsCommands) ([]r53.HostedZone, error) {
	var zones []r53.HostedZone
	in := &r53.ListHostedZonesRequest{}
	for {
		out, err := cfnTrustTyped[r53.ListHostedZonesResponse](ctx, c, "route53", "ListHostedZones", in)
		if err != nil {
			return nil, err
		}
		zones = append(zones, out.HostedZones...)
		if out.IsTruncated == nil || !bool(*out.IsTruncated) || out.NextMarker == nil {
			return zones, nil
		}
		in = &r53.ListHostedZonesRequest{Marker: out.NextMarker}
	}
}

// cfnRoute53ZoneID resolves HostedZoneId or a unique HostedZoneName as documented
// for AWS::Route53::RecordSet and AWS::Route53::RecordSetGroup.
func cfnRoute53ZoneID(ctx context.Context, c StepFunctionsCommands, p map[string]any) (string, error) {
	if id := cfnComputeString(p, "HostedZoneId"); id != "" {
		return cfnRoute53CleanID(id), nil
	}
	name := cfnRoute53Canonical(cfnComputeString(p, "HostedZoneName"))
	zones, err := cfnRoute53Zones(ctx, c)
	if err != nil {
		return "", err
	}
	var found []string
	for _, z := range zones {
		if cfnRoute53Canonical(cfnComputeValue(z.Name)) == name {
			found = append(found, cfnRoute53CleanID(cfnComputeValue(z.Id)))
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("HostedZoneName %s must identify exactly one hosted zone; found %d", name, len(found))
	}
	return found[0], nil
}

// AWS::Route53::HostedZone
// Contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-hostedzone.html
// Wire: https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateHostedZone.html
// The incarnation claim is the zone's CallerReference, which Route53 retains and
// requires to be unique, so recovery never adopts another zone.
type cfnRoute53HostedZone struct{ commands StepFunctionsCommands }

func (cfnRoute53HostedZone) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "HostedZoneConfig", "HostedZoneTags", "VPCs", "QueryLoggingConfig", "HostedZoneFeatures"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name"); err != nil {
		return err
	}
	if cfnTrustPresent(p, "VPCs") {
		return fmt.Errorf("private hosted zones require an isolated VPC resolver boundary, which Route53 does not own")
	}
	if cfnTrustPresent(p, "QueryLoggingConfig") {
		return fmt.Errorf("QueryLoggingConfig has no Route53 query-log delivery owner")
	}
	if cfnTrustPresent(p, "HostedZoneFeatures") {
		return fmt.Errorf("HostedZoneFeatures have no Route53 owner")
	}
	if cfnTrustPresent(p, "HostedZoneTags") {
		return fmt.Errorf("HostedZoneTags have no Route53 tagging owner")
	}
	_, err := cfnRoute53Comment(p)
	return err
}
func cfnRoute53Comment(p map[string]any) (*string, error) {
	if p["HostedZoneConfig"] == nil {
		return nil, nil
	}
	config, ok := cfnComputeObject(p["HostedZoneConfig"])
	if !ok {
		return nil, fmt.Errorf("HostedZoneConfig must be an object")
	}
	if err := cfnComputeProperties(config, "Comment"); err != nil {
		return nil, fmt.Errorf("HostedZoneConfig: %w", err)
	}
	if err := cfnComputeStrings(config, "Comment"); err != nil {
		return nil, err
	}
	if config["Comment"] == nil {
		return nil, nil
	}
	comment := cfnComputeString(config, "Comment")
	return &comment, nil
}
func (h cfnRoute53HostedZone) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnRoute53Canonical(cfnComputeString(a, "Name")) != cfnRoute53Canonical(cfnComputeString(b, "Name")), nil
}
func (h cfnRoute53HostedZone) get(ctx context.Context, id string) (*r53.GetHostedZoneResponse, error) {
	return cfnTrustTyped[r53.GetHostedZoneResponse](ctx, h.commands, "route53", "GetHostedZone", &r53.GetHostedZoneRequest{Id: new(r53.ResourceId(id))})
}
func (h cfnRoute53HostedZone) result(zone *r53.GetHostedZoneResponse) cloudformation.ResourceResult {
	id := cfnRoute53CleanID(cfnComputeValue(zone.HostedZone.Id))
	servers := []any{}
	if zone.DelegationSet != nil {
		for _, name := range zone.DelegationSet.NameServers {
			servers = append(servers, string(name))
		}
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "NameServers": servers}}
}
func (h cfnRoute53HostedZone) comment(ctx context.Context, id string, p map[string]any) error {
	comment, err := cfnRoute53Comment(p)
	if err != nil {
		return err
	}
	text := ""
	if comment != nil {
		text = *comment
	}
	_, err = cfnTrustTyped[r53.UpdateHostedZoneCommentResponse](ctx, h.commands, "route53", "UpdateHostedZoneComment", &r53.UpdateHostedZoneCommentRequest{Id: new(r53.ResourceId(id)), Comment: new(r53.ResourceDescription(text))})
	return err
}
func (h cfnRoute53HostedZone) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claim := cfnTrustClaim(r, "hostedzone")
	in := &r53.CreateHostedZoneRequest{Name: new(r53.DNSName(cfnComputeString(r.Properties, "Name"))), CallerReference: new(r53.Nonce(claim))}
	if comment, _ := cfnRoute53Comment(r.Properties); comment != nil {
		in.HostedZoneConfig = &r53.HostedZoneConfig{Comment: new(r53.ResourceDescription(*comment))}
	}
	id := ""
	out, err := cfnTrustTyped[r53.CreateHostedZoneResponse](ctx, h.commands, "route53", "CreateHostedZone", in)
	switch {
	case err == nil:
		id = cfnRoute53CleanID(cfnComputeValue(out.HostedZone.Id))
	case cfnTrustCode(err) == "HostedZoneAlreadyExists":
		zones, listErr := cfnRoute53Zones(ctx, h.commands)
		if listErr != nil {
			return cloudformation.ResourceResult{}, listErr
		}
		for _, z := range zones {
			if cfnComputeValue(z.CallerReference) == claim {
				id = cfnRoute53CleanID(cfnComputeValue(z.Id))
			}
		}
		if id == "" {
			return cloudformation.ResourceResult{}, err
		}
		if cfnRoute53Canonical(cfnComputeValue(cfnRoute53ZoneName(zones, id))) != cfnRoute53Canonical(cfnComputeString(r.Properties, "Name")) {
			return cloudformation.ResourceResult{}, fmt.Errorf("hosted zone %s for this incarnation has a different name", id)
		}
		if err := h.comment(ctx, id, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	default:
		return cloudformation.ResourceResult{}, err
	}
	zone, err := h.get(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(zone), nil
}
func cfnRoute53ZoneName(zones []r53.HostedZone, id string) *r53.DNSName {
	for _, z := range zones {
		if cfnRoute53CleanID(cfnComputeValue(z.Id)) == id {
			return z.Name
		}
	}
	return nil
}
func (h cfnRoute53HostedZone) owned(ctx context.Context, r cloudformation.ResourceRequest) (*r53.GetHostedZoneResponse, error) {
	zone, err := h.get(ctx, cfnRoute53CleanID(r.PhysicalID))
	if err != nil {
		return nil, err
	}
	if !r.CloudControl && cfnComputeValue(zone.HostedZone.CallerReference) != cfnTrustClaim(r, "hostedzone") {
		return nil, fmt.Errorf("hosted zone %s is not owned by this stack resource incarnation", r.PhysicalID)
	}
	return zone, nil
}
func (h cfnRoute53HostedZone) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::Route53::HostedZone", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	zone, err := h.owned(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnRoute53CleanID(cfnComputeValue(zone.HostedZone.Id))
	if err := h.comment(ctx, id, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(zone), nil
}
func (h cfnRoute53HostedZone) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	zone, err := h.owned(ctx, r)
	if err != nil {
		if cfnRoute53Missing(err) && !r.CloudControl {
			return nil
		}
		return err
	}
	_, err = cfnTrustTyped[r53.DeleteHostedZoneResponse](ctx, h.commands, "route53", "DeleteHostedZone", &r53.DeleteHostedZoneRequest{Id: zone.HostedZone.Id})
	if err != nil && cfnRoute53Missing(err) && !r.CloudControl {
		return nil
	}
	return err
}
func cfnRoute53ZoneProperties(zone *r53.GetHostedZoneResponse) cloudformation.Properties {
	id := cfnRoute53CleanID(cfnComputeValue(zone.HostedZone.Id))
	servers := []any{}
	if zone.DelegationSet != nil {
		for _, name := range zone.DelegationSet.NameServers {
			servers = append(servers, string(name))
		}
	}
	p := cloudformation.Properties{"Id": id, "Name": cfnComputeValue(zone.HostedZone.Name), "NameServers": servers}
	if zone.HostedZone.Config != nil && cfnComputeValue(zone.HostedZone.Config.Comment) != "" {
		p["HostedZoneConfig"] = map[string]any{"Comment": cfnComputeValue(zone.HostedZone.Config.Comment)}
	}
	return p
}
func (h cfnRoute53HostedZone) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	zone, err := h.get(ctx, cfnRoute53CleanID(r.PhysicalID))
	if err != nil {
		return nil, err
	}
	return cfnRoute53ZoneProperties(zone), nil
}
func (h cfnRoute53HostedZone) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	zones, err := cfnRoute53Zones(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(zones))
	for _, z := range zones {
		id := cfnRoute53CleanID(cfnComputeValue(z.Id))
		zone, err := h.get(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cfnRoute53ZoneProperties(zone)})
	}
	return out, nil
}
