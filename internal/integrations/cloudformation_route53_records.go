package integrations

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	r53 "stackd/internal/awsapi/route53"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/route53"
)

// AWS::Route53::RecordSet and AWS::Route53::RecordSetGroup
// Contracts: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordsetgroup.html
// Wire: https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
// Each record set retains an internal Route53 owner claim for its incarnation;
// every mutation is one atomic ChangeResourceRecordSets batch.

var cfnRoute53RecordKeys = []string{"AliasTarget", "CidrRoutingConfig", "Failover", "GeoLocation", "GeoProximityLocation", "HealthCheckId", "HostedZoneId", "HostedZoneName", "MultiValueAnswer", "Name", "Region", "ResourceRecords", "SetIdentifier", "TTL", "Type", "Weight"}

func cfnRoute53ValidateZone(p map[string]any) error {
	if err := cfnComputeStrings(p, "HostedZoneId", "HostedZoneName", "Comment"); err != nil {
		return err
	}
	if (cfnComputeString(p, "HostedZoneId") == "") == (cfnComputeString(p, "HostedZoneName") == "") {
		return fmt.Errorf("specify exactly one of HostedZoneId or HostedZoneName")
	}
	return nil
}

func cfnRoute53ValidateRecord(p map[string]any) error {
	if err := cfnComputeRequired(p, "Name", "Type"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Type", "SetIdentifier", "HostedZoneId", "HostedZoneName", "HealthCheckId", "Failover", "Region"); err != nil {
		return err
	}
	for _, key := range []string{"CidrRoutingConfig", "Failover", "GeoLocation", "GeoProximityLocation", "HealthCheckId", "Region"} {
		if cfnTrustPresent(p, key) {
			return fmt.Errorf("%s requires health or location routing authorities that Route53 does not own", key)
		}
	}
	_, err := cfnRoute53Desired(p)
	return err
}

// cfnRoute53Desired projects CloudFormation record properties onto the Route53
// ResourceRecordSet; the owner performs record semantic validation.
func cfnRoute53Desired(p map[string]any) (r53.ResourceRecordSet, error) {
	rr := r53.ResourceRecordSet{Name: new(r53.DNSName(cfnComputeString(p, "Name"))), Type: new(r53.RRType(cfnComputeString(p, "Type")))}
	if id := cfnComputeString(p, "SetIdentifier"); id != "" {
		rr.SetIdentifier = new(r53.ResourceRecordSetIdentifier(id))
	}
	if v, ok := p["TTL"]; ok && v != nil {
		n, err := cfnTrustInt(v, "TTL")
		if err != nil {
			return rr, err
		}
		rr.TTL = new(r53.TTL(n))
	}
	if v, ok := p["Weight"]; ok && v != nil {
		n, err := cfnTrustInt(v, "Weight")
		if err != nil {
			return rr, err
		}
		rr.Weight = new(r53.ResourceRecordSetWeight(n))
	}
	if v, ok := p["MultiValueAnswer"]; ok && v != nil {
		multi, err := cfnTrustBool(v, "MultiValueAnswer")
		if err != nil {
			return rr, err
		}
		if multi {
			rr.MultiValueAnswer = new(r53.ResourceRecordSetMultiValueAnswer(true))
		}
	}
	values, err := cfnComputeStringList(p, "ResourceRecords")
	if err != nil {
		return rr, err
	}
	for _, value := range values {
		rr.ResourceRecords = append(rr.ResourceRecords, r53.ResourceRecord{Value: new(r53.RData(value))})
	}
	if p["AliasTarget"] != nil {
		alias, ok := cfnComputeObject(p["AliasTarget"])
		if !ok {
			return rr, fmt.Errorf("AliasTarget must be an object")
		}
		if err := cfnComputeProperties(alias, "DNSName", "HostedZoneId", "EvaluateTargetHealth"); err != nil {
			return rr, fmt.Errorf("AliasTarget: %w", err)
		}
		if err := cfnComputeRequired(alias, "DNSName", "HostedZoneId"); err != nil {
			return rr, fmt.Errorf("AliasTarget: %w", err)
		}
		if err := cfnComputeStrings(alias, "DNSName", "HostedZoneId"); err != nil {
			return rr, fmt.Errorf("AliasTarget: %w", err)
		}
		if v, ok := alias["EvaluateTargetHealth"]; ok && v != nil {
			evaluate, err := cfnTrustBool(v, "AliasTarget.EvaluateTargetHealth")
			if err != nil {
				return rr, err
			}
			if evaluate {
				return rr, fmt.Errorf("AliasTarget.EvaluateTargetHealth requires a target-health authority that Route53 does not own")
			}
		}
		rr.AliasTarget = &r53.AliasTarget{DNSName: new(r53.DNSName(cfnComputeString(alias, "DNSName"))), HostedZoneId: new(r53.ResourceId(cfnComputeString(alias, "HostedZoneId"))), EvaluateTargetHealth: new(r53.AliasHealthEnabled(false))}
	}
	return rr, nil
}

func cfnRoute53Key(rr r53.ResourceRecordSet) string {
	return route53.CloudFormationRecordKey(cfnRoute53Canonical(cfnComputeValue(rr.Name)), cfnComputeValue(rr.Type), cfnComputeValue(rr.SetIdentifier))
}

// cfnRoute53Records lists every record set of a zone and the internal owner claim
// retained for each, keyed by cfnRoute53Key.
func cfnRoute53Records(ctx context.Context, c StepFunctionsCommands, zoneID string) ([]r53.ResourceRecordSet, map[string]string, error) {
	owners := map[string]string{}
	ctx = route53.WithCloudFormationOwnership(ctx, "", false, owners)
	var records []r53.ResourceRecordSet
	in := &r53.ListResourceRecordSetsRequest{HostedZoneId: new(r53.ResourceId(zoneID))}
	for {
		out, err := cfnTrustTyped[r53.ListResourceRecordSetsResponse](ctx, c, "route53", "ListResourceRecordSets", in)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, out.ResourceRecordSets...)
		if out.IsTruncated == nil || !bool(*out.IsTruncated) {
			return records, owners, nil
		}
		in = &r53.ListResourceRecordSetsRequest{HostedZoneId: new(r53.ResourceId(zoneID)), StartRecordName: out.NextRecordName, StartRecordType: out.NextRecordType, StartRecordIdentifier: out.NextRecordIdentifier}
	}
}

func cfnRoute53OwnedBy(records []r53.ResourceRecordSet, owners map[string]string, claim string) []r53.ResourceRecordSet {
	var out []r53.ResourceRecordSet
	for _, rr := range records {
		if claim != "" && owners[cfnRoute53Key(rr)] == claim {
			out = append(out, rr)
		}
	}
	return out
}

// cfnRoute53Reconcile atomically deletes owned records absent from desired and
// upserts desired records. A nonempty claim stamps desired records; with enforce
// the owner rejects records retained by any other claim, so nothing is adopted.
func cfnRoute53Reconcile(ctx context.Context, c StepFunctionsCommands, zoneID, claim string, enforce bool, owned, desired []r53.ResourceRecordSet, comment string) (string, error) {
	want := map[string]bool{}
	for _, rr := range desired {
		want[cfnRoute53Key(rr)] = true
	}
	var changes r53.Changes
	for i := range owned {
		if !want[cfnRoute53Key(owned[i])] {
			changes = append(changes, r53.Change{Action: new(r53.ChangeAction("DELETE")), ResourceRecordSet: &owned[i]})
		}
	}
	for i := range desired {
		changes = append(changes, r53.Change{Action: new(r53.ChangeAction("UPSERT")), ResourceRecordSet: &desired[i]})
	}
	if len(changes) == 0 {
		return "", nil
	}
	batch := &r53.ChangeBatch{Changes: changes}
	if comment != "" {
		batch.Comment = new(r53.ResourceDescription(comment))
	}
	ctx = route53.WithCloudFormationOwnership(ctx, claim, enforce, nil)
	out, err := cfnTrustTyped[r53.ChangeResourceRecordSetsResponse](ctx, c, "route53", "ChangeResourceRecordSets", &r53.ChangeResourceRecordSetsRequest{HostedZoneId: new(r53.ResourceId(zoneID)), ChangeBatch: batch})
	if err != nil {
		return "", err
	}
	if out.ChangeInfo == nil {
		return "", nil
	}
	return cfnRoute53CleanID(cfnComputeValue(out.ChangeInfo.Id)), nil
}

func cfnRoute53RecordProperties(rr r53.ResourceRecordSet) map[string]any {
	p := map[string]any{"Name": cfnComputeValue(rr.Name), "Type": cfnComputeValue(rr.Type)}
	if rr.SetIdentifier != nil {
		p["SetIdentifier"] = cfnComputeValue(rr.SetIdentifier)
	}
	if rr.TTL != nil {
		p["TTL"] = strconv.FormatInt(int64(*rr.TTL), 10)
	}
	if rr.Weight != nil {
		p["Weight"] = int64(*rr.Weight)
	}
	if rr.MultiValueAnswer != nil && bool(*rr.MultiValueAnswer) {
		p["MultiValueAnswer"] = true
	}
	if len(rr.ResourceRecords) > 0 {
		values := make([]any, 0, len(rr.ResourceRecords))
		for _, v := range rr.ResourceRecords {
			values = append(values, cfnComputeValue(v.Value))
		}
		p["ResourceRecords"] = values
	}
	if rr.AliasTarget != nil {
		p["AliasTarget"] = map[string]any{"DNSName": cfnComputeValue(rr.AliasTarget.DNSName), "HostedZoneId": cfnComputeValue(rr.AliasTarget.HostedZoneId), "EvaluateTargetHealth": false}
	}
	return p
}

type cfnRoute53RecordSet struct{ commands StepFunctionsCommands }

func (cfnRoute53RecordSet) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, append([]string{"Comment"}, cfnRoute53RecordKeys...)...); err != nil {
		return err
	}
	if err := cfnRoute53ValidateZone(p); err != nil {
		return err
	}
	return cfnRoute53ValidateRecord(p)
}

// HostedZoneId and HostedZoneName are create-only; record identity changes are
// applied in place by one atomic batch, as documented ("No interruption").
func (h cfnRoute53RecordSet) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "HostedZoneId", "HostedZoneName"), nil
}

// Physical identifiers follow the registry primary identifier order:
// Name|HostedZoneId|Type|SetIdentifier.
func cfnRoute53RecordID(zoneID string, rr r53.ResourceRecordSet) string {
	return strings.Join([]string{cfnRoute53Canonical(cfnComputeValue(rr.Name)), zoneID, cfnComputeValue(rr.Type), cfnComputeValue(rr.SetIdentifier)}, "|")
}
func cfnRoute53ParseRecordID(id string) (zoneID, key string, err error) {
	parts := strings.Split(id, "|")
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", fmt.Errorf("invalid record set identifier %q", id)
	}
	return cfnRoute53CleanID(parts[1]), route53.CloudFormationRecordKey(cfnRoute53Canonical(parts[0]), parts[2], parts[3]), nil
}
func (h cfnRoute53RecordSet) apply(ctx context.Context, r cloudformation.ResourceRequest, owned []r53.ResourceRecordSet, claim string, enforce bool) (cloudformation.ResourceResult, error) {
	zoneID, err := cfnRoute53ZoneID(ctx, h.commands, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	desired, err := cfnRoute53Desired(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if _, err := cfnRoute53Reconcile(ctx, h.commands, zoneID, claim, enforce, owned, []r53.ResourceRecordSet{desired}, cfnComputeString(r.Properties, "Comment")); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: cfnRoute53RecordID(zoneID, desired), Ref: cfnComputeString(r.Properties, "Name")}, nil
}
func (h cfnRoute53RecordSet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	zoneID, err := cfnRoute53ZoneID(ctx, h.commands, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claim := cfnTrustClaim(r, "recordset")
	records, owners, err := cfnRoute53Records(ctx, h.commands, zoneID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.apply(ctx, r, cfnRoute53OwnedBy(records, owners, claim), claim, true)
	return result, cfnResourceCreateOwnedError(r, err)
}

// current locates the record set of this request. Stack operations follow the
// incarnation claim; Cloud Control follows the identifier and preserves its claim.
func (h cfnRoute53RecordSet) current(ctx context.Context, r cloudformation.ResourceRequest) (zoneID string, owned []r53.ResourceRecordSet, claim string, err error) {
	zoneID, key, err := cfnRoute53ParseRecordID(r.PhysicalID)
	if err != nil {
		return "", nil, "", err
	}
	records, owners, err := cfnRoute53Records(ctx, h.commands, zoneID)
	if err != nil {
		return "", nil, "", err
	}
	if !r.CloudControl {
		claim = cfnTrustClaim(r, "recordset")
		return zoneID, cfnRoute53OwnedBy(records, owners, claim), claim, nil
	}
	for _, rr := range records {
		if cfnRoute53Key(rr) == key {
			return zoneID, []r53.ResourceRecordSet{rr}, owners[key], nil
		}
	}
	return "", nil, "", cfnTrustNotFound("record set " + r.PhysicalID + " does not exist")
}
func (h cfnRoute53RecordSet) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::Route53::RecordSet", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	zoneID, owned, claim, err := h.current(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	desiredZone, err := cfnRoute53ZoneID(ctx, h.commands, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if desiredZone != zoneID {
		return cloudformation.ResourceResult{}, fmt.Errorf("%w: AWS::Route53::RecordSet hosted zone", cloudformation.ErrCreateOnly)
	}
	return h.apply(ctx, r, owned, claim, claim != "")
}
func (h cfnRoute53RecordSet) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	zoneID, owned, claim, err := h.current(ctx, r)
	if err != nil {
		if cfnRoute53Missing(err) && !r.CloudControl {
			return nil
		}
		return err
	}
	if len(owned) == 0 {
		return nil
	}
	_, err = cfnRoute53Reconcile(ctx, h.commands, zoneID, claim, claim != "", owned, nil, "")
	return err
}
func (h cfnRoute53RecordSet) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	r.CloudControl = true
	zoneID, owned, _, err := h.current(ctx, r)
	if err != nil {
		return nil, err
	}
	p := cfnRoute53RecordProperties(owned[0])
	p["HostedZoneId"] = zoneID
	return p, nil
}
func (h cfnRoute53RecordSet) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	zones, err := cfnRoute53Zones(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, z := range zones {
		zoneID := cfnRoute53CleanID(cfnComputeValue(z.Id))
		records, _, err := cfnRoute53Records(ctx, h.commands, zoneID)
		if err != nil {
			return nil, err
		}
		for _, rr := range records {
			p := cfnRoute53RecordProperties(rr)
			p["HostedZoneId"] = zoneID
			out = append(out, cloudformation.ResourceDescription{Identifier: cfnRoute53RecordID(zoneID, rr), Properties: p})
		}
	}
	return out, nil
}

// AWS::Route53::RecordSetGroup physical identity is HostedZoneId|claim; Ref is
// the group name (logical ID) and GetAtt Id is the Route53 change ID, as documented.
type cfnRoute53RecordSetGroup struct{ commands StepFunctionsCommands }

const cfnRoute53GroupClaimPrefix = "stackd-cfn-recordsetgroup-"

func (cfnRoute53RecordSetGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Comment", "HostedZoneId", "HostedZoneName", "RecordSets"); err != nil {
		return err
	}
	if err := cfnRoute53ValidateZone(p); err != nil {
		return err
	}
	_, err := cfnRoute53GroupRecords(p)
	return err
}
func cfnRoute53GroupRecords(p map[string]any) ([]r53.ResourceRecordSet, error) {
	if p["RecordSets"] == nil {
		return nil, nil
	}
	list, ok := p["RecordSets"].([]any)
	if !ok {
		return nil, fmt.Errorf("RecordSets must be a list")
	}
	seen := map[string]bool{}
	out := make([]r53.ResourceRecordSet, 0, len(list))
	for i, item := range list {
		record, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("RecordSets[%d] must be an object", i)
		}
		if err := cfnComputeProperties(record, cfnRoute53RecordKeys...); err != nil {
			return nil, fmt.Errorf("RecordSets[%d]: %w", i, err)
		}
		for _, key := range []string{"HostedZoneId", "HostedZoneName"} {
			if v := cfnComputeString(record, key); v != "" && v != cfnComputeString(p, key) {
				return nil, fmt.Errorf("RecordSets[%d].%s must match the group's %s", i, key, key)
			}
		}
		if err := cfnRoute53ValidateRecord(record); err != nil {
			return nil, fmt.Errorf("RecordSets[%d]: %w", i, err)
		}
		rr, _ := cfnRoute53Desired(record)
		key := cfnRoute53Key(rr)
		if seen[key] {
			return nil, fmt.Errorf("RecordSets[%d] duplicates another record set", i)
		}
		seen[key] = true
		out = append(out, rr)
	}
	return out, nil
}
func (h cfnRoute53RecordSetGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "HostedZoneId", "HostedZoneName"), nil
}
func cfnRoute53ParseGroupID(id string) (zoneID, claim string, err error) {
	zoneID, claim, ok := strings.Cut(id, "|")
	if !ok || zoneID == "" || !strings.HasPrefix(claim, cfnRoute53GroupClaimPrefix) {
		return "", "", fmt.Errorf("invalid record set group identifier %q", id)
	}
	return cfnRoute53CleanID(zoneID), claim, nil
}
func (h cfnRoute53RecordSetGroup) apply(ctx context.Context, r cloudformation.ResourceRequest, zoneID, claim string) (cloudformation.ResourceResult, error) {
	desired, err := cfnRoute53GroupRecords(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	records, owners, err := cfnRoute53Records(ctx, h.commands, zoneID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	change, err := cfnRoute53Reconcile(ctx, h.commands, zoneID, claim, true, cfnRoute53OwnedBy(records, owners, claim), desired, cfnComputeString(r.Properties, "Comment"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cloudformation.ResourceResult{PhysicalID: zoneID + "|" + claim, Ref: r.LogicalID, Attributes: map[string]any{}}
	if change != "" {
		result.Attributes["Id"] = change
	}
	return result, nil
}
func (h cfnRoute53RecordSetGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	zoneID, err := cfnRoute53ZoneID(ctx, h.commands, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.apply(ctx, r, zoneID, cfnTrustClaim(r, "recordsetgroup"))
	return result, cfnResourceCreateOwnedError(r, err)
}
func (h cfnRoute53RecordSetGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::Route53::RecordSetGroup", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	zoneID, claim, err := cfnRoute53ParseGroupID(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if !r.CloudControl && claim != cfnTrustClaim(r, "recordsetgroup") {
		return cloudformation.ResourceResult{}, fmt.Errorf("record set group %s is not owned by this stack resource incarnation", r.PhysicalID)
	}
	desiredZone, err := cfnRoute53ZoneID(ctx, h.commands, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if desiredZone != zoneID {
		return cloudformation.ResourceResult{}, fmt.Errorf("%w: AWS::Route53::RecordSetGroup hosted zone", cloudformation.ErrCreateOnly)
	}
	return h.apply(ctx, r, zoneID, claim)
}
func (h cfnRoute53RecordSetGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	zoneID, claim, err := cfnRoute53ParseGroupID(r.PhysicalID)
	if err != nil {
		return err
	}
	if !r.CloudControl && claim != cfnTrustClaim(r, "recordsetgroup") {
		return fmt.Errorf("record set group %s is not owned by this stack resource incarnation", r.PhysicalID)
	}
	records, owners, err := cfnRoute53Records(ctx, h.commands, zoneID)
	if err != nil {
		if cfnRoute53Missing(err) && !r.CloudControl {
			return nil
		}
		return err
	}
	owned := cfnRoute53OwnedBy(records, owners, claim)
	if len(owned) == 0 {
		if r.CloudControl {
			return cfnTrustNotFound("record set group " + r.PhysicalID + " does not exist")
		}
		return nil
	}
	_, err = cfnRoute53Reconcile(ctx, h.commands, zoneID, claim, true, owned, nil, "")
	return err
}
func cfnRoute53GroupProperties(id, zoneID string, owned []r53.ResourceRecordSet) cloudformation.Properties {
	records := make([]any, 0, len(owned))
	for _, rr := range owned {
		records = append(records, cfnRoute53RecordProperties(rr))
	}
	return cloudformation.Properties{"Id": id, "HostedZoneId": zoneID, "RecordSets": records}
}
func (h cfnRoute53RecordSetGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	zoneID, claim, err := cfnRoute53ParseGroupID(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	records, owners, err := cfnRoute53Records(ctx, h.commands, zoneID)
	if err != nil {
		return nil, err
	}
	owned := cfnRoute53OwnedBy(records, owners, claim)
	if len(owned) == 0 {
		return nil, cfnTrustNotFound("record set group " + r.PhysicalID + " does not exist")
	}
	return cfnRoute53GroupProperties(r.PhysicalID, zoneID, owned), nil
}
func (h cfnRoute53RecordSetGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	zones, err := cfnRoute53Zones(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, z := range zones {
		zoneID := cfnRoute53CleanID(cfnComputeValue(z.Id))
		records, owners, err := cfnRoute53Records(ctx, h.commands, zoneID)
		if err != nil {
			return nil, err
		}
		groups := map[string][]r53.ResourceRecordSet{}
		for _, rr := range records {
			if claim := owners[cfnRoute53Key(rr)]; strings.HasPrefix(claim, cfnRoute53GroupClaimPrefix) {
				groups[claim] = append(groups[claim], rr)
			}
		}
		claims := make([]string, 0, len(groups))
		for claim := range groups {
			claims = append(claims, claim)
		}
		sort.Strings(claims)
		for _, claim := range claims {
			id := zoneID + "|" + claim
			out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cfnRoute53GroupProperties(id, zoneID, groups[claim])})
		}
	}
	return out, nil
}
