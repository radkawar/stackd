package integrations

import (
	"context"
	"fmt"
	"reflect"

	api "stackd/internal/awsapi/s3control"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/s3"
)

// cfnS3AccessPoint provisions general-purpose bucket access points through the
// S3 Control owner. The owner stores this incarnation's private claim on the
// access point row; tags are public metadata and never prove ownership. The
// owner retains access point identity, policy, public-access settings and
// authorization.
type cfnS3AccessPoint struct{ commands StepFunctionsCommands }
type cfnS3AccessPointPublicAccess struct {
	BlockPublicAcls       *cfnMessagingBool
	BlockPublicPolicy     *cfnMessagingBool
	IgnorePublicAcls      *cfnMessagingBool
	RestrictPublicBuckets *cfnMessagingBool
}
type cfnS3AccessPointProperties struct {
	Bucket                         string
	BucketAccountId                string
	Name                           string
	Policy                         cfnStorageDocument
	PublicAccessBlockConfiguration *cfnS3AccessPointPublicAccess
	Tags                           []cfnMessagingTag
	VpcConfiguration               *struct{ VpcId string }
}

func (h cfnS3AccessPoint) decode(raw cloudformation.Properties) (cfnS3AccessPointProperties, error) {
	var p cfnS3AccessPointProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	if len(p.Bucket) < 3 || len(p.Bucket) > 255 {
		return p, fmt.Errorf("property Bucket must be 3 through 255 characters")
	}
	if p.VpcConfiguration != nil && p.VpcConfiguration.VpcId == "" {
		return p, fmt.Errorf("VpcConfiguration requires VpcId")
	}
	if p.Policy != nil {
		if _, err := cfnMessagingPolicy(p.Policy); err != nil {
			return p, err
		}
	}
	_, err := cfnMessagingTags(cloudformation.ResourceRequest{}, p.Tags)
	return p, err
}
func (h cfnS3AccessPoint) Validate(raw cloudformation.Properties) error {
	_, err := h.decode(raw)
	return err
}

// Replacement follows the registry create-only properties. A customer-supplied
// name cannot be replaced in place because both incarnations share it.
func (h cfnS3AccessPoint) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	changed := cfnMessagingChanged(a, b, "Name", "Bucket", "BucketAccountId", "VpcConfiguration")
	named, _ := a["Name"].(string)
	return cfnMessagingReplacement(named != "" && named == b["Name"], changed)
}
func (h cfnS3AccessPoint) name(r cloudformation.ResourceRequest, p cfnS3AccessPointProperties) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	if p.Name != "" {
		return p.Name
	}
	return cfnMessagingName(r, 50, false)
}
func (h cfnS3AccessPoint) arn(r cloudformation.ResourceRequest, name string) string {
	return "arn:" + r.Scope.Partition + ":s3:" + r.Scope.Region + ":" + r.Scope.Account + ":accesspoint/" + name
}

// cfnS3AccessPointContext binds this incarnation's access point claim. Cloud
// Control creates claim their access point; other Cloud Control operations act
// on an existing access point under current IAM alone.
func cfnS3AccessPointContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return s3.WithCloudFormationAccessPointOwner(ctx, cfnS3Claim(r))
}
func (h cfnS3AccessPoint) get(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.GetAccessPointOutput, error) {
	return cfnMessagingCall[api.GetAccessPointOutput](ctx, h.commands, "s3control", "GetAccessPoint", &api.GetAccessPointInput{AccountId: new(api.AccountId(r.Scope.Account)), Name: new(api.AccessPointName(name))})
}
func (h cfnS3AccessPoint) tags(ctx context.Context, r cloudformation.ResourceRequest, name string) (map[string]string, error) {
	out, err := cfnMessagingCall[api.ListTagsForResourceOutput](ctx, h.commands, "s3control", "ListTagsForResource", &api.ListTagsForResourceInput{AccountId: new(api.AccountId(r.Scope.Account)), ResourceArn: new(api.S3ResourceArn(h.arn(r, name)))})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.Tags))
	for _, tag := range out.Tags {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func cfnS3ControlTags(tags map[string]string) api.TagList {
	out := make(api.TagList, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		out = append(out, api.Tag{Key: new(api.TagKeyString(key)), Value: new(api.TagValueString(tags[key]))})
	}
	return out
}
func (p *cfnS3AccessPointPublicAccess) native() *api.PublicAccessBlockConfiguration {
	if p == nil {
		return nil
	}
	setting := func(value *cfnMessagingBool) *api.Setting {
		if value == nil {
			return nil
		}
		return new(api.Setting(bool(*value)))
	}
	return &api.PublicAccessBlockConfiguration{BlockPublicAcls: setting(p.BlockPublicAcls), BlockPublicPolicy: setting(p.BlockPublicPolicy), IgnorePublicAcls: setting(p.IgnorePublicAcls), RestrictPublicBuckets: setting(p.RestrictPublicBuckets)}
}

// cfnS3AccessPointPublicAccessSettings compares effective settings: an omitted
// configuration and omitted members mean the S3 default of true.
func cfnS3AccessPointPublicAccessSettings(p *cfnS3AccessPointPublicAccess) [4]bool {
	out := [4]bool{true, true, true, true}
	if p == nil {
		return out
	}
	for i, value := range []*cfnMessagingBool{p.BlockPublicAcls, p.BlockPublicPolicy, p.IgnorePublicAcls, p.RestrictPublicBuckets} {
		if value != nil {
			out[i] = bool(*value)
		}
	}
	return out
}
func (h cfnS3AccessPoint) putPolicy(ctx context.Context, r cloudformation.ResourceRequest, name string, policy, previous cfnStorageDocument) error {
	if policy == nil {
		if previous == nil {
			return nil
		}
		err := cfnMessagingExec(ctx, h.commands, "s3control", "DeleteAccessPointPolicy", &api.DeleteAccessPointPolicyInput{AccountId: new(api.AccountId(r.Scope.Account)), Name: new(api.AccessPointName(name))})
		if cfnMessagingMissing(err, "NoSuchAccessPointPolicy") {
			return nil
		}
		return err
	}
	document, err := cfnMessagingPolicy(policy)
	if err != nil {
		return err
	}
	return cfnMessagingExec(ctx, h.commands, "s3control", "PutAccessPointPolicy", &api.PutAccessPointPolicyInput{AccountId: new(api.AccountId(r.Scope.Account)), Name: new(api.AccessPointName(name)), Policy: new(api.Policy(document))})
}
func (h cfnS3AccessPoint) result(ctx context.Context, r cloudformation.ResourceRequest, name string) (cloudformation.ResourceResult, error) {
	result := cfnMessagingResult(name)
	out, err := h.get(ctx, r, name)
	if err != nil {
		return result, err
	}
	result.Attributes = map[string]any{"Name": name, "Arn": cfnComputeValue(out.AccessPointArn), "Alias": cfnComputeValue(out.Alias), "NetworkOrigin": cfnComputeValue(out.NetworkOrigin)}
	return result, nil
}
func (h cfnS3AccessPoint) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.decode(r.Properties)
	if err != nil {
		if admitted, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	name := h.name(r, p)
	tags, err := cfnMessagingTags(r, p.Tags)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnS3AccessPointContext(ctx, r, true)
	input := &api.CreateAccessPointInput{AccountId: new(api.AccountId(r.Scope.Account)), Name: new(api.AccessPointName(name)), Bucket: new(api.BucketName(p.Bucket)), PublicAccessBlockConfiguration: p.PublicAccessBlockConfiguration.native(), Tags: cfnS3ControlTags(tags)}
	if p.BucketAccountId != "" {
		input.BucketAccountId = new(api.AccountId(p.BucketAccountId))
	}
	if p.VpcConfiguration != nil {
		input.VpcConfiguration = &api.VpcConfiguration{VpcId: new(api.VpcId(p.VpcConfiguration.VpcId))}
	}
	// The owner admits a new access point with this claim, or returns the one
	// this exact incarnation already committed; any other is rejected.
	if err := cfnMessagingExec(ctx, h.commands, "s3control", "CreateAccessPoint", input); err != nil {
		if cfnMessagingMissing(err, "AccessPointAlreadyOwnedByYou") {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		// A failed reply is not evidence that admission did not occur.
		if recovered, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	if err := h.putPolicy(ctx, r, name, p.Policy, nil); err != nil {
		return cfnMessagingResult(name), err
	}
	result, err := h.result(ctx, r, name)
	if err != nil {
		return cfnMessagingResult(name), err
	}
	return result, nil
}

// RecoverCreation observes only the access point whose private claim is this
// exact incarnation. A same-name access point with copied tags is foreign.
func (h cfnS3AccessPoint) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := h.name(r, cfnS3AccessPointProperties{Name: cfnComputeString(r.Properties, "Name")})
	result, err := h.result(cfnS3AccessPointContext(ctx, r, true), r, name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnStorageMissing(err, "NoSuchAccessPoint")
	}
	return result, nil
}
func (h cfnS3AccessPoint) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::S3::AccessPoint", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	ctx = cfnS3AccessPointContext(ctx, r, false)
	result := cfnMessagingResult(r.PhysicalID)
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replace {
		return result, fmt.Errorf("access point update requires replacement")
	}
	old, err := h.decode(r.Previous)
	if err != nil {
		return result, err
	}
	next, err := h.decode(r.Properties)
	if err != nil {
		return result, err
	}
	tags, err := h.tags(ctx, r, r.PhysicalID)
	if err != nil {
		return result, err
	}
	// TODO: Comeback S3 Control exposes no public access-point public-access
	// mutation; reject the change rather than reporting an unapplied update.
	if cfnS3AccessPointPublicAccessSettings(old.PublicAccessBlockConfiguration) != cfnS3AccessPointPublicAccessSettings(next.PublicAccessBlockConfiguration) {
		return result, fmt.Errorf("the S3 owner cannot change an access point PublicAccessBlockConfiguration after creation")
	}
	if !reflect.DeepEqual(old.Policy, next.Policy) || r.CloudControl {
		if err := h.putPolicy(ctx, r, r.PhysicalID, next.Policy, old.Policy); err != nil {
			return result, err
		}
	}
	wanted, err := cfnMessagingTags(r, next.Tags)
	if err != nil {
		return result, err
	}
	var removed api.TagKeyList
	for key := range tags {
		if _, keep := wanted[key]; !keep {
			removed = append(removed, api.TagKeyString(key))
		}
	}
	arn := new(api.S3ResourceArn(h.arn(r, r.PhysicalID)))
	if len(removed) != 0 {
		if err := cfnMessagingExec(ctx, h.commands, "s3control", "UntagResource", &api.UntagResourceInput{AccountId: new(api.AccountId(r.Scope.Account)), ResourceArn: arn, TagKeys: removed}); err != nil {
			return result, err
		}
	}
	if len(wanted) != 0 {
		if err := cfnMessagingExec(ctx, h.commands, "s3control", "TagResource", &api.TagResourceInput{AccountId: new(api.AccountId(r.Scope.Account)), ResourceArn: arn, Tags: cfnS3ControlTags(wanted)}); err != nil {
			return result, err
		}
	}
	return h.result(ctx, r, r.PhysicalID)
}
func (h cfnS3AccessPoint) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		var p cfnS3AccessPointProperties
		if err := cfnMessagingDecode(r.Properties, &p); err != nil {
			return err
		}
		r.PhysicalID = h.name(r, p)
	}
	err := cfnMessagingExec(cfnS3AccessPointContext(ctx, r, false), h.commands, "s3control", "DeleteAccessPoint", &api.DeleteAccessPointInput{AccountId: new(api.AccountId(r.Scope.Account)), Name: new(api.AccessPointName(r.PhysicalID))})
	if cfnMessagingMissing(err, "NoSuchAccessPoint") && !r.CloudControl {
		return nil
	}
	return cfnStorageMissing(err, "NoSuchAccessPoint")
}
func (h cfnS3AccessPoint) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.get(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, cfnStorageMissing(err, "NoSuchAccessPoint")
	}
	return h.project(ctx, r, out)
}
func (h cfnS3AccessPoint) project(ctx context.Context, r cloudformation.ResourceRequest, out *api.GetAccessPointOutput) (cloudformation.Properties, error) {
	name := cfnComputeValue(out.Name)
	p := cloudformation.Properties{"Name": name, "Bucket": cfnComputeValue(out.Bucket), "BucketAccountId": cfnComputeValue(out.BucketAccountId), "Arn": cfnComputeValue(out.AccessPointArn), "Alias": cfnComputeValue(out.Alias), "NetworkOrigin": cfnComputeValue(out.NetworkOrigin)}
	if out.VpcConfiguration != nil {
		p["VpcConfiguration"] = map[string]any{"VpcId": cfnComputeValue(out.VpcConfiguration.VpcId)}
	}
	if block := out.PublicAccessBlockConfiguration; block != nil {
		settings := map[string]any{}
		for key, value := range map[string]*api.Setting{"BlockPublicAcls": block.BlockPublicAcls, "BlockPublicPolicy": block.BlockPublicPolicy, "IgnorePublicAcls": block.IgnorePublicAcls, "RestrictPublicBuckets": block.RestrictPublicBuckets} {
			if value != nil {
				settings[key] = bool(*value)
			}
		}
		p["PublicAccessBlockConfiguration"] = settings
	}
	policy, err := cfnMessagingCall[api.GetAccessPointPolicyOutput](ctx, h.commands, "s3control", "GetAccessPointPolicy", &api.GetAccessPointPolicyInput{AccountId: new(api.AccountId(r.Scope.Account)), Name: new(api.AccessPointName(name))})
	if err != nil && !cfnMessagingMissing(err, "NoSuchAccessPointPolicy") {
		return nil, err
	}
	if err == nil && policy.Policy != nil {
		var document map[string]any
		if err := cfnStorageJSON(string(*policy.Policy), &document); err != nil {
			return nil, err
		}
		p["Policy"] = document
	}
	tags, err := h.tags(ctx, r, name)
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnS3AccessPoint) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var resources []cloudformation.ResourceDescription
	input := &api.ListAccessPointsInput{AccountId: new(api.AccountId(r.Scope.Account)), MaxResults: new(api.MaxResults(1000))}
	for {
		out, err := cfnMessagingCall[api.ListAccessPointsOutput](ctx, h.commands, "s3control", "ListAccessPoints", input)
		if err != nil {
			return nil, err
		}
		for _, point := range out.AccessPointList {
			name := cfnComputeValue(point.Name)
			current, err := h.get(ctx, r, name)
			if err != nil {
				return nil, err
			}
			p, err := h.project(ctx, r, current)
			if err != nil {
				return nil, err
			}
			resources = append(resources, cloudformation.ResourceDescription{Identifier: name, Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return resources, nil
		}
		input.NextToken = out.NextToken
	}
}

var _ cloudformation.ResourceReader = cfnS3AccessPoint{}
