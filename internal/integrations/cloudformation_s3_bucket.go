package integrations

import (
	"context"
	"encoding/json"
	"fmt"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/s3"
)

// cfnS3Claim is the private native provenance of one exact resource
// incarnation. The S3 owner stores it on the bucket, bucket-policy edge or
// access point row in the transaction that creates it; it is never a tag.
func cfnS3Claim(r cloudformation.ResourceRequest) string {
	claim, _ := json.Marshal([]string{r.Type, r.StackID, r.LogicalID, r.Token})
	return string(claim)
}

// cfnS3BucketContext binds this incarnation's bucket claim. Cloud Control
// creates claim their new bucket; other Cloud Control operations act on an
// existing bucket under current IAM alone.
func cfnS3BucketContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return s3.WithCloudFormationBucketOwner(ctx, cfnS3Claim(r))
}

type cfnS3Bucket struct{ commands StepFunctionsCommands }
type cfnS3BucketProperties struct {
	BucketName              string
	Tags                    []cfnMessagingTag
	AccessControl           string
	VersioningConfiguration *struct{ Status string }
	OwnershipControls       *struct {
		Rules []struct{ ObjectOwnership string }
	}
	PublicAccessBlockConfiguration *struct {
		BlockPublicAcls       *cfnMessagingBool
		BlockPublicPolicy     *cfnMessagingBool
		IgnorePublicAcls      *cfnMessagingBool
		RestrictPublicBuckets *cfnMessagingBool
	}
	BucketEncryption          *struct{ ServerSideEncryptionConfiguration []cfnS3EncryptionRule }
	NotificationConfiguration *cfnS3Notifications
	LifecycleConfiguration    *cfnS3Lifecycle
	CorsConfiguration         *cfnS3Cors
}
type cfnS3EncryptionRule struct {
	ServerSideEncryptionByDefault *struct {
		SSEAlgorithm   string
		KMSMasterKeyID string
	}
	BucketKeyEnabled       *cfnMessagingBool
	BlockedEncryptionTypes *struct{ EncryptionType []string }
}

func cfnS3ACL(value string) string {
	switch value {
	case "Private":
		return "private"
	case "PublicRead":
		return "public-read"
	case "PublicReadWrite":
		return "public-read-write"
	case "AuthenticatedRead":
		return "authenticated-read"
	case "LogDeliveryWrite":
		return "log-delivery-write"
	case "BucketOwnerRead":
		return "bucket-owner-read"
	case "BucketOwnerFullControl":
		return "bucket-owner-full-control"
	default:
		return ""
	}
}
func (h cfnS3Bucket) Validate(raw cloudformation.Properties) error {
	var p cfnS3BucketProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return err
	}
	if _, supplied := raw["BucketName"]; supplied && (len(p.BucketName) < 3 || len(p.BucketName) > 63) {
		return fmt.Errorf("BucketName must be 3 through 63 characters")
	}
	if p.AccessControl != "" && cfnS3ACL(p.AccessControl) == "" {
		return fmt.Errorf("unsupported AccessControl; AwsExecRead is not implemented by the S3 owner")
	}
	if p.VersioningConfiguration != nil && p.VersioningConfiguration.Status != "Enabled" && p.VersioningConfiguration.Status != "Suspended" {
		return fmt.Errorf("VersioningConfiguration.Status must be Enabled or Suspended")
	}
	if controls := p.OwnershipControls; controls != nil {
		if len(controls.Rules) != 1 {
			return fmt.Errorf("OwnershipControls requires exactly one rule")
		}
		value := controls.Rules[0].ObjectOwnership
		if value != "BucketOwnerEnforced" && value != "BucketOwnerPreferred" && value != "ObjectWriter" {
			return fmt.Errorf("invalid ObjectOwnership")
		}
	}
	if encryption := p.BucketEncryption; encryption != nil {
		if len(encryption.ServerSideEncryptionConfiguration) != 1 {
			return fmt.Errorf("BucketEncryption requires exactly one rule")
		}
		rule := encryption.ServerSideEncryptionConfiguration[0]
		if defaults := rule.ServerSideEncryptionByDefault; defaults != nil {
			if defaults.SSEAlgorithm != "AES256" && defaults.SSEAlgorithm != "aws:kms" {
				return fmt.Errorf("bucket encryption supports AES256 and aws:kms only")
			}
			if defaults.SSEAlgorithm == "AES256" && defaults.KMSMasterKeyID != "" {
				return fmt.Errorf("KMSMasterKeyID requires aws:kms")
			}
			if defaults.SSEAlgorithm == "aws:kms" && rule.BucketKeyEnabled != nil && bool(*rule.BucketKeyEnabled) {
				return fmt.Errorf("S3 KMS Bucket Keys are not implemented by the S3 owner")
			}
		}
		if blocked := rule.BlockedEncryptionTypes; blocked != nil {
			if len(blocked.EncryptionType) != 1 || blocked.EncryptionType[0] != "NONE" && blocked.EncryptionType[0] != "SSE-C" {
				return fmt.Errorf("BlockedEncryptionTypes requires exactly one NONE or SSE-C value")
			}
		}
	}
	if _, err := p.NotificationConfiguration.native(); err != nil {
		return err
	}
	if _, err := p.LifecycleConfiguration.native(); err != nil {
		return err
	}
	if _, err := p.CorsConfiguration.native(); err != nil {
		return err
	}
	_, err := cfnMessagingTags(cloudformation.ResourceRequest{}, p.Tags)
	return err
}
func (h cfnS3Bucket) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingChanged(a, b, "BucketName"), nil
}
func cfnS3NativeTags(tags map[string]string) api.TagSet {
	out := make(api.TagSet, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		out = append(out, api.Tag{Key: new(api.ObjectKey(key)), Value: new(api.Value(tags[key]))})
	}
	return out
}
func (h cfnS3Bucket) tags(ctx context.Context, r cloudformation.ResourceRequest, name string) (map[string]string, error) {
	out, err := cfnMessagingCall[api.GetBucketTaggingOutput](ctx, h.commands, "s3", "GetBucketTagging", &api.GetBucketTaggingInput{Bucket: new(api.BucketName(name)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))})
	if cfnMessagingMissing(err, "NoSuchTagSet") {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.TagSet))
	for _, tag := range out.TagSet {
		tags[string(*tag.Key)] = string(*tag.Value)
	}
	return tags, nil
}
func (h cfnS3Bucket) putTags(ctx context.Context, r cloudformation.ResourceRequest, name string, tags map[string]string) error {
	return cfnMessagingExec(ctx, h.commands, "s3", "PutBucketTagging", &api.PutBucketTaggingInput{Bucket: new(api.BucketName(name)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account)), Tagging: &api.Tagging{TagSet: cfnS3NativeTags(tags)}})
}
func (h cfnS3Bucket) result(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	out := cfnMessagingResult(name)
	suffix := "amazonaws.com"
	if r.Scope.Partition == "aws-cn" {
		suffix = "amazonaws.com.cn"
	}
	out.Attributes = map[string]any{"Arn": fmt.Sprintf("arn:%s:s3:::%s", r.Scope.Partition, name), "DomainName": name + ".s3." + suffix, "RegionalDomainName": name + ".s3." + r.Scope.Region + "." + suffix, "DualStackDomainName": name + ".s3.dualstack." + r.Scope.Region + "." + suffix}
	return out
}
func (h cfnS3Bucket) apply(ctx context.Context, r cloudformation.ResourceRequest, p, old cfnS3BucketProperties, name string) error {
	bucket := new(api.BucketName(name))
	owner := new(api.AccountId(r.Scope.Account))
	// Clear grants before enabling BucketOwnerEnforced, which rejects a
	// transition while non-owner ACL grants still exist.
	if (p.AccessControl == "" || p.AccessControl == "Private") && old.AccessControl != "" && old.AccessControl != "Private" {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketAcl", &api.PutBucketAclInput{Bucket: bucket, ExpectedBucketOwner: owner, ACL: new(api.BucketCannedACL("private"))}); err != nil {
			return err
		}
	}
	if p.OwnershipControls != nil {
		value := p.OwnershipControls.Rules[0].ObjectOwnership
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketOwnershipControls", &api.PutBucketOwnershipControlsInput{Bucket: bucket, ExpectedBucketOwner: owner, OwnershipControls: &api.OwnershipControls{Rules: api.OwnershipControlsRules{{ObjectOwnership: new(api.ObjectOwnership(value))}}}}); err != nil {
			return err
		}
	} else if old.OwnershipControls != nil {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "DeleteBucketOwnershipControls", &api.DeleteBucketOwnershipControlsInput{Bucket: bucket, ExpectedBucketOwner: owner}); err != nil {
			return err
		}
	}
	if p.PublicAccessBlockConfiguration != nil {
		pab := p.PublicAccessBlockConfiguration
		setting := func(value *cfnMessagingBool) *api.Setting {
			if value == nil {
				return nil
			}
			return new(api.Setting(bool(*value)))
		}
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutPublicAccessBlock", &api.PutPublicAccessBlockInput{Bucket: bucket, ExpectedBucketOwner: owner, PublicAccessBlockConfiguration: &api.PublicAccessBlockConfiguration{BlockPublicAcls: setting(pab.BlockPublicAcls), BlockPublicPolicy: setting(pab.BlockPublicPolicy), IgnorePublicAcls: setting(pab.IgnorePublicAcls), RestrictPublicBuckets: setting(pab.RestrictPublicBuckets)}}); err != nil {
			return err
		}
	} else if old.PublicAccessBlockConfiguration != nil {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "DeletePublicAccessBlock", &api.DeletePublicAccessBlockInput{Bucket: bucket, ExpectedBucketOwner: owner}); err != nil {
			return err
		}
	}
	if p.AccessControl != "" && p.AccessControl != "Private" {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketAcl", &api.PutBucketAclInput{Bucket: bucket, ExpectedBucketOwner: owner, ACL: new(api.BucketCannedACL(cfnS3ACL(p.AccessControl)))}); err != nil {
			return err
		}
	}
	if p.VersioningConfiguration != nil || old.VersioningConfiguration != nil {
		status := "Suspended"
		if p.VersioningConfiguration != nil {
			status = p.VersioningConfiguration.Status
		}
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketVersioning", &api.PutBucketVersioningInput{Bucket: bucket, ExpectedBucketOwner: owner, VersioningConfiguration: &api.VersioningConfiguration{Status: new(api.BucketVersioningStatus(status))}}); err != nil {
			return err
		}
	}
	if p.BucketEncryption != nil {
		rule := p.BucketEncryption.ServerSideEncryptionConfiguration[0]
		native := api.ServerSideEncryptionRule{}
		if defaults := rule.ServerSideEncryptionByDefault; defaults != nil {
			native.ApplyServerSideEncryptionByDefault = &api.ServerSideEncryptionByDefault{SSEAlgorithm: new(api.ServerSideEncryption(defaults.SSEAlgorithm))}
			if defaults.KMSMasterKeyID != "" {
				native.ApplyServerSideEncryptionByDefault.KMSMasterKeyID = new(api.SSEKMSKeyId(defaults.KMSMasterKeyID))
			}
		}
		if rule.BucketKeyEnabled != nil {
			native.BucketKeyEnabled = new(api.BucketKeyEnabled(bool(*rule.BucketKeyEnabled)))
		}
		if rule.BlockedEncryptionTypes != nil {
			native.BlockedEncryptionTypes = &api.BlockedEncryptionTypes{}
			for _, value := range rule.BlockedEncryptionTypes.EncryptionType {
				native.BlockedEncryptionTypes.EncryptionType = append(native.BlockedEncryptionTypes.EncryptionType, api.EncryptionType(value))
			}
		}
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketEncryption", &api.PutBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner, ServerSideEncryptionConfiguration: &api.ServerSideEncryptionConfiguration{Rules: api.ServerSideEncryptionRules{native}}}); err != nil {
			return err
		}
	} else if old.BucketEncryption != nil {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "DeleteBucketEncryption", &api.DeleteBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner}); err != nil {
			return err
		}
	}
	if p.NotificationConfiguration != nil || old.NotificationConfiguration != nil {
		notifications, err := p.NotificationConfiguration.native()
		if err != nil {
			return err
		}
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketNotificationConfiguration", &api.PutBucketNotificationConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner, NotificationConfiguration: notifications}); err != nil {
			return err
		}
	}
	if p.LifecycleConfiguration != nil {
		input, err := p.LifecycleConfiguration.native()
		if err != nil {
			return err
		}
		input.Bucket, input.ExpectedBucketOwner = bucket, owner
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketLifecycleConfiguration", input); err != nil {
			return err
		}
	} else if old.LifecycleConfiguration != nil {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "DeleteBucketLifecycle", &api.DeleteBucketLifecycleInput{Bucket: bucket, ExpectedBucketOwner: owner}); err != nil {
			return err
		}
	}
	if p.CorsConfiguration != nil {
		config, err := p.CorsConfiguration.native()
		if err != nil {
			return err
		}
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketCors", &api.PutBucketCorsInput{Bucket: bucket, ExpectedBucketOwner: owner, CORSConfiguration: config}); err != nil {
			return err
		}
	} else if old.CorsConfiguration != nil {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "DeleteBucketCors", &api.DeleteBucketCorsInput{Bucket: bucket, ExpectedBucketOwner: owner}); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnS3Bucket) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnS3BucketProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := p.BucketName
	if name == "" {
		name = cfnMessagingName(r, 63, false)
	}
	tags, err := cfnMessagingTags(r, p.Tags)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnS3BucketContext(ctx, r, true)
	input := &api.CreateBucketInput{Bucket: new(api.BucketName(name)), CreateBucketConfiguration: &api.CreateBucketConfiguration{Tags: cfnS3NativeTags(tags)}}
	if r.Scope.Region != "us-east-1" {
		input.CreateBucketConfiguration.LocationConstraint = new(api.BucketLocationConstraint(r.Scope.Region))
	}
	if p.OwnershipControls != nil {
		input.ObjectOwnership = new(api.ObjectOwnership(p.OwnershipControls.Rules[0].ObjectOwnership))
	}
	// The owner admits a new bucket with this claim, or returns the bucket this
	// exact incarnation already committed; any other bucket is rejected.
	if err := cfnMessagingExec(ctx, h.commands, "s3", "CreateBucket", input); err != nil {
		if cfnMessagingMissing(err, "BucketAlreadyOwnedByYou", "BucketAlreadyExists") {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		// A failed reply is not evidence that admission did not occur.
		if recovered, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return h.result(r, name), h.apply(ctx, r, p, cfnS3BucketProperties{}, name)
}

// RecoverCreation observes only the bucket whose private claim is this exact
// incarnation. A same-name bucket with copied tags is a foreign bucket.
func (h cfnS3Bucket) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeString(r.Properties, "BucketName")
	if name == "" {
		name = cfnMessagingName(r, 63, false)
	}
	ctx = cfnS3BucketContext(ctx, r, true)
	if _, err := cfnMessagingCall[api.GetBucketLocationOutput](ctx, h.commands, "s3", "GetBucketLocation", &api.GetBucketLocationInput{Bucket: new(api.BucketName(name)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))}); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(r, name), nil
}
func (h cfnS3Bucket) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::S3::Bucket", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		name, err := cfnS3BucketIdentifier(r)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		r.PhysicalID = name
	}
	ctx = cfnS3BucketContext(ctx, r, false)
	result := h.result(r, r.PhysicalID)
	replacement, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replacement {
		return result, fmt.Errorf("bucket update requires replacement")
	}
	var old, next cfnS3BucketProperties
	if err := cfnMessagingDecode(r.Previous, &old); err != nil {
		return result, err
	}
	if err := cfnMessagingDecode(r.Properties, &next); err != nil {
		return result, err
	}
	if err := h.apply(ctx, r, next, old, r.PhysicalID); err != nil {
		return result, err
	}
	wanted, err := cfnMessagingTags(r, next.Tags)
	if err != nil {
		return result, err
	}
	if err := h.putTags(ctx, r, r.PhysicalID, wanted); err != nil {
		return result, err
	}
	return result, nil
}
func (h cfnS3Bucket) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.CloudControl {
		name, err := cfnS3BucketIdentifier(r)
		if err != nil {
			return err
		}
		r.PhysicalID = name
	}
	err := cfnMessagingExec(cfnS3BucketContext(ctx, r, false), h.commands, "s3", "DeleteBucket", &api.DeleteBucketInput{Bucket: new(api.BucketName(r.PhysicalID)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))})
	if cfnMessagingMissing(err, "NoSuchBucket") && !r.CloudControl {
		return nil
	}
	return err
}
