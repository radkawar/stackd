package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/services/cloudformation"
)

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
}
type cfnS3EncryptionRule struct {
	ServerSideEncryptionByDefault *struct {
		SSEAlgorithm   string
		KMSMasterKeyID string
	}
	BucketKeyEnabled       *cfnMessagingBool
	BlockedEncryptionTypes *struct{ EncryptionType []string }
}
type cfnS3Lifecycle struct{ Rules []cfnS3LifecycleRule }
type cfnS3LifecycleRule struct {
	ID                          string `json:"Id"`
	Status, Prefix              string
	NoncurrentVersionExpiration *struct {
		NoncurrentDays          cfnMessagingInt
		NewerNoncurrentVersions *cfnMessagingInt
	}
	AbortIncompleteMultipartUpload *struct{ DaysAfterInitiation cfnMessagingInt }
}

func (p *cfnS3Lifecycle) native() (*api.BucketLifecycleConfiguration, error) {
	if p == nil {
		return nil, nil
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("LifecycleConfiguration requires Rules")
	}
	out := &api.BucketLifecycleConfiguration{}
	for _, rule := range p.Rules {
		if rule.Status != "Enabled" && rule.Status != "Disabled" {
			return nil, fmt.Errorf("lifecycle rule Status must be Enabled or Disabled")
		}
		if rule.NoncurrentVersionExpiration == nil && rule.AbortIncompleteMultipartUpload == nil {
			return nil, fmt.Errorf("lifecycle rule requires a supported action")
		}
		next := api.LifecycleRule{ID: new(api.ID(rule.ID)), Status: new(api.ExpirationStatus(rule.Status)), Filter: &api.LifecycleRuleFilter{Prefix: new(api.Prefix(rule.Prefix))}}
		if value := rule.NoncurrentVersionExpiration; value != nil {
			if value.NoncurrentDays < 1 || value.NoncurrentDays > 2147483647 {
				return nil, fmt.Errorf("NoncurrentDays must be a positive 32-bit integer")
			}
			next.NoncurrentVersionExpiration = &api.NoncurrentVersionExpiration{NoncurrentDays: new(api.Days(value.NoncurrentDays))}
			if value.NewerNoncurrentVersions != nil {
				if *value.NewerNoncurrentVersions < 1 || *value.NewerNoncurrentVersions > 100 {
					return nil, fmt.Errorf("NewerNoncurrentVersions must be 1 through 100")
				}
				next.NoncurrentVersionExpiration.NewerNoncurrentVersions = new(api.VersionCount(*value.NewerNoncurrentVersions))
			}
		}
		if value := rule.AbortIncompleteMultipartUpload; value != nil {
			if value.DaysAfterInitiation < 1 || value.DaysAfterInitiation > 2147483647 {
				return nil, fmt.Errorf("DaysAfterInitiation must be a positive 32-bit integer")
			}
			next.AbortIncompleteMultipartUpload = &api.AbortIncompleteMultipartUpload{DaysAfterInitiation: new(api.DaysAfterInitiation(value.DaysAfterInitiation))}
		}
		out.Rules = append(out.Rules, next)
	}
	return out, nil
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
		config, err := p.LifecycleConfiguration.native()
		if err != nil {
			return err
		}
		if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketLifecycleConfiguration", &api.PutBucketLifecycleConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner, LifecycleConfiguration: config}); err != nil {
			return err
		}
	} else if old.LifecycleConfiguration != nil {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "DeleteBucketLifecycle", &api.DeleteBucketLifecycleInput{Bucket: bucket, ExpectedBucketOwner: owner}); err != nil {
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
	tags, err := h.tags(ctx, r, name)
	if err == nil {
		if err := cfnMessagingOwned(tags, r); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return h.result(r, name), h.apply(ctx, r, p, cfnS3BucketProperties{}, name)
	}
	if !cfnMessagingMissing(err, "NoSuchBucket") {
		return cloudformation.ResourceResult{}, err
	}
	tags, err = cfnMessagingTags(r, p.Tags)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := &api.CreateBucketInput{Bucket: new(api.BucketName(name)), CreateBucketConfiguration: &api.CreateBucketConfiguration{Tags: cfnS3NativeTags(tags)}}
	if r.Scope.Region != "us-east-1" {
		input.CreateBucketConfiguration.LocationConstraint = new(api.BucketLocationConstraint(r.Scope.Region))
	}
	if p.OwnershipControls != nil {
		input.ObjectOwnership = new(api.ObjectOwnership(p.OwnershipControls.Rules[0].ObjectOwnership))
	}
	if err := cfnMessagingExec(ctx, h.commands, "s3", "CreateBucket", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(r, name), h.apply(ctx, r, p, cfnS3BucketProperties{}, name)
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
	tags, err := h.tags(ctx, r, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err := cfnMessagingOwned(tags, r); !r.CloudControl && err != nil {
		return result, err
	}
	if err := h.apply(ctx, r, next, old, r.PhysicalID); err != nil {
		return result, err
	}
	wanted, err := cfnMessagingTags(r, next.Tags)
	if err != nil {
		return result, err
	}
	wanted = cfnResourceMutationTags(r, tags, wanted)
	for k, v := range tags {
		if strings.HasPrefix(k, "stackd:cloudformation:") && k != cfnMessagingOwnerTag && k != cfnMessagingTokenTag {
			wanted[k] = v
		}
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
	tags, err := h.tags(ctx, r, r.PhysicalID)
	if cfnMessagingMissing(err, "NoSuchBucket") && !r.CloudControl {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnMessagingOwned(tags, r); !r.CloudControl && err != nil {
		return err
	}
	return cfnMessagingExec(ctx, h.commands, "s3", "DeleteBucket", &api.DeleteBucketInput{Bucket: new(api.BucketName(r.PhysicalID)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))})
}
