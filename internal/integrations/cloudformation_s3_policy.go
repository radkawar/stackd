package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/s3"
)

// cfnS3BucketPolicy attaches a policy edge through the S3 owner, which stores
// this incarnation's private claim on the bucket with the policy. Stack
// operations replace or remove only the policy this claim attached; a bucket
// policy written by any other owner is never adopted or deleted.
type cfnS3BucketPolicy struct{ commands StepFunctionsCommands }
type cfnS3BucketPolicyProperties struct {
	Bucket         string
	PolicyDocument map[string]any
}

func (h cfnS3BucketPolicy) Validate(raw cloudformation.Properties) error {
	var p cfnS3BucketPolicyProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return err
	}
	if p.Bucket == "" {
		return fmt.Errorf("property Bucket is required")
	}
	_, err := cfnMessagingPolicy(p.PolicyDocument)
	return err
}
func (h cfnS3BucketPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingChanged(a, b, "Bucket"), nil
}

// cfnS3BucketPolicyContext binds this incarnation's policy-edge claim. Cloud
// Control creates claim their edge; other Cloud Control operations act on the
// bucket policy under current IAM alone.
func cfnS3BucketPolicyContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return s3.WithCloudFormationBucketPolicyOwner(ctx, cfnS3Claim(r))
}
func (h cfnS3BucketPolicy) apply(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var p cfnS3BucketPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	// The claim check and policy write commit in one owner transaction.
	ctx = cfnS3BucketPolicyContext(ctx, r, create)
	if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketPolicy", &api.PutBucketPolicyInput{Bucket: new(api.BucketName(p.Bucket)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account)), Policy: new(api.Policy(doc))}); err != nil {
		if !create {
			return cfnMessagingResult(p.Bucket), err
		}
		// A failed reply is not evidence that admission did not occur.
		if recovered, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnMessagingResult(p.Bucket), nil
}
func (h cfnS3BucketPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.apply(ctx, r, true)
}

// RecoverCreation observes only a policy edge carrying this exact incarnation's
// private claim; another writer's policy on the same bucket is not admission.
func (h cfnS3BucketPolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	bucket := cfnComputeString(r.Properties, "Bucket")
	ctx = cfnS3BucketPolicyContext(ctx, r, true)
	_, err := cfnMessagingCall[api.GetBucketPolicyOutput](ctx, h.commands, "s3", "GetBucketPolicy", &api.GetBucketPolicyInput{Bucket: new(api.BucketName(bucket)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))})
	if err != nil {
		return cloudformation.ResourceResult{}, cfnStorageMissing(err, "NoSuchBucket", "NoSuchBucketPolicy")
	}
	return cfnMessagingResult(bucket), nil
}
func (h cfnS3BucketPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cfnMessagingResult(r.PhysicalID), err
	}
	if replace {
		return cfnMessagingResult(r.PhysicalID), fmt.Errorf("bucket policy update requires replacement")
	}
	return h.apply(ctx, r, false)
}
func (h cfnS3BucketPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	var p cfnS3BucketPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return err
	}
	// Under a stack claim the owner removes only this incarnation's policy and
	// reports NoSuchBucketPolicy when the claim no longer has one.
	err := cfnMessagingExec(cfnS3BucketPolicyContext(ctx, r, false), h.commands, "s3", "DeleteBucketPolicy", &api.DeleteBucketPolicyInput{Bucket: new(api.BucketName(p.Bucket)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))})
	if cfnMessagingMissing(err, "NoSuchBucket", "NoSuchBucketPolicy") && !r.CloudControl {
		return nil
	}
	return err
}
