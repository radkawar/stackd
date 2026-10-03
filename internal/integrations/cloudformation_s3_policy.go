package integrations

import (
	"context"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/services/cloudformation"
)

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
func (h cfnS3BucketPolicy) policy(ctx context.Context, r cloudformation.ResourceRequest, name string) (string, error) {
	out, err := cfnMessagingCall[api.GetBucketPolicyOutput](ctx, h.commands, "s3", "GetBucketPolicy", &api.GetBucketPolicyInput{Bucket: new(api.BucketName(name)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))})
	if cfnMessagingMissing(err, "NoSuchBucketPolicy") {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if out.Policy == nil {
		return "", nil
	}
	return string(*out.Policy), nil
}
func (h cfnS3BucketPolicy) apply(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
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
	bucket := cfnS3Bucket(h)
	tags, err := bucket.tags(ctx, r, p.Bucket)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	marker := tags[cfnMessagingPolicyTag]
	if marker != "" && marker != cfnMessagingMarker(r) {
		return cloudformation.ResourceResult{}, fmt.Errorf("bucket policy is owned by another resource")
	}
	current, err := h.policy(ctx, r, p.Bucket)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if marker == "" && current != "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("bucket already has an unrelated policy")
	}
	if marker == "" {
		tags[cfnMessagingPolicyTag] = cfnMessagingMarker(r)
		if err := bucket.putTags(ctx, r, p.Bucket, tags); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	result := cfnMessagingResult(p.Bucket)
	if err := cfnMessagingExec(ctx, h.commands, "s3", "PutBucketPolicy", &api.PutBucketPolicyInput{Bucket: new(api.BucketName(p.Bucket)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account)), Policy: new(api.Policy(doc))}); err != nil {
		if marker == "" {
			delete(tags, cfnMessagingPolicyTag)
			err = errors.Join(err, bucket.putTags(ctx, r, p.Bucket, tags))
		}
		return result, err
	}
	return result, nil
}
func (h cfnS3BucketPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.apply(ctx, r)
}
func (h cfnS3BucketPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cfnMessagingResult(r.PhysicalID), err
	}
	if replace {
		return cfnMessagingResult(r.PhysicalID), fmt.Errorf("bucket policy update requires replacement")
	}
	return h.apply(ctx, r)
}
func (h cfnS3BucketPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	var p cfnS3BucketPolicyProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return err
	}
	bucket := cfnS3Bucket(h)
	tags, err := bucket.tags(ctx, r, p.Bucket)
	if cfnMessagingMissing(err, "NoSuchBucket") {
		return nil
	}
	if err != nil {
		return err
	}
	marker := tags[cfnMessagingPolicyTag]
	if marker == "" {
		return nil
	}
	if marker != cfnMessagingMarker(r) {
		return fmt.Errorf("refusing to delete another resource's bucket policy")
	}
	current, err := h.policy(ctx, r, p.Bucket)
	if err != nil {
		return err
	}
	doc, err := cfnMessagingPolicy(p.PolicyDocument)
	if err != nil {
		return err
	}
	if current != "" && !cfnMessagingEqualJSON(current, doc) {
		return fmt.Errorf("bucket policy changed outside this CloudFormation resource")
	}
	if current != "" {
		if err := cfnMessagingExec(ctx, h.commands, "s3", "DeleteBucketPolicy", &api.DeleteBucketPolicyInput{Bucket: new(api.BucketName(p.Bucket)), ExpectedBucketOwner: new(api.AccountId(r.Scope.Account))}); err != nil {
			return err
		}
	}
	delete(tags, cfnMessagingPolicyTag)
	return bucket.putTags(ctx, r, p.Bucket, tags)
}
