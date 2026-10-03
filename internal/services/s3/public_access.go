package s3

import (
	"context"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// AccountPolicySource supplies the published Organizations override. Managed
// policies enable or disable all four flags and prohibit account-level edits.
type AccountPolicySource interface {
	S3PublicAccessBlock(ctx context.Context, partition, accountID string) (enabled bool, managed bool, err error)
}

func (s *Service) putPublicAccessBlock(ctx context.Context, in *api.PutPublicAccessBlockInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutPublicAccessBlock", value(in.Bucket), "", "publicAccessBlock")
	out := &preparedResponse{}
	if p := in.PublicAccessBlockConfiguration; p != nil {
		params := map[string]any{"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"}
		for name, setting := range map[string]*api.Setting{
			"BlockPublicAcls":       p.BlockPublicAcls,
			"IgnorePublicAcls":      p.IgnorePublicAcls,
			"BlockPublicPolicy":     p.BlockPublicPolicy,
			"RestrictPublicBuckets": p.RestrictPublicBuckets,
		} {
			if setting != nil {
				params[name] = bool(*setting)
			}
		}
		c.params["PublicAccessBlockConfiguration"] = params
	}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketPublicAccessBlock", "", nil); w != nil {
			return w
		}
		p := in.PublicAccessBlockConfiguration
		if p == nil {
			return failure("MissingRequestBodyError", "Request Body is empty", 400)
		}
		if p.BlockPublicAcls == nil && p.IgnorePublicAcls == nil && p.BlockPublicPolicy == nil && p.RestrictPublicBuckets == nil {
			return failure("InvalidRequest", "Must specify at least one configuration.", 400)
		}
		// PUT replaces the complete configuration. An omitted setting is false,
		// whereas no supplied settings is a rejected request, not a deletion.
		b.PublicAccess = &PublicAccessBlock{
			BlockPublicACLs:       publicAccessSetting(p.BlockPublicAcls),
			IgnorePublicACLs:      publicAccessSetting(p.IgnorePublicAcls),
			BlockPublicPolicy:     publicAccessSetting(p.BlockPublicPolicy),
			RestrictPublicBuckets: publicAccessSetting(p.RestrictPublicBuckets),
		}
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return out.prepare(c, &api.PutPublicAccessBlockOutput{})
	})
	return out, wire
}

func publicAccessSetting[T ~bool](setting *T) bool {
	return setting != nil && bool(*setting)
}

func (s *Service) deletePublicAccessBlock(ctx context.Context, in *api.DeletePublicAccessBlockInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeletePublicAccessBlock", value(in.Bucket), "", "publicAccessBlock")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketPublicAccessBlock", "", nil); w != nil {
			return w
		}
		b.PublicAccess = nil
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return out.prepare(c, &api.DeletePublicAccessBlockOutput{})
	})
	return out, wire
}

func (s *Service) getBucketPolicyStatus(ctx context.Context, in *api.GetBucketPolicyStatusInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketPolicyStatus", value(in.Bucket), "", "policyStatus")
	out := &api.GetBucketPolicyStatusOutput{}
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketPolicyStatus", "", nil); w != nil {
			return w
		}
		if b.Policy.Document == "" {
			return failure("NoSuchBucketPolicy", "The bucket policy does not exist.", 404)
		}
		public, err := bucketPolicyPublic(b.Policy.Document, b.Key.ARN())
		if err != nil {
			return err
		}
		out.PolicyStatus = &api.PolicyStatus{IsPublic: new(api.IsPublic(public))}
		return response.prepare(c, out)
	})
	return response, wire
}

// Bucket and owner-account settings only combine for enforcement. Retained
// bucket configuration and GET responses remain independent of account changes.
func (s *Service) bucketPublicAccess(reader Reader, bucket BucketRecord) (PublicAccessBlock, error) {
	account, err := s.accountPublicAccess(reader, bucket.Key.Partition, bucket.AccountID)
	if err != nil {
		return PublicAccessBlock{}, err
	}
	var effective PublicAccessBlock
	for _, block := range [2]*PublicAccessBlock{bucket.PublicAccess, account} {
		if block != nil {
			effective.BlockPublicACLs = effective.BlockPublicACLs || block.BlockPublicACLs
			effective.IgnorePublicACLs = effective.IgnorePublicACLs || block.IgnorePublicACLs
			effective.BlockPublicPolicy = effective.BlockPublicPolicy || block.BlockPublicPolicy
			effective.RestrictPublicBuckets = effective.RestrictPublicBuckets || block.RestrictPublicBuckets
		}
	}
	return effective, nil
}
