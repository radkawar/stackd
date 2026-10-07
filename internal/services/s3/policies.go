package s3

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awschecksum"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func checkMD5(body []byte, expected string) *awswire.Error {
	if expected == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(expected)
	if err != nil || len(decoded) != md5.Size {
		return failure("InvalidDigest", "The Content-MD5 you specified is not valid.", 400)
	}
	sum, err := awschecksum.Sum("MD5", body)
	if err != nil {
		return wireError(err)
	}
	if expected != sum {
		return failure("BadDigest", "The Content-MD5 you specified did not match what we received.", 400)
	}
	return nil
}
func (s *Service) putBucketPolicy(ctx context.Context, in *api.PutBucketPolicyInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketPolicy", value(in.Bucket), "", "policy")
	response := &preparedResponse{}
	if document := value(in.Policy); json.Valid([]byte(document)) {
		c.params["bucketPolicy"] = json.RawMessage(document)
	}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketPolicy", "", nil); w != nil {
			return w
		}
		policyClaim, policyClaimed := cloudFormationOwner(tx.Context(), cloudFormationBucketPolicy)
		if policyClaimed && b.PolicyOwner != policyClaim && (b.PolicyOwner != "" || b.Policy.Document != "") {
			return cloudFormationOwnerConflict("bucket policy")
		}
		document := value(in.Policy)
		if len(document) > 20*1024 {
			return failure("MalformedPolicy", "Policy exceeds the maximum allowed size.", 400)
		}
		if in.ConfirmRemoveSelfBucketAccess != nil {
			return unsupported("Self-access removal confirmation is not implemented.")
		}
		bound, err := s.bindS3ResourcePolicy(tx.Context(), document)
		if err != nil {
			return err
		}
		public, err := bucketPolicyPublic(document, b.Key.ARN())
		if err != nil {
			return err
		}
		if public && c.publicAccess.BlockPublicPolicy {
			return denied()
		}
		b.Policy = bound
		if policyClaimed {
			b.PolicyOwner = policyClaim
		}
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return response.prepare(c, &api.PutBucketPolicyOutput{})
	})
	return response, wire
}
func (s *Service) getBucketPolicy(ctx context.Context, in *api.GetBucketPolicyInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketPolicy", value(in.Bucket), "", "policy")
	response := &preparedResponse{}
	out := &api.GetBucketPolicyOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketPolicy", "", nil); w != nil {
			return w
		}
		// Under a policy-edge claim, only that claim's policy is observable.
		if claim, claimed := cloudFormationOwner(tx.Context(), cloudFormationBucketPolicy); b.Policy.Document == "" || claimed && b.PolicyOwner != claim {
			return failure("NoSuchBucketPolicy", "The bucket policy does not exist.", 404)
		}
		if s.binder == nil {
			return unsupported("Resource policy rendering is not configured.")
		}
		document, err := s.binder.RenderResourcePolicy(tx.Context(), b.Policy)
		if err != nil {
			return err
		}
		out.Policy = new(api.Policy(document))
		return response.prepare(c, out)
	})
	return response, wire
}
func (s *Service) deleteBucketPolicy(ctx context.Context, in *api.DeleteBucketPolicyInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketPolicy", value(in.Bucket), "", "policy")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "DeleteBucketPolicy", "", nil); w != nil {
			return w
		}
		if claim, claimed := cloudFormationOwner(tx.Context(), cloudFormationBucketPolicy); claimed && b.PolicyOwner != claim {
			if b.PolicyOwner != "" {
				return cloudFormationOwnerConflict("bucket policy")
			}
			// This incarnation's policy edge no longer exists; never remove
			// a policy another writer attached afterwards.
			return failure("NoSuchBucketPolicy", "The bucket policy does not exist.", 404)
		}
		b.Policy, b.PolicyOwner = authorization.BoundPolicy{}, ""
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return response.prepare(c, &api.DeleteBucketPolicyOutput{})
	})
	return response, wire
}

// bindS3ResourcePolicy shares immutable IAM bindings and S3's canonical
// account-root presentation across bucket and access-point policies.
func (s *Service) bindS3ResourcePolicy(ctx context.Context, document string) (authorization.BoundPolicy, error) {
	if s.binder == nil {
		return authorization.BoundPolicy{}, unsupported("Resource policy principal binding is not configured.")
	}
	bound, err := s.binder.BindResourcePolicy(ctx, document, authorization.ResourcePolicyOptions{})
	if err != nil {
		return authorization.BoundPolicy{}, failure("MalformedPolicy", err.Error(), 400)
	}
	parsed, err := policy.ParseResource([]byte(bound.Document))
	if err != nil {
		return authorization.BoundPolicy{}, err
	}
	var replacements map[string]string
	for _, principal := range parsed.AWSPrincipals() {
		if publicPolicyFixedAccount(principal) {
			if replacements == nil {
				replacements = make(map[string]string)
			}
			replacements[principal] = "arn:" + awsctx.FromContext(ctx).Partition + ":iam::" + principal + ":root"
		}
	}
	if len(replacements) != 0 {
		canonical, err := policy.RewriteResourcePrincipals([]byte(bound.Document), replacements)
		if err != nil {
			return authorization.BoundPolicy{}, err
		}
		bound.Document = string(canonical)
	}
	return bound, nil
}
