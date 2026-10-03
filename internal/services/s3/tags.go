package s3

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getBucketTagging(ctx context.Context, in *api.GetBucketTaggingInput) (*api.GetBucketTaggingOutput, *awswire.Error) {
	c := call(ctx, "GetBucketTagging", value(in.Bucket), "")
	c.params["tagging"] = ""
	out := &api.GetBucketTaggingOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketTagging", "", nil); w != nil {
			return w
		}
		tags, err := tx.BucketTags(b.Key)
		if err != nil {
			return err
		}
		if len(tags) == 0 {
			wire := failure("NoSuchTagSet", "The TagSet does not exist", 404)
			wire.BucketName = b.Key.Name
			return wire
		}
		out.TagSet = outputTags(tags)
		return nil
	})
	return out, wire
}

func (s *Service) putBucketTagging(ctx context.Context, in *api.PutBucketTaggingInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketTagging", value(in.Bucket), "", "tagging")
	response := &preparedResponse{}
	bucketTaggingParameters(c, in.Tagging)
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketTagging", "", nil); w != nil {
			return w
		}
		if b.ABACEnabled {
			return failure("BadRequest", "This S3 general purpose bucket has attribute-based access control (ABAC) enabled. To add tags to this bucket, initiate a TagResource request. To delete tags from this bucket, initiate an UntagResource request.", 400)
		}
		tags, wire := validateBucketTags(in.Tagging, false)
		if wire != nil {
			return wire
		}
		if err := tx.ReplaceBucketTags(b.Key, tags); err != nil {
			return err
		}
		return response.prepare(c, &api.PutBucketTaggingOutput{})
	})
	return response, wire
}

func (s *Service) deleteBucketTagging(ctx context.Context, in *api.DeleteBucketTaggingInput) (*api.DeleteBucketTaggingOutput, *awswire.Error) {
	c := call(ctx, "DeleteBucketTagging", value(in.Bucket), "")
	c.params["tagging"] = ""
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		// Both mutation APIs require s3:PutBucketTagging, not an IAM
		// action named after the DeleteBucketTagging operation.
		if w := s.authorize(tx.Context(), c, b, "PutBucketTagging", "", nil); w != nil {
			return w
		}
		if b.ABACEnabled {
			return failure("BadRequest", "This S3 general purpose bucket has attribute-based access control (ABAC) enabled. To delete tags from this bucket, initiate an UntagResource request.", 400)
		}
		return tx.ReplaceBucketTags(b.Key, nil)
	})
	return &api.DeleteBucketTaggingOutput{}, wire
}

func validateBucketTags(in *api.Tagging, creating bool) ([]Tag, *awswire.Error) {
	if in != nil && len(in.TagSet) > 50 {
		return nil, failure("BadRequest", "Bucket tag count cannot be greater than 50", 400)
	}
	tags, wire := validateTags(in, creating)
	if wire != nil {
		return nil, wire
	}
	for _, tag := range tags {
		if len(tag.Key) < 4 || !strings.EqualFold(tag.Key[:4], "aws:") {
			continue
		}
		if creating {
			return nil, failure("InvalidTag", "User-defined tag keys can't start with \"aws:\". This prefix is reserved for system tags. Remove \"aws:\" from your tag keys and try again.", 400)
		}
		if strings.HasPrefix(tag.Key, "aws:") {
			return nil, failure("InvalidTag", "System tags cannot be added/updated by requester", 400)
		}
		return nil, failure("InvalidTag", "Invalid Tag. Tags cannot start with \"aws:\"(case insensitive) unless they are System Tags that start with \"aws:\"(case sensitive)", 400)
	}
	return tags, nil
}

// CloudTrail retains S3's XML-shaped Tagging document rather than the SDK's
// array shape. A singleton Tag is an object in the captured native event.
func bucketTaggingParameters(c *apiCall, tagging *api.Tagging) {
	if tagging == nil {
		return
	}
	var tags any = tagging.TagSet
	if len(tagging.TagSet) == 1 {
		tags = tagging.TagSet[0]
	}
	c.params["Tagging"] = map[string]any{
		"xmlns":  "http://s3.amazonaws.com/doc/2006-03-01/",
		"TagSet": map[string]any{"Tag": tags},
	}
}
