package s3

import (
	"context"
	"errors"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getBucketAbac(ctx context.Context, in *api.GetBucketAbacInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketAbac", value(in.Bucket), "", "abac")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		bucket, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, bucket, "GetBucketAbac", "", nil); wire != nil {
			return wire
		}
		status := api.BucketAbacStatusDisabled
		if bucket.ABACEnabled {
			status = api.BucketAbacStatusEnabled
		}
		return out.prepare(c, &api.GetBucketAbacOutput{AbacStatus: &api.AbacStatus{Status: &status}})
	})
	return out, wire
}

func (s *Service) putBucketAbac(ctx context.Context, in *api.PutBucketAbacInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketAbac", value(in.Bucket), "", "abac")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		bucket, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if s.events != nil {
			request, _ := awsapi.FromContext(ctx)
			abacBodyParameters(c, request.Body, value(in.ExpectedBucketOwner), err)
		}
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, bucket, "PutBucketAbac", "", nil); wire != nil {
			return wire
		}
		if in.AbacStatus.Status == nil {
			return malformedXML()
		}
		bucket.ABACEnabled = *in.AbacStatus.Status == api.BucketAbacStatusEnabled
		if err := tx.PutBucket(bucket); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketAbacOutput{})
	})
	return out, wire
}

func abacBodyParameters(c *apiCall, body []byte, expected string, err error) {
	var wire *awswire.Error
	if expected != "" && errors.As(err, &wire) && wire.Code == "NoSuchBucket" {
		// Native expected-owner admission rejects an absent bucket before
		// consuming the ABAC document, for both valid and invalid statuses.
		c.additional["bytesTransferredIn"] = 0
		return
	}
	xmlAuditParameters(c, body)
}
