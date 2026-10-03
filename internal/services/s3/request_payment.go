package s3

import (
	"context"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) getBucketRequestPayment(ctx context.Context, in *api.GetBucketRequestPaymentInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketRequestPayment", value(in.Bucket), "", "requestPayment")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketRequestPayment", "", nil); w != nil {
			return w
		}
		payer := api.Payer("BucketOwner")
		if b.RequesterPays {
			payer = "Requester"
		}
		return out.prepare(c, &api.GetBucketRequestPaymentOutput{Payer: &payer})
	})
	return out, wire
}

func (s *Service) putBucketRequestPayment(ctx context.Context, in *api.PutBucketRequestPaymentInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketRequestPayment", value(in.Bucket), "", "requestPayment")
	if s.events != nil {
		request, _ := awsapi.FromContext(ctx)
		xmlAuditParameters(c, request.Body)
	}
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketRequestPayment", "", nil); w != nil {
			return w
		}
		b.RequesterPays = value(in.RequestPaymentConfiguration.Payer) == "Requester"
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketRequestPaymentOutput{})
	})
	return out, wire
}

// requestPayment belongs to one HTTP request or typed command. Acknowledging payment happens at
// bucket admission, before IAM and object selection; native error responses can
// therefore carry the same charge header as successful responses.
type requestPayment struct {
	payer   string
	charged bool
}

type requestPaymentKey struct{}

func admitRequestPayment(ctx context.Context, bucket BucketRecord) *awswire.Error {
	metadata := awsctx.FromContext(ctx)
	if !bucket.RequesterPays || metadata.AccountID == bucket.AccountID {
		return nil
	}
	payment, _ := ctx.Value(requestPaymentKey{}).(*requestPayment)
	if payment == nil || payment.payer != "requester" || metadata.PrincipalARN == "" && metadata.ServicePrincipal.Name == "" {
		return denied()
	}
	payment.charged = true
	return nil
}

func commandRequestPayer(input any) string {
	switch in := input.(type) {
	case *api.AbortMultipartUploadInput:
		return value(in.RequestPayer)
	case *api.CompleteMultipartUploadInput:
		return value(in.RequestPayer)
	case *api.CopyObjectInput:
		return value(in.RequestPayer)
	case *api.CreateMultipartUploadInput:
		return value(in.RequestPayer)
	case *api.DeleteObjectInput:
		return value(in.RequestPayer)
	case *api.DeleteObjectsInput:
		return value(in.RequestPayer)
	case *api.GetBucketAccelerateConfigurationInput:
		return value(in.RequestPayer)
	case *api.GetObjectAclInput:
		return value(in.RequestPayer)
	case *api.GetObjectAttributesInput:
		return value(in.RequestPayer)
	case *api.GetObjectLegalHoldInput:
		return value(in.RequestPayer)
	case *api.GetObjectInput:
		return value(in.RequestPayer)
	case *api.GetObjectRetentionInput:
		return value(in.RequestPayer)
	case *api.GetObjectTaggingInput:
		return value(in.RequestPayer)
	case *api.HeadObjectInput:
		return value(in.RequestPayer)
	case *api.ListMultipartUploadsInput:
		return value(in.RequestPayer)
	case *api.ListObjectVersionsInput:
		return value(in.RequestPayer)
	case *api.ListObjectsInput:
		return value(in.RequestPayer)
	case *api.ListObjectsV2Input:
		return value(in.RequestPayer)
	case *api.ListPartsInput:
		return value(in.RequestPayer)
	case *api.PutObjectAclInput:
		return value(in.RequestPayer)
	case *api.PutObjectLegalHoldInput:
		return value(in.RequestPayer)
	case *api.PutObjectLockConfigurationInput:
		return value(in.RequestPayer)
	case *api.PutObjectInput:
		return value(in.RequestPayer)
	case *api.PutObjectRetentionInput:
		return value(in.RequestPayer)
	case *api.PutObjectTaggingInput:
		return value(in.RequestPayer)
	case *api.RestoreObjectInput:
		return value(in.RequestPayer)
	case *api.UploadPartCopyInput:
		return value(in.RequestPayer)
	case *api.UploadPartInput:
		return value(in.RequestPayer)
	default:
		return ""
	}
}

func setCommandRequestCharged(output any) {
	switch out := output.(type) {
	case *api.AbortMultipartUploadOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.CompleteMultipartUploadOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.CopyObjectOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.CreateMultipartUploadOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.DeleteObjectOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.DeleteObjectsOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.GetBucketAccelerateConfigurationOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.GetObjectAclOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.GetObjectAttributesOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.GetObjectOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.HeadObjectOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.ListMultipartUploadsOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.ListObjectVersionsOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.ListObjectsOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.ListObjectsV2Output:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.ListPartsOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.PutObjectAclOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.PutObjectLegalHoldOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.PutObjectLockConfigurationOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.PutObjectOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.PutObjectRetentionOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.RestoreObjectOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.UploadPartCopyOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	case *api.UploadPartOutput:
		out.RequestCharged = new(api.RequestChargedRequester)
	}
}
