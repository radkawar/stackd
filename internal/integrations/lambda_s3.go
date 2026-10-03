package integrations

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
	"stackd/internal/services/s3"
)

// LambdaS3Commands retains S3's object, version, policy and audit ownership.
// The returned region belongs to the authorized bucket read, not a second
// bucket-location lookup requiring unrelated deployment permissions.
type LambdaS3Commands interface {
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
	HeadObject(context.Context, *api.HeadObjectInput) (*s3.ObjectResponse[api.HeadObjectOutput], *awswire.Error)
}

type LambdaS3Code struct{ S3 LambdaS3Commands }

func lambdaCodeContext(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		metadata.ParentEventID = parent
	}
	metadata.RequestID = uuid.NewString()
	metadata.SourceIP, metadata.UserAgent = "lambda.amazonaws.com", "lambda.amazonaws.com"
	metadata.TransportKnown, metadata.SecureTransport = true, true
	metadata.InvokedBy = "lambda.amazonaws.com"
	return awsctx.WithMetadata(ctx, metadata)
}

func sourceObjectInput(object lambda.S3ObjectReference) *api.GetObjectInput {
	input := &api.GetObjectInput{Bucket: new(api.BucketName(object.Bucket)), Key: new(api.ObjectKey(object.Key))}
	if object.VersionID != "" {
		input.VersionId = new(api.ObjectVersionId(object.VersionID))
	}
	return input
}

func (a LambdaS3Code) ReadCode(ctx context.Context, scope lambda.Scope, resourceARN string, object lambda.S3ObjectReference, reference bool) ([]byte, lambda.S3ObjectReference, *awswire.Error) {
	input := sourceObjectInput(object)
	if reference {
		// Resolving the caller's selected object must not copy the current key
		// and then silently reference a different version after an overwrite.
		head, wire := a.S3.HeadObject(lambdaCodeContext(ctx), (*api.HeadObjectInput)(input))
		if wire != nil {
			return nil, object, lambdaSourceError(object, wire)
		}
		if head.Output.VersionId == nil || *head.Output.VersionId == "null" {
			return nil, object, &awswire.Error{Code: "InvalidParameterValueException", Message: "Self-managed S3 code storage requires a versioned source object.", StatusCode: 400}
		}
		object.VersionID = string(*head.Output.VersionId)
		code, wire := a.ReadReference(ctx, scope, resourceARN, object)
		return code, object, wire
	}
	out, wire := a.S3.GetObject(lambdaCodeContext(ctx), input)
	if wire != nil {
		return nil, object, lambdaSourceError(object, wire)
	}
	if out.Region != scope.Region {
		return nil, object, lambdaSourceError(object, &awswire.Error{Code: "TemporaryRedirect", Message: "Please re-send this request to the specified temporary endpoint. Continue to use the original request endpoint for future requests.", StatusCode: 307})
	}
	if out.Output.VersionId != nil {
		object.VersionID = string(*out.Output.VersionId)
	}
	return out.Output.Body, object, nil
}

func (a LambdaS3Code) ReadReference(ctx context.Context, scope lambda.Scope, resourceARN string, object lambda.S3ObjectReference) ([]byte, *awswire.Error) {
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, ParentEventID: origin.ParentEventID})
	ctx = lambdaServiceContext(ctx, resourceARN)
	out, wire := a.S3.GetObject(lambdaCodeContext(ctx), sourceObjectInput(object))
	if wire != nil && wire.Code == "AccessDenied" {
		return nil, &awswire.Error{Code: "InvalidParameterValueException", Message: fmt.Sprintf("Lambda service principal lambda.amazonaws.com does not have s3:GetObject and s3:GetObjectVersion permission on s3://%s/%s. Update the bucket policy to grant the Lambda service principal access and retry.", object.Bucket, object.Key), StatusCode: 400}
	}
	if wire != nil {
		return nil, lambdaSourceError(object, wire)
	}
	return out.Output.Body, nil
}

func lambdaSourceError(object lambda.S3ObjectReference, wire *awswire.Error) *awswire.Error {
	operation := "GetObject"
	if object.VersionID != "" {
		operation += "Version"
	}
	code, status := "InvalidParameterValueException", 400
	if wire.StatusCode >= 500 {
		code, status = "ServiceException", 500
	}
	if wire.Code == "AccessDenied" {
		return &awswire.Error{Code: "AccessDeniedException", StatusCode: 403, Message: fmt.Sprintf("Your access has been denied by S3, please make sure your request credentials have permission to %s for %s/%s. S3 Error Code: %s. S3 Error Message: %s", operation, object.Bucket, object.Key, wire.Code, wire.Message)}
	}
	return &awswire.Error{Code: code, StatusCode: status, Message: fmt.Sprintf("Error occurred while %s. S3 Error Code: %s. S3 Error Message: %s", operation, wire.Code, wire.Message)}
}
