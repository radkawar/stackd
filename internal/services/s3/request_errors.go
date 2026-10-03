package s3

import (
	"context"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// ResolveRequestError preserves native authority/state precedence without
// dispatching a command whose generated input failed validation.
func (s *Service) ResolveRequestError(ctx context.Context, name string, request awsapi.Request, err error) *awswire.Error {
	if wire := configurationQueryIDError(name, request.Query.Get("id")); wire != nil {
		return wire
	}
	switch name {
	case "PutBucketInventoryConfiguration", "PutBucketAnalyticsConfiguration", "PutBucketAbac", "PutBucketAccelerateConfiguration", "GetBucketAccelerateConfiguration":
		model, _ := awscatalog.LookupService("s3")
		operation, _ := model.Operation(name)
		envelope := request
		envelope.Body = nil
		input, _ := api.NewInput(name)
		if bindErr := awsapi.BindHTTP(model, operation, envelope, input); bindErr == nil {
			var bucket *api.BucketName
			var expected *api.AccountId
			switch in := input.(type) {
			case *api.PutBucketInventoryConfigurationInput:
				bucket, expected = in.Bucket, in.ExpectedBucketOwner
			case *api.PutBucketAnalyticsConfigurationInput:
				bucket, expected = in.Bucket, in.ExpectedBucketOwner
			case *api.PutBucketAbacInput:
				bucket, expected = in.Bucket, in.ExpectedBucketOwner
			case *api.PutBucketAccelerateConfigurationInput:
				bucket, expected = in.Bucket, in.ExpectedBucketOwner
			case *api.GetBucketAccelerateConfigurationInput:
				bucket, expected = in.Bucket, in.ExpectedBucketOwner
			}
			c := call(ctx, name, value(bucket), "")
			c.params["Host"] = request.Host
			if stateErr := s.repository.View(ctx, func(reader Reader) error {
				if name == "PutBucketAccelerateConfiguration" || name == "GetBucketAccelerateConfiguration" {
					_, lookupErr := s.accelerationBucket(reader, c, expected)
					return lookupErr
				}
				bucket, lookupErr := s.configurationBucket(reader, c, expected)
				if lookupErr != nil {
					return lookupErr
				}
				if name == "PutBucketAnalyticsConfiguration" {
					if wire := s.authorize(reader.Context(), c, bucket, "PutAnalyticsConfiguration", "", nil); wire != nil {
						return wire
					}
				}
				return nil
			}); stateErr != nil {
				return wireError(stateErr)
			}
		}
	}
	if restoreRequestError(name, err) != nil {
		model, _ := awscatalog.LookupService("s3")
		operation, _ := model.Operation(name)
		// Only the generated envelope is needed to select and authorize the
		// resource. Invalid body fields never enter command execution.
		request.Body = nil
		var in api.RestoreObjectInput
		if bindErr := awsapi.BindHTTP(model, operation, request, &in); bindErr == nil {
			c := s.accessCall(ctx, name, value(in.Bucket), value(in.Key), "restore")
			stateErr := s.repository.View(ctx, func(reader Reader) error {
				_, object, lookupErr := s.restoreObjectVersion(reader, c, &in)
				if lookupErr != nil {
					return lookupErr
				}
				if objectArchiveClass(&object) == "" {
					return invalidRestoreState()
				}
				return nil
			})
			if stateErr != nil {
				return wireError(stateErr)
			}
		}
	}
	if wire, ok := err.(*awswire.Error); ok {
		return wire
	}
	return s.RequestError(name, err)
}
