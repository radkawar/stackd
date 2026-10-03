package s3

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) putBucketLifecycleConfiguration(ctx context.Context, in *api.PutBucketLifecycleConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketLifecycleConfiguration", value(in.Bucket), "", "lifecycle")
	c.params["LifecycleConfiguration"] = in.LifecycleConfiguration
	if in.TransitionDefaultMinimumObjectSize != nil {
		c.params["x-amz-transition-default-minimum-object-size"] = value(in.TransitionDefaultMinimumObjectSize)
	}
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutLifecycleConfiguration", "", nil); wire != nil {
			return wire
		}
		minimum := "all_storage_classes_128K"
		if in.TransitionDefaultMinimumObjectSize != nil {
			minimum = value(in.TransitionDefaultMinimumObjectSize)
			if minimum != "all_storage_classes_128K" && minimum != "varies_by_storage_class" {
				return invalidLifecycleMinimum(minimum)
			}
		}
		configuration, err := parseLifecycleConfiguration(in.LifecycleConfiguration)
		if err != nil {
			return err
		}
		configuration.MinimumObjectSize = minimum
		if c.eventID == "" {
			c.eventID = uuid.NewString()
		}
		configuration.ParentEventID = c.eventID
		for _, rule := range configuration.Rules {
			if rule.Enabled {
				configuration.NextScan = new(objectDayDeadline(s.clock.Now(), 0))
				break
			}
		}
		if err := tx.ReplaceBucketLifecycle(b.Key, configuration); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketLifecycleConfigurationOutput{TransitionDefaultMinimumObjectSize: new(api.TransitionDefaultMinimumObjectSize(minimum))})
	})
	return out, wire
}

func (s *Service) getBucketLifecycleConfiguration(ctx context.Context, in *api.GetBucketLifecycleConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketLifecycleConfiguration", value(in.Bucket), "", "lifecycle")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetLifecycleConfiguration", "", nil); wire != nil {
			return wire
		}
		configuration, err := tx.BucketLifecycle(b.Key)
		if err != nil {
			return err
		}
		if configuration == nil {
			wire := failure("NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist", 404)
			wire.BucketName = b.Key.Name
			return wire
		}
		return out.prepare(c, outputLifecycleConfiguration(configuration))
	})
	return out, wire
}

func (s *Service) deleteBucketLifecycle(ctx context.Context, in *api.DeleteBucketLifecycleInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketLifecycle", value(in.Bucket), "", "lifecycle")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutLifecycleConfiguration", "", nil); wire != nil {
			return wire
		}
		if err := tx.ReplaceBucketLifecycle(b.Key, nil); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketLifecycleOutput{})
	})
	return out, wire
}

func invalidLifecycleMinimum(minimum string) *awswire.Error {
	return failure("InvalidRequest", "Invalid TransitionDefaultMinimumObjectSize found: "+minimum, 400)
}

// Lifecycle's semantic errors differ from the generated model's enum and tag
// constraints. Keep XML decoding and response serialization in the generated API.
func lifecycleRequestError(name string, err error) *awswire.Error {
	if name != "PutBucketLifecycleConfiguration" {
		return nil
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		if validation.Path == "TransitionDefaultMinimumObjectSize" {
			return invalidLifecycleMinimum(validation.EnumValue)
		}
		if strings.HasPrefix(validation.Path, "LifecycleConfiguration") {
			if strings.HasSuffix(validation.Path, ".StorageClass") && validation.Constraint == "enum" {
				return lifecycleAdmissionClass(validation.EnumValue)
			}
			if strings.HasPrefix(validation.Constraint, "length.") && strings.HasSuffix(validation.Path, ".Key") {
				return failure("InvalidRequest", "A Tag's Key must be a length between 1 and 128.", 400)
			}
			return malformedXML()
		}
		return nil
	}
	return malformedXML()
}
