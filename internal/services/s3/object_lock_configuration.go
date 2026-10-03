package s3

import (
	"context"
	"strconv"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getObjectLockConfiguration(ctx context.Context, in *api.GetObjectLockConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetObjectLockConfiguration", value(in.Bucket), "", "object-lock")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetBucketObjectLockConfiguration", "", nil); wire != nil {
			return wire
		}
		if !b.ObjectLockEnabled {
			return failure("ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket", 404)
		}
		return response.prepare(c, &api.GetObjectLockConfigurationOutput{ObjectLockConfiguration: objectLockConfigurationOutput(b.DefaultRetention)})
	})
	return response, wire
}

func (s *Service) putObjectLockConfiguration(ctx context.Context, in *api.PutObjectLockConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutObjectLockConfiguration", value(in.Bucket), "", "object-lock")
	request, _ := awsapi.FromContext(ctx)
	xmlAuditParameters(c, request.Body)
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutBucketObjectLockConfiguration", "", nil); wire != nil {
			return wire
		}
		// S3 accepts the legacy activation token without requiring or validating it.
		retention, wire := bucketDefaultRetention(in.ObjectLockConfiguration)
		if wire != nil {
			return wire
		}
		if b.Versioning != "Enabled" {
			return failure("InvalidBucketState", "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration", 409)
		}
		b.ObjectLockEnabled = true
		b.DefaultRetention = retention
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return response.prepare(c, &api.PutObjectLockConfigurationOutput{})
	})
	return response, wire
}

func bucketDefaultRetention(config *api.ObjectLockConfiguration) (DefaultRetention, *awswire.Error) {
	if config == nil || value(config.ObjectLockEnabled) != "Enabled" {
		return DefaultRetention{}, malformedXML()
	}
	if config.Rule == nil {
		return DefaultRetention{}, nil
	}
	in := config.Rule.DefaultRetention
	if in == nil || value(in.Mode) != "GOVERNANCE" && value(in.Mode) != "COMPLIANCE" || in.Days != nil && in.Years != nil {
		return DefaultRetention{}, malformedXML()
	}
	out := DefaultRetention{Mode: value(in.Mode)}
	if in.Days != nil {
		if *in.Days <= 0 {
			return DefaultRetention{}, argumentError("Days", strconv.FormatInt(int64(*in.Days), 10), "Default retention period must be a positive integer value")
		}
		if *in.Days > 36500 {
			return DefaultRetention{}, argumentError("Days", strconv.FormatInt(int64(*in.Days), 10), "Default retention period too large.")
		}
		out.Period.Days = int32(*in.Days)
	}
	if in.Years != nil {
		if *in.Years <= 0 {
			return DefaultRetention{}, argumentError("Years", strconv.FormatInt(int64(*in.Years), 10), "Default retention period must be a positive integer value")
		}
		if *in.Years > 100 {
			return DefaultRetention{}, argumentError("Years", strconv.FormatInt(int64(*in.Years), 10), "Default retention period too large.")
		}
		out.Period.Years = int32(*in.Years)
	}
	if hold := in.DefaultEventHold; hold != nil {
		if (hold.Days == nil) == (hold.Years == nil) {
			return DefaultRetention{}, malformedXML()
		}
		if hold.Days != nil {
			if *hold.Days <= 0 {
				return DefaultRetention{}, argumentError("Days", strconv.FormatInt(int64(*hold.Days), 10), "Default event hold duration must be a positive integer value.")
			}
			if *hold.Days > 36500 {
				return DefaultRetention{}, argumentError("Days", strconv.FormatInt(int64(*hold.Days), 10), "Default event hold duration must be at most 36500 days.")
			}
			out.EventHold.Days = int32(*hold.Days)
		}
		if hold.Years != nil {
			if *hold.Years <= 0 {
				return DefaultRetention{}, argumentError("Years", strconv.FormatInt(int64(*hold.Years), 10), "Default event hold duration must be a positive integer value.")
			}
			if *hold.Years > 100 {
				return DefaultRetention{}, argumentError("Years", strconv.FormatInt(int64(*hold.Years), 10), "Default event hold duration must be at most 100 years.")
			}
			out.EventHold.Years = int32(*hold.Years)
		}
	}
	if out.Period == (RetentionPeriod{}) && out.EventHold == (RetentionPeriod{}) {
		return DefaultRetention{}, failure("InvalidRequest", "DefaultRetention must specify a fixed retention (Days or Years) or a DefaultEventHold.", 400)
	}
	return out, nil
}

func objectLockConfigurationOutput(retention DefaultRetention) *api.ObjectLockConfiguration {
	config := &api.ObjectLockConfiguration{ObjectLockEnabled: new(api.ObjectLockEnabled("Enabled"))}
	if retention.Mode == "" {
		return config
	}
	out := &api.DefaultRetention{Mode: new(api.ObjectLockRetentionMode(retention.Mode))}
	if retention.Period.Days != 0 {
		out.Days = new(api.Days(retention.Period.Days))
	}
	if retention.Period.Years != 0 {
		out.Years = new(api.Years(retention.Period.Years))
	}
	if retention.EventHold != (RetentionPeriod{}) {
		out.DefaultEventHold = &api.EventHoldDuration{}
		if retention.EventHold.Days != 0 {
			out.DefaultEventHold.Days = new(api.Days(retention.EventHold.Days))
		}
		if retention.EventHold.Years != 0 {
			out.DefaultEventHold.Years = new(api.Years(retention.EventHold.Years))
		}
	}
	config.Rule = &api.ObjectLockRule{DefaultRetention: out}
	return config
}
