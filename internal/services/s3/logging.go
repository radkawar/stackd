package s3

import (
	"context"
	"errors"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getBucketLogging(ctx context.Context, in *api.GetBucketLoggingInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketLogging", value(in.Bucket), "", "logging")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetBucketLogging", "", nil); wire != nil {
			return wire
		}
		config, err := tx.BucketLogging(b.Key)
		if err != nil {
			return err
		}
		return out.prepare(c, &api.GetBucketLoggingOutput{LoggingEnabled: loggingOutput(config)})
	})
	return out, wire
}

func (s *Service) putBucketLogging(ctx context.Context, in *api.PutBucketLoggingInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketLogging", value(in.Bucket), "", "logging")
	request, _ := awsapi.FromContext(ctx)
	xmlAuditParameters(c, request.Body)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutBucketLogging", "", nil); wire != nil {
			return wire
		}
		config, wire := loggingConfiguration(in.BucketLoggingStatus.LoggingEnabled)
		if wire != nil {
			return wire
		}
		if config != nil {
			target, err := tx.Bucket(BucketKey{Partition: b.Key.Partition, Name: config.TargetBucket})
			if errors.Is(err, ErrNotFound) {
				wire := failure("InvalidTargetBucketForLogging", "The target bucket for logging does not exist", 400)
				wire.TargetBucket = config.TargetBucket
				return wire
			}
			if err != nil {
				return err
			}
			if target.AccountID != b.AccountID {
				wire := failure("InvalidTargetBucketForLogging", "The owner for the bucket to be logged and the target bucket must be the same.", 400)
				wire.TargetBucket = config.TargetBucket
				return wire
			}
			if target.Region != b.Region {
				wire := failure("CrossLocationLoggingProhibitted", "Cross S3 location logging not allowed. ", 403)
				wire.TargetBucketLocation = target.Region
				return wire
			}
			if target.Ownership == "BucketOwnerEnforced" && len(config.Grants) != 0 {
				return failure("AccessControlListNotSupported", "Target grants not allowed for bucket owner enforced buckets", 400)
			}
		}
		if err := tx.ReplaceBucketLogging(b.Key, config); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketLoggingOutput{})
	})
	return out, wire
}

func loggingConfiguration(enabled *api.LoggingEnabled) (*LoggingConfiguration, *awswire.Error) {
	if enabled == nil {
		return nil, nil
	}
	out := &LoggingConfiguration{TargetBucket: value(enabled.TargetBucket), TargetPrefix: value(enabled.TargetPrefix)}
	if format := enabled.TargetObjectKeyFormat; format != nil {
		if (format.SimplePrefix == nil) == (format.PartitionedPrefix == nil) {
			return nil, malformedXML()
		}
		if format.SimplePrefix != nil {
			out.KeyFormat = "SimplePrefix"
		} else {
			out.KeyFormat = "PartitionedPrefix"
			if format.PartitionedPrefix.PartitionDateSource != nil {
				out.KeyFormat = value(format.PartitionedPrefix.PartitionDateSource)
			}
		}
	}
	if enabled.TargetGrants != nil {
		out.Grants = make([]ACLGrant, len(enabled.TargetGrants))
		for i, grant := range enabled.TargetGrants {
			g := ACLGrant{Type: value(grant.Grantee.Type), ID: value(grant.Grantee.ID), URI: value(grant.Grantee.URI), Permission: value(grant.Permission)}
			if wire := validateGrant(g); wire != nil {
				if wire.Code == "MalformedACLError" {
					return nil, malformedXML()
				}
				return nil, wire
			}
			out.Grants[i] = g
		}
	}
	return out, nil
}

func loggingOutput(config *LoggingConfiguration) *api.LoggingEnabled {
	if config == nil {
		return nil
	}
	out := &api.LoggingEnabled{TargetBucket: new(api.TargetBucket(config.TargetBucket)), TargetPrefix: new(api.TargetPrefix(config.TargetPrefix))}
	switch config.KeyFormat {
	case "SimplePrefix":
		out.TargetObjectKeyFormat = &api.TargetObjectKeyFormat{SimplePrefix: &api.SimplePrefix{}}
	case "PartitionedPrefix":
		out.TargetObjectKeyFormat = &api.TargetObjectKeyFormat{PartitionedPrefix: &api.PartitionedPrefix{}}
	case "EventTime", "DeliveryTime":
		out.TargetObjectKeyFormat = &api.TargetObjectKeyFormat{PartitionedPrefix: &api.PartitionedPrefix{PartitionDateSource: new(api.PartitionDateSource(config.KeyFormat))}}
	}
	if config.Grants != nil {
		out.TargetGrants = make(api.TargetGrants, len(config.Grants))
		for i, grant := range config.Grants {
			grantee := &api.Grantee{Type: new(api.Type(grant.Type))}
			if grant.ID != "" {
				grantee.ID = new(api.ID(grant.ID))
			}
			if grant.URI != "" {
				grantee.URI = new(api.URI(grant.URI))
			}
			out.TargetGrants[i] = api.TargetGrant{Grantee: grantee, Permission: new(api.BucketLogsPermission(grant.Permission))}
		}
	}
	return out
}
