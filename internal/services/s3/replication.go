package s3

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) putBucketReplication(ctx context.Context, in *api.PutBucketReplicationInput) (*api.PutBucketReplicationOutput, *awswire.Error) {
	c := call(ctx, "PutBucketReplication", value(in.Bucket), "")
	c.params["replication"] = ""
	c.params["ReplicationConfiguration"] = in.ReplicationConfiguration
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutReplicationConfiguration", "", nil); w != nil {
			return w
		}
		input := in.ReplicationConfiguration
		if input == nil || input.Role == nil || len(input.Rules) == 0 {
			return malformedXML()
		}
		role := value(input.Role)
		parsed, parseErr := arn.Parse(role)
		if parseErr != nil || parsed.Partition != b.Key.Partition || parsed.Service != "iam" || parsed.Region != "" || !accountNumber.MatchString(parsed.AccountID) || parsed.Resource == "" {
			return argumentError("Role", role, "Invalid Role specified in replication configuration")
		}
		if !strings.HasPrefix(parsed.Resource, "role/") || len(parsed.Resource) == len("role/") {
			return argumentError("Role", role, "The relative id should start with role")
		}
		// IAM roles are not looked up or assumed at admission. Even a missing
		// role can be retained, but PassRole cannot cross the caller's account.
		if parsed.AccountID != awsctx.FromContext(tx.Context()).AccountID {
			return denied()
		}
		if w := s.authorizer.Authorize(tx.Context(), authorization.Request{
			Action: "iam:PassRole", ResourceARN: role, ResourceAccountID: parsed.AccountID,
			Context: map[string][]string{"iam:PassedToService": {"s3.amazonaws.com"}},
		}); w != nil {
			return w
		}
		if b.Versioning != "Enabled" {
			return failure("InvalidRequest", "Versioning must be 'Enabled' on the bucket to apply a replication configuration", 400)
		}
		conf, err := parseReplicationConfiguration(input, b.Key)
		if err != nil {
			return err
		}
		checked := make(map[BucketKey]string, len(conf.Rules))
		for i := range conf.Rules {
			rule := &conf.Rules[i]
			key := rule.Destination.Bucket
			if region, ok := checked[key]; ok {
				rule.Destination.Region = region
				continue
			}
			destination, err := tx.Bucket(key)
			if errors.Is(err, ErrNotFound) {
				return failure("InvalidRequest", "Destination bucket must exist.", 400)
			}
			if err != nil {
				return err
			}
			if destination.Versioning != "Enabled" {
				return failure("InvalidRequest", "Destination bucket must have versioning enabled.", 400)
			}
			// Native admission allows a locked source and unlocked destination.
			// Object metadata and current role authority are delivery concerns.
			rule.Destination.Region = destination.Region
			checked[key] = destination.Region
		}
		if err := s.configureReplicationMetrics(tx, b, conf); err != nil {
			return err
		}
		return tx.ReplaceBucketReplication(b.Key, conf)
	})
	return &api.PutBucketReplicationOutput{}, wire
}

func (s *Service) getBucketReplication(ctx context.Context, in *api.GetBucketReplicationInput) (*api.GetBucketReplicationOutput, *awswire.Error) {
	c := call(ctx, "GetBucketReplication", value(in.Bucket), "")
	c.params["replication"] = ""
	out := &api.GetBucketReplicationOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetReplicationConfiguration", "", nil); w != nil {
			return w
		}
		conf, err := tx.BucketReplication(b.Key)
		if err != nil {
			return err
		}
		if conf == nil {
			wire := failure("ReplicationConfigurationNotFoundError", "The replication configuration was not found", 404)
			wire.BucketName = b.Key.Name
			return wire
		}
		out.ReplicationConfiguration = outputReplicationConfiguration(conf)
		return nil
	})
	return out, wire
}

func (s *Service) deleteBucketReplication(ctx context.Context, in *api.DeleteBucketReplicationInput) (*api.DeleteBucketReplicationOutput, *awswire.Error) {
	c := call(ctx, "DeleteBucketReplication", value(in.Bucket), "")
	c.params["replication"] = ""
	c.additional = map[string]any{"httpStatusCode": 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutReplicationConfiguration", "", nil); w != nil {
			return w
		}
		if err := s.configureReplicationMetrics(tx, b, nil); err != nil {
			return err
		}
		return tx.ReplaceBucketReplication(b.Key, nil)
	})
	return &api.DeleteBucketReplicationOutput{}, wire
}

func parseReplicationConfiguration(in *api.ReplicationConfiguration, source BucketKey) (*ReplicationConfiguration, error) {
	out := &ReplicationConfiguration{RoleARN: value(in.Role), Rules: make([]ReplicationRule, 0, len(in.Rules))}
	legacy := false
	for _, rule := range in.Rules {
		if rule.Filter == nil {
			legacy = true
		}
	}
	ids := make(map[string]struct{}, len(in.Rules))
	priorities := make(map[int32]struct{}, len(in.Rules))
	for _, rule := range in.Rules {
		if !replicationStatus(value(rule.Status)) || rule.Destination == nil || rule.Destination.Bucket == nil || rule.ExistingObjectReplication != nil {
			return nil, malformedXML()
		}
		filter, wire := parseReplicationFilter(rule)
		if wire != nil {
			return nil, wire
		}
		if legacy {
			if rule.Priority != nil {
				return nil, replicationSchemaError("Priority", false)
			}
			if rule.DeleteMarkerReplication != nil {
				return nil, replicationSchemaError("DeleteMarkerReplication", false)
			}
		} else {
			if rule.Priority == nil {
				return nil, replicationSchemaError("Priority", true)
			}
			if rule.DeleteMarkerReplication == nil {
				return nil, replicationSchemaError("DeleteMarkerReplication", true)
			}
		}
		stored := ReplicationRule{ID: value(rule.ID), Enabled: value(rule.Status) == "Enabled", Filter: filter}
		if len(stored.ID) > 255 {
			return nil, argumentError("ID", stored.ID, "Rule Id cannot be greater than 255")
		}
		if stored.ID == "" {
			id, err := uuid.NewRandom()
			if err != nil {
				return nil, err
			}
			stored.ID = id.String()
		}
		if _, duplicate := ids[stored.ID]; duplicate {
			return nil, argumentError("ID", stored.ID, "Rule Id must be unique")
		}
		ids[stored.ID] = struct{}{}
		if rule.Priority != nil {
			priority := int32(*rule.Priority)
			if priority < 0 {
				return nil, failure("InvalidRequest", "Priority must be between 0 and 2147483647.", 400)
			}
			if _, duplicate := priorities[priority]; duplicate {
				return nil, failure("InvalidRequest", fmt.Sprintf("Found duplicate priority %d.", priority), 400)
			}
			priorities[priority] = struct{}{}
			stored.Priority = new(priority)
		}
		if marker := rule.DeleteMarkerReplication; marker != nil {
			stored.DeleteMarkerReplication = value(marker.Status)
			if !replicationStatus(stored.DeleteMarkerReplication) {
				return nil, malformedXML()
			}
			if stored.DeleteMarkerReplication == "Enabled" && len(filter.Tags) != 0 {
				return nil, failure("InvalidRequest", "Delete marker replication is not supported if any Tag filter is specified. Please refer to S3 Developer Guide for more information.", 400)
			}
		}
		if criteria := rule.SourceSelectionCriteria; criteria != nil {
			if criteria.SseKmsEncryptedObjects == nil && criteria.ReplicaModifications == nil {
				return nil, failure("InvalidRequest", "SourceSelectionCriteria cannot be empty.", 400)
			}
			if selector := criteria.SseKmsEncryptedObjects; selector != nil {
				stored.SSEKMSObjects = value(selector.Status)
				if !replicationStatus(stored.SSEKMSObjects) {
					return nil, malformedXML()
				}
			}
			if selector := criteria.ReplicaModifications; selector != nil {
				stored.ReplicaModifications = value(selector.Status)
				if !replicationStatus(stored.ReplicaModifications) {
					return nil, malformedXML()
				}
			}
		}
		destination, wire := parseReplicationDestination(rule.Destination, source, stored.SSEKMSObjects != "")
		if wire != nil {
			return nil, wire
		}
		stored.Destination = destination
		out.Rules = append(out.Rules, stored)
	}
	return out, nil
}

func replicationStatus(status string) bool { return status == "Enabled" || status == "Disabled" }

func replicationSchemaError(field string, required bool) *awswire.Error {
	restriction := " cannot be used for this version"
	if required {
		restriction = " must be specified for this version"
	}
	return failure("InvalidRequest", field+restriction+" of Cross Region Replication configuration schema. Please refer to S3 Developer Guide for more information.", 400)
}

func parseReplicationFilter(rule api.ReplicationRule) (ReplicationFilter, *awswire.Error) {
	if rule.Filter == nil {
		if rule.Prefix == nil {
			return ReplicationFilter{}, malformedXML()
		}
		return ReplicationFilter{Kind: "legacy", Prefix: new(value(rule.Prefix))}, nil
	}
	if rule.Prefix != nil {
		return ReplicationFilter{}, malformedXML()
	}
	in := rule.Filter
	out := ReplicationFilter{Kind: "empty"}
	members := 0
	var tags api.TagSet
	if in.Prefix != nil {
		members++
		out.Kind, out.Prefix = "prefix", new(value(in.Prefix))
	}
	if in.Tag != nil {
		members++
		out.Kind, tags = "tag", api.TagSet{*in.Tag}
	}
	if in.And != nil {
		members++
		out.Kind, tags = "and", in.And.Tags
		predicates := len(tags)
		if in.And.Prefix != nil {
			out.Prefix = new(value(in.And.Prefix))
			predicates++
		}
		if predicates < 2 {
			return ReplicationFilter{}, malformedXML()
		}
	}
	if members > 1 {
		return ReplicationFilter{}, malformedXML()
	}
	if len(tags) != 0 {
		seen := make(map[string]struct{}, len(tags))
		for _, tag := range tags {
			key := value(tag.Key)
			if _, duplicate := seen[key]; duplicate {
				return ReplicationFilter{}, failure("InvalidRequest", "Duplicate Tag Keys are not allowed.", 400)
			}
			seen[key] = struct{}{}
		}
		var wire *awswire.Error
		out.Tags, wire = validateTags(&api.Tagging{TagSet: tags}, false)
		if wire != nil {
			return ReplicationFilter{}, wire
		}
	}
	return out, nil
}

func parseReplicationDestination(in *api.Destination, source BucketKey, kmsSelector bool) (ReplicationDestination, *awswire.Error) {
	out := ReplicationDestination{AccountID: value(in.Account), StorageClass: value(in.StorageClass)}
	bucketARN := value(in.Bucket)
	parsed, err := arn.Parse(bucketARN)
	if err != nil || parsed.Partition != source.Partition || parsed.Service != "s3" || parsed.Region != "" || parsed.AccountID != "" {
		return out, argumentError("Bucket", bucketARN, "Invalid bucket ARN")
	}
	if validateBucket(parsed.Resource) != nil {
		return out, argumentError("Bucket", bucketARN, "The specified bucket is not valid.")
	}
	out.Bucket = BucketKey{Partition: parsed.Partition, Name: parsed.Resource}
	if out.Bucket == source {
		return out, failure("InvalidRequest", "Destination bucket cannot be the same as the source bucket.", 400)
	}
	if _, wire := parseStorageClass(in.StorageClass); wire != nil {
		return out, malformedXML()
	}
	if override := in.AccessControlTranslation; override != nil {
		if value(override.Owner) != "Destination" {
			return out, malformedXML()
		}
		if out.AccountID == "" {
			return out, failure("InvalidRequest", "Account must be specified if the Owner in AccessControlTranslation has a value", 400)
		}
		out.OwnerOverride = true
	}
	// Account is a submitted assertion: native admission retains even an
	// unrelated account or a nonnumeric string, without checking ownership.
	if encryption := in.EncryptionConfiguration; encryption != nil {
		if !kmsSelector {
			return out, failure("InvalidRequest", "SseKmsEncryptedObjects must be specified if EncryptionConfiguration is present.", 400)
		}
		out.KMSKeyID = value(encryption.ReplicaKmsKeyID)
	}
	if kmsSelector && out.KMSKeyID == "" {
		return out, failure("InvalidRequest", "ReplicaKmsKeyID must be specified if SseKmsEncryptedObjects tag is present.", 400)
	}
	if out.KMSKeyID != "" {
		key, err := arn.Parse(out.KMSKeyID)
		if err != nil || key.Partition != source.Partition || key.Service != "kms" || key.Region == "" || !accountNumber.MatchString(key.AccountID) || (!strings.HasPrefix(key.Resource, "key/") && !strings.HasPrefix(key.Resource, "alias/")) || strings.HasSuffix(key.Resource, "/") {
			return out, argumentError("ReplicaKmsKeyID", out.KMSKeyID, "Invalid ReplicaKmsKeyID ARN.")
		}
	}
	if wire := parseReplicationMetrics(in, &out); wire != nil {
		return out, wire
	}
	return out, nil
}

func parseReplicationMetrics(in *api.Destination, out *ReplicationDestination) *awswire.Error {
	if metrics := in.Metrics; metrics != nil {
		out.MetricsStatus = value(metrics.Status)
		if !replicationStatus(out.MetricsStatus) {
			return malformedXML()
		}
		if threshold := metrics.EventThreshold; threshold != nil && threshold.Minutes != nil {
			out.MetricsMinutes = new(int32(*threshold.Minutes))
		}
	}
	if rtc := in.ReplicationTime; rtc != nil {
		out.TimeStatus = value(rtc.Status)
		if !replicationStatus(out.TimeStatus) || rtc.Time == nil {
			return malformedXML()
		}
		if in.Metrics == nil {
			return failure("InvalidRequest", "Replication destination must contain both ReplicationTime and Metrics or neither.", 400)
		}
		if rtc.Time.Minutes != nil {
			out.TimeMinutes = new(int32(*rtc.Time.Minutes))
		}
		if out.TimeMinutes == nil || *out.TimeMinutes != 15 {
			return replicationMetricsError("ReplicationTime", "Invalid time minute value")
		}
	}
	if out.TimeStatus == "Enabled" {
		if out.MetricsMinutes == nil {
			return replicationMetricsError("ReplicationMetrics", "ReplicationMetrics must contain an event threshold")
		}
		if *out.MetricsMinutes != 15 {
			return replicationMetricsError("ReplicationMetrics", "Invalid event threshold minute value")
		}
	} else if in.Metrics != nil && in.Metrics.EventThreshold != nil {
		return replicationMetricsError("Metrics", "Metrics cannot contain an event threshold when ReplicationTime is not specified or Disabled")
	}
	return nil
}

func replicationMetricsError(name, message string) *awswire.Error {
	wire := invalid(message)
	wire.ArgumentName = name
	return wire
}

func outputReplicationConfiguration(in *ReplicationConfiguration) *api.ReplicationConfiguration {
	out := &api.ReplicationConfiguration{Role: new(api.Role(in.RoleARN)), Rules: make(api.ReplicationRules, 0, len(in.Rules))}
	for _, rule := range in.Rules {
		status := api.ReplicationRuleStatus("Disabled")
		if rule.Enabled {
			status = api.ReplicationRuleStatus("Enabled")
		}
		stored := api.ReplicationRule{ID: new(api.ID(rule.ID)), Status: new(status), Destination: outputReplicationDestination(rule.Destination)}
		if rule.Priority != nil {
			stored.Priority = new(api.Priority(*rule.Priority))
		}
		filter := rule.Filter
		switch filter.Kind {
		case "legacy":
			stored.Prefix = new(api.Prefix(*filter.Prefix))
		case "empty":
			stored.Filter = &api.ReplicationRuleFilter{}
		case "prefix":
			stored.Filter = &api.ReplicationRuleFilter{Prefix: new(api.Prefix(*filter.Prefix))}
		case "tag":
			tag := filter.Tags[0]
			stored.Filter = &api.ReplicationRuleFilter{Tag: &api.Tag{Key: new(api.ObjectKey(tag.Key)), Value: new(api.Value(tag.Value))}}
		case "and":
			and := &api.ReplicationRuleAndOperator{Tags: outputTags(filter.Tags)}
			if filter.Prefix != nil {
				and.Prefix = new(api.Prefix(*filter.Prefix))
			}
			stored.Filter = &api.ReplicationRuleFilter{And: and}
		}
		if rule.DeleteMarkerReplication != "" {
			stored.DeleteMarkerReplication = &api.DeleteMarkerReplication{Status: new(api.DeleteMarkerReplicationStatus(rule.DeleteMarkerReplication))}
		}
		if rule.SSEKMSObjects != "" || rule.ReplicaModifications != "" {
			stored.SourceSelectionCriteria = &api.SourceSelectionCriteria{}
			if rule.SSEKMSObjects != "" {
				stored.SourceSelectionCriteria.SseKmsEncryptedObjects = &api.SseKmsEncryptedObjects{Status: new(api.SseKmsEncryptedObjectsStatus(rule.SSEKMSObjects))}
			}
			if rule.ReplicaModifications != "" {
				stored.SourceSelectionCriteria.ReplicaModifications = &api.ReplicaModifications{Status: new(api.ReplicaModificationsStatus(rule.ReplicaModifications))}
			}
		}
		out.Rules = append(out.Rules, stored)
	}
	return out
}

func outputReplicationDestination(in ReplicationDestination) *api.Destination {
	out := &api.Destination{Bucket: new(api.BucketName(in.Bucket.ARN()))}
	if in.AccountID != "" {
		out.Account = new(api.AccountId(in.AccountID))
	}
	if in.OwnerOverride {
		out.AccessControlTranslation = &api.AccessControlTranslation{Owner: new(api.OwnerOverride("Destination"))}
	}
	if in.StorageClass != "" {
		out.StorageClass = new(api.StorageClass(in.StorageClass))
	}
	if in.KMSKeyID != "" {
		out.EncryptionConfiguration = &api.EncryptionConfiguration{ReplicaKmsKeyID: new(api.ReplicaKmsKeyID(in.KMSKeyID))}
	}
	if in.MetricsStatus != "" {
		out.Metrics = &api.Metrics{Status: new(api.MetricsStatus(in.MetricsStatus))}
		if in.MetricsMinutes != nil {
			out.Metrics.EventThreshold = &api.ReplicationTimeValue{Minutes: new(api.Minutes(*in.MetricsMinutes))}
		}
	}
	if in.TimeStatus != "" {
		out.ReplicationTime = &api.ReplicationTime{Status: new(api.ReplicationTimeStatus(in.TimeStatus))}
		if in.TimeMinutes != nil {
			out.ReplicationTime.Time = &api.ReplicationTimeValue{Minutes: new(api.Minutes(*in.TimeMinutes))}
		}
	}
	return out
}
