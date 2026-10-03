package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/services/configservice"
	"stackd/internal/services/s3"
	"stackd/internal/services/sqs"
	"stackd/storage"
)

// ConfigResources reads a consistent snapshot from the existing typed owners.
// It does not issue synthetic API calls or persist a second live resource store.
type ConfigResources struct{ Backends *storage.Backends }

func (ConfigResources) SupportedTypes() []string {
	return []string{"AWS::S3::Bucket", "AWS::SQS::Queue"}
}
func (r ConfigResources) List(ctx context.Context, service string) ([]configservice.Item, error) {
	if r.Backends == nil || r.Backends.Read == nil {
		return nil, errors.New("config requires coordinated owner repositories")
	}
	m := awsctx.FromContext(ctx)
	scope := configservice.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
	var out []configservice.Item
	err := r.Backends.Read(ctx, func(ctx context.Context) error {
		if service == "" || service == "sqs" {
			rows, err := r.queues(ctx, scope)
			if err != nil {
				return err
			}
			out = append(out, rows...)
		}
		if service == "" || service == "s3" {
			rows, err := r.buckets(ctx, scope)
			if err != nil {
				return err
			}
			out = append(out, rows...)
		}
		return nil
	})
	slices.SortFunc(out, func(a, b configservice.Item) int {
		if n := strings.Compare(a.ResourceType, b.ResourceType); n != 0 {
			return n
		}
		return strings.Compare(a.ResourceID, b.ResourceID)
	})
	return out, err
}
func configQueueURL(key sqs.QueueKey) string {
	suffix := "amazonaws.com"
	if key.Partition == "aws-cn" {
		suffix = "amazonaws.com.cn"
	}
	return "https://sqs." + key.Region + "." + suffix + "/" + key.Account + "/" + key.Name
}
func (r ConfigResources) queues(ctx context.Context, scope configservice.Scope) (out []configservice.Item, err error) {
	err = r.Backends.SQS.View(ctx, func(reader sqs.Reader) error {
		rows, err := reader.Queues()
		if err != nil {
			return err
		}
		for _, q := range rows {
			if q.Key.Partition != scope.Partition || q.Key.Account != scope.AccountID || q.Key.Region != scope.Region {
				continue
			}
			arn := "arn:" + scope.Partition + ":sqs:" + scope.Region + ":" + scope.AccountID + ":" + q.Key.Name
			url := configQueueURL(q.Key)
			c := q.Configuration
			// Native configuration items retain SQS attributes as strings, including
			// decimal timestamps. Query-schema integer annotations are not wire types.
			configuration := map[string]any{"QueueArn": arn, "DelaySeconds": strconv.Itoa(c.DelaySeconds), "MaximumMessageSize": strconv.Itoa(c.MaximumMessageSize), "MessageRetentionPeriod": strconv.Itoa(c.RetentionSeconds), "VisibilityTimeout": strconv.Itoa(c.VisibilitySeconds), "ReceiveMessageWaitTimeSeconds": strconv.Itoa(c.WaitSeconds), "CreatedTimestamp": strconv.FormatInt(q.Created.Unix(), 10), "LastModifiedTimestamp": strconv.FormatInt(q.Modified.Unix(), 10), "SqsManagedSseEnabled": strconv.FormatBool(c.ManagedSSE)}
			if c.FIFO {
				configuration["FifoQueue"] = "true"
				configuration["ContentBasedDeduplication"] = strconv.FormatBool(c.ContentDeduplication)
				configuration["DeduplicationScope"] = c.DeduplicationScope
				configuration["FifoThroughputLimit"] = c.Throughput
			}
			if c.KMSKey != "" {
				configuration["KmsMasterKeyId"] = c.KMSKey
				configuration["KmsDataKeyReusePeriodSeconds"] = strconv.Itoa(c.KMSReuseSeconds)
			}
			if c.Policy != "" {
				configuration["Policy"] = c.Policy
			}
			if c.DeadLetterTargetARN != "" {
				policy, _ := json.Marshal(map[string]any{"deadLetterTargetArn": c.DeadLetterTargetARN, "maxReceiveCount": c.MaxReceiveCount})
				configuration["RedrivePolicy"] = string(policy)
			}
			// The native owned queue omitted the implicit allowAll default.
			if c.RedrivePermission != "" && (c.RedrivePermission != "allowAll" || len(c.RedriveSources) > 0) {
				policy := map[string]any{"redrivePermission": c.RedrivePermission}
				if len(c.RedriveSources) > 0 {
					policy["sourceQueueArns"] = c.RedriveSources
				}
				raw, _ := json.Marshal(policy)
				configuration["RedriveAllowPolicy"] = string(raw)
			}
			raw, err := json.Marshal(configuration)
			if err != nil {
				return err
			}
			tags := map[string]string{}
			for _, tag := range q.Tags {
				tags[tag.Key] = tag.Value
			}
			out = append(out, configservice.Item{Scope: scope, ResourceType: "AWS::SQS::Queue", ResourceID: url, ResourceName: q.Key.Name, ARN: arn, AvailabilityZone: "Not Applicable", CreationTime: q.Created, Configuration: string(raw), Tags: tags, Supplementary: map[string]string{"Tags": configJSON(tags)}})
		}
		return nil
	})
	return
}
func configJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }
func (r ConfigResources) buckets(ctx context.Context, scope configservice.Scope) (out []configservice.Item, err error) {
	err = r.Backends.S3.View(ctx, func(reader s3.Reader) error {
		rows, err := reader.Buckets(scope.Partition, scope.AccountID)
		if err != nil {
			return err
		}
		for _, b := range rows {
			if b.Region != scope.Region {
				continue
			}
			tags, err := reader.BucketTags(b.Key)
			if err != nil {
				return err
			}
			tagMap := map[string]string{}
			for _, tag := range tags {
				tagMap[tag.Key] = tag.Value
			}
			supplementary := map[string]string{}
			version := b.Versioning
			if version == "" {
				version = "Off"
			}
			supplementary["BucketVersioningConfiguration"] = configJSON(map[string]any{"status": version, "isMfaDeleteEnabled": nil})
			logging, err := reader.BucketLogging(b.Key)
			if err != nil {
				return err
			}
			logConfig := map[string]any{"destinationBucketName": nil, "logFilePrefix": nil, "targetObjectKeyFormat": nil}
			if logging != nil {
				logConfig["destinationBucketName"] = logging.TargetBucket
				logConfig["logFilePrefix"] = logging.TargetPrefix
			}
			supplementary["BucketLoggingConfiguration"] = configJSON(logConfig)
			var policy any
			if b.Policy.Document != "" {
				policy = b.Policy.Document
			}
			supplementary["BucketPolicy"] = configJSON(map[string]any{"policyText": policy})
			if b.PublicAccess != nil {
				p := b.PublicAccess
				supplementary["PublicAccessBlockConfiguration"] = configJSON(map[string]bool{"blockPublicAcls": p.BlockPublicACLs, "ignorePublicAcls": p.IgnorePublicACLs, "blockPublicPolicy": p.BlockPublicPolicy, "restrictPublicBuckets": p.RestrictPublicBuckets})
			}
			algorithm := b.EncryptionAlgorithm
			if algorithm == "" {
				algorithm = "AES256"
			}
			defaults := map[string]any{"sseAlgorithm": algorithm, "kmsMasterKeyID": nil}
			if b.KMSKeyID != "" {
				defaults["kmsMasterKeyID"] = b.KMSKeyID
			}
			supplementary["ServerSideEncryptionConfiguration"] = configJSON(map[string]any{"rules": []any{map[string]any{"applyServerSideEncryptionByDefault": defaults, "bucketKeyEnabled": b.BucketKeyEnabled}}})
			supplementary["IsRequesterPaysEnabled"] = strconv.FormatBool(b.RequesterPays)
			var acceleration any
			if b.AccelerationStatus != "" {
				acceleration = b.AccelerationStatus
			}
			supplementary["BucketAccelerateConfiguration"] = configJSON(map[string]any{"status": acceleration, "isRequesterCharged": false})
			supplementary["BucketTaggingConfiguration"] = configJSON(map[string]any{"tagSets": []any{map[string]any{"tags": tagMap}}})
			abac := "Disabled"
			if b.ABACEnabled {
				abac = "Enabled"
			}
			supplementary["AbacStatus"] = configJSON(map[string]string{"status": abac})
			acl := b.ACL
			if acl == nil || b.Ownership == "BucketOwnerEnforced" {
				acl = s3.DefaultACL(b.Key.Partition, b.AccountID)
			}
			owner := map[string]any{"displayName": nil, "id": acl.OwnerID}
			grants := []any{}
			for _, grant := range acl.Grants {
				grantee := map[string]any{"displayName": nil, "id": grant.ID}
				if grant.Type == "Group" {
					grantee = map[string]any{"uri": grant.URI}
				}
				permission := map[string]string{"FULL_CONTROL": "FullControl", "READ": "Read", "WRITE": "Write", "READ_ACP": "ReadAcp", "WRITE_ACP": "WriteAcp"}[grant.Permission]
				grants = append(grants, map[string]any{"grantee": grantee, "permission": permission})
			}
			supplementary["AccessControlList"] = configJSON(configJSON(map[string]any{"grantSet": nil, "grantList": grants, "owner": owner, "isRequesterCharged": false}))
			// TODO: Comeback fixture-calibrated S3 notification, CORS, lifecycle,
			// replication, website and Object Lock supplementary documents through their
			// typed owners. They are not synthesized from API echoes.
			out = append(out, configservice.Item{Scope: scope, ResourceType: "AWS::S3::Bucket", ResourceID: b.Key.Name, ResourceName: b.Key.Name, ARN: b.Key.ARN(), AvailabilityZone: "Regional", CreationTime: b.Created, Configuration: configJSON(map[string]any{"name": b.Key.Name, "owner": owner, "creationDate": b.Created.UTC().Format("2006-01-02T15:04:05.000Z"), "region": b.Region}), Tags: tagMap, Supplementary: supplementary})
		}
		return nil
	})
	return
}

// CapturePermission supplies the owner's current bound resource policy and tag
// conditions to the ordinary IAM evaluator under the Config role. Historical
// configuration JSON never serves as an authorization document.
func (r ConfigResources) CapturePermission(ctx context.Context, item configservice.Item) (authorization.Request, error) {
	request := authorization.Request{ResourceARN: item.ARN, ResourceAccountID: item.AccountID, Context: map[string][]string{}}
	if r.Backends == nil {
		return request, errors.New("config requires owner policy repositories")
	}
	for k, v := range item.Tags {
		request.Context["aws:ResourceTag/"+k] = []string{v}
	}
	switch item.ResourceType {
	case "AWS::SQS::Queue":
		err := r.Backends.SQS.View(ctx, func(reader sqs.Reader) error {
			rows, err := reader.Queues()
			if err != nil {
				return err
			}
			for _, q := range rows {
				if q.Key.Partition != item.Partition || q.Key.Account != item.AccountID || q.Key.Region != item.Region || q.Key.Name != item.ResourceName {
					continue
				}
				request.ResourcePolicies = []authorization.BoundPolicy{{Document: q.Configuration.Policy, PrincipalIDs: maps.Clone(q.Configuration.PolicyPrincipals)}}
				request.Context = map[string][]string{}
				for _, tag := range q.Tags {
					request.Context["aws:ResourceTag/"+tag.Key] = []string{tag.Value}
				}
				return nil
			}
			if item.Status != "ResourceDeleted" {
				return sqs.ErrNotFound
			}
			return nil
		})
		return request, err
	case "AWS::S3::Bucket":
		err := r.Backends.S3.View(ctx, func(reader s3.Reader) error {
			b, err := reader.Bucket(s3.BucketKey{Partition: item.Partition, Name: item.ResourceID})
			if errors.Is(err, s3.ErrNotFound) && item.Status == "ResourceDeleted" {
				return nil
			}
			if err != nil {
				return err
			}
			if b.AccountID != item.AccountID || b.Region != item.Region {
				return s3.ErrNotFound
			}
			request.ResourcePolicies = []authorization.BoundPolicy{b.Policy}
			request.Context = map[string][]string{"s3:ResourceAccount": {b.AccountID}}
			tags, err := reader.BucketTags(b.Key)
			if err != nil {
				return err
			}
			for _, tag := range tags {
				request.Context["aws:ResourceTag/"+tag.Key] = []string{tag.Value}
				request.Context["s3:BucketTag/"+tag.Key] = []string{tag.Value}
			}
			return nil
		})
		return request, err
	default:
		return request, fmt.Errorf("unsupported Config owner %s", item.ResourceType)
	}
}

var _ configservice.Resources = ConfigResources{}
var _ ConfigCapturePolicies = ConfigResources{}
