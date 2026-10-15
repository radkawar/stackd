package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"stackd/internal/awsapi"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
)

func (a *EC2FlowLogs) s3Command(ctx context.Context, action string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("s3")
	operation, _ := model.Operation(action)
	return a.S3.ExecuteCommand(flowLogCommand(ctx), awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
}

func (a *EC2FlowLogs) s3Preflight(ctx context.Context, record ec2.FlowLogRecord, bucket, prefix string) *awswire.Error {
	ctx = flowLogS3Context(ctx, record.Key)
	if _, wire := a.S3.GetBucketACL(ctx, &s3api.GetBucketAclInput{Bucket: new(s3api.BucketName(bucket))}); wire != nil {
		return wire
	}
	return a.S3.CheckPutObject(ctx, &s3api.PutObjectInput{Bucket: new(s3api.BucketName(bucket)), Key: new(s3api.ObjectKey(flowLogS3Prefix(prefix, record.Key, record.HivePartitions) + "permission-check.log.gz")), ACL: new(s3api.ObjectCannedACL("bucket-owner-full-control"))})
}

func (a *EC2FlowLogs) validateS3(ctx context.Context, record ec2.FlowLogRecord) *awswire.Error {
	if a.S3 == nil {
		return flowLogDeliveryError("S3 flow log delivery is unavailable.")
	}
	bucket, prefix, wire := flowLogBucket(record.Destination)
	if wire != nil {
		return wire
	}
	denied := a.s3Preflight(ctx, record, bucket, prefix)
	if denied == nil {
		return nil
	}
	if denied.Code != "AccessDenied" {
		return denied
	}
	// Only the actual bucket owner, using the configuring caller's current IAM
	// authority, can install delivery permission. A service principal cannot
	// grant itself permission. Existing policy statements remain intact.
	out, wire := a.s3Command(ctx, "GetBucketPolicy", &s3api.GetBucketPolicyInput{Bucket: new(s3api.BucketName(bucket)), ExpectedBucketOwner: new(s3api.AccountId(record.Key.Scope.AccountID))})
	if wire != nil && wire.Code != "NoSuchBucketPolicy" {
		return denied
	}
	policy := map[string]json.RawMessage{"Version": json.RawMessage(`"2012-10-17"`)}
	if wire != nil {
		policy["Id"] = json.RawMessage(`"AWSLogDeliveryWrite20150319"`)
	}
	var statements []json.RawMessage
	if wire == nil {
		result, ok := out.(*s3api.GetBucketPolicyOutput)
		if !ok || result.Policy == nil {
			return flowLogDeliveryError("S3 returned no readable bucket policy.")
		}
		if err := json.Unmarshal([]byte(*result.Policy), &policy); err != nil {
			return serviceRoleFailure(err)
		}
		if raw := policy["Statement"]; len(raw) != 0 {
			if err := json.Unmarshal(raw, &statements); err != nil {
				var statement map[string]json.RawMessage
				if err := json.Unmarshal(raw, &statement); err != nil {
					return serviceRoleFailure(err)
				}
				statements = []json.RawMessage{raw}
			}
		}
	}
	used := make(map[string]bool, len(statements))
	for _, raw := range statements {
		var statement struct{ Sid string }
		if err := json.Unmarshal(raw, &statement); err != nil {
			return serviceRoleFailure(err)
		}
		used[statement.Sid] = true
	}
	sid := func(base string) string {
		for n := 1; ; n++ {
			candidate := fmt.Sprintf("%s%d", base, n)
			if !used[candidate] {
				used[candidate] = true
				return candidate
			}
		}
	}
	bucketARN := "arn:" + record.Key.Scope.Partition + ":s3:::" + bucket
	path := prefix
	if path != "" {
		path += "/"
	}
	path += "AWSLogs/"
	if record.HivePartitions {
		path += "aws-account-id="
	}
	path += record.Key.Scope.AccountID + "/*"
	sourceARN := "arn:" + record.Key.Scope.Partition + ":logs:" + record.Key.Scope.Region + ":" + record.Key.Scope.AccountID + ":*"
	for _, statement := range []map[string]any{
		{"Sid": sid("AWSLogDeliveryWrite"), "Effect": "Allow", "Principal": map[string]string{"Service": "delivery.logs.amazonaws.com"}, "Action": "s3:PutObject", "Resource": bucketARN + "/" + path, "Condition": map[string]any{"StringEquals": map[string]string{"aws:SourceAccount": record.Key.Scope.AccountID, "s3:x-amz-acl": "bucket-owner-full-control"}, "ArnLike": map[string]string{"aws:SourceArn": sourceARN}}},
		{"Sid": sid("AWSLogDeliveryAclCheck"), "Effect": "Allow", "Principal": map[string]string{"Service": "delivery.logs.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": bucketARN, "Condition": map[string]any{"StringEquals": map[string]string{"aws:SourceAccount": record.Key.Scope.AccountID}, "ArnLike": map[string]string{"aws:SourceArn": sourceARN}}},
	} {
		encoded, err := json.Marshal(statement)
		if err != nil {
			return serviceRoleFailure(err)
		}
		exists, err := flowLogPolicyContains(statements, encoded)
		if err != nil {
			return serviceRoleFailure(err)
		}
		if exists {
			continue
		}
		statements = append(statements, encoded)
	}
	encodedStatements, err := json.Marshal(statements)
	if err != nil {
		return serviceRoleFailure(err)
	}
	policy["Statement"] = encodedStatements
	encoded, err := json.Marshal(policy)
	if err != nil {
		return serviceRoleFailure(err)
	}
	if _, wire := a.s3Command(ctx, "PutBucketPolicy", &s3api.PutBucketPolicyInput{Bucket: new(s3api.BucketName(bucket)), ExpectedBucketOwner: new(s3api.AccountId(record.Key.Scope.AccountID)), Policy: new(s3api.Policy(encoded))}); wire != nil {
		return wire
	}
	return a.s3Preflight(ctx, record, bucket, prefix)
}

// Native auto-attachment reuses the existing ACL grant for another destination
// prefix. Statement IDs identify statements; they are not permission semantics.
func flowLogPolicyContains(statements []json.RawMessage, candidate []byte) (bool, error) {
	normalize := func(raw []byte) ([]byte, error) {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(raw, &statement); err != nil {
			return nil, err
		}
		delete(statement, "Sid")
		encoded, err := json.Marshal(statement)
		if err != nil {
			return nil, err
		}
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, err
		}
		return json.Marshal(value)
	}
	wanted, err := normalize(candidate)
	if err != nil {
		return false, err
	}
	for _, statement := range statements {
		got, err := normalize(statement)
		if err != nil {
			return false, err
		}
		if bytes.Equal(got, wanted) {
			return true, nil
		}
	}
	return false, nil
}
