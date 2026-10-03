package integrations

import (
	"context"
	"math"

	"stackd/internal/services/cognitoidp"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/kms"
	"stackd/internal/services/lambda"
	"stackd/internal/services/logs"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/internal/services/s3"
	"stackd/internal/services/secretsmanager"
	"stackd/internal/services/sns"
	"stackd/internal/services/sqs"
	"stackd/internal/services/ssm"
	"stackd/internal/services/ssmdocuments"
	"stackd/internal/services/stepfunctions"
)

func (r ResourceTaggingResources) listTaggingS3(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.S3.View(ctx, func(tx s3.Reader) error {
		buckets, err := tx.Buckets(scope.Partition, scope.AccountID)
		if err != nil {
			return err
		}
		for _, bucket := range buckets {
			if bucket.Region != scope.Region {
				continue
			}
			tags, err := tx.BucketTags(bucket.Key)
			if err != nil {
				return err
			}
			out = append(out, tagging.Resource{ARN: bucket.Key.ARN(), ResourceType: "s3:bucket", Tags: resourceTaggingS3Tags(tags)})
		}
		points, err := tx.AccessPoints(s3.AccessPointQuery{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, point := range points {
			tags, err := tx.AccessPointTags(point.Key)
			if err != nil {
				return err
			}
			out = append(out, tagging.Resource{ARN: point.Key.ARN(), ResourceType: "s3:accesspoint", Tags: resourceTaggingS3Tags(tags)})
		}
		return nil
	})
	return
}

func resourceTaggingS3Tags(tags []s3.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[tag.Key] = tag.Value
	}
	return out
}

func (r ResourceTaggingResources) listTaggingSQS(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.SQS.View(ctx, func(tx sqs.Reader) error {
		queues, err := tx.Queues()
		if err != nil {
			return err
		}
		for _, queue := range queues {
			if queue.Key.Partition != scope.Partition || queue.Key.Account != scope.AccountID || queue.Key.Region != scope.Region {
				continue
			}
			var tags map[string]string
			if len(queue.Tags) != 0 {
				tags = make(map[string]string, len(queue.Tags))
				for _, tag := range queue.Tags {
					tags[tag.Key] = tag.Value
				}
			}
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "sqs", queue.Key.Name), ResourceType: "sqs:queue", Tags: tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingSNS(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.SNS.View(ctx, func(tx sns.Reader) error {
		rows, err := tx.Topics(sns.TopicQuery{Scope: sns.Scope(scope), Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "sns:topic", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingLambda(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Lambda.View(ctx, func(tx lambda.Reader) error {
		sc := lambda.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region}
		functions, err := tx.Functions(sc)
		if err != nil {
			return err
		}
		for _, row := range functions {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "lambda:function", Tags: row.Tags})
		}
		mappings, err := tx.EventSourceMappings(sc)
		if err != nil {
			return err
		}
		for _, row := range mappings {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "lambda:event-source-mapping", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingEvents(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.EventBridge.View(ctx, func(tx eventbridge.Reader) error {
		buses, err := tx.Buses(eventbridge.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region})
		if err != nil {
			return err
		}
		// The native owner exposes the default bus before its first write.
		hasDefault := false
		for _, bus := range buses {
			hasDefault = hasDefault || bus.Key.Name == "default"
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "events", "event-bus/"+bus.Key.Name), ResourceType: "events:event-bus", Tags: bus.Tags})
			rules, err := tx.Rules(bus.Key)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				name := rule.Key.Name
				if bus.Key.Name != "default" {
					name = bus.Key.Name + "/" + name
				}
				out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "events", "rule/"+name), ResourceType: "events:rule", Tags: rule.Tags})
			}
		}
		if !hasDefault {
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "events", "event-bus/default"), ResourceType: "events:event-bus"})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingLogs(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Logs.View(ctx, func(tx logs.Reader) error {
		groups, err := tx.Groups(logs.GroupQuery{Scope: logs.Scope(scope), Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range groups {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "logs:log-group", Tags: row.Tags})
		}
		destinations, err := tx.Destinations(logs.DestinationQuery{Scope: logs.Scope(scope), Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range destinations {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "logs:destination", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingKMS(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.KMS.View(ctx, func(tx kms.Reader) error {
		keys, err := tx.Keys(kms.StorageScope(scope))
		if err != nil {
			return err
		}
		for _, key := range keys {
			if key.Manager != "CUSTOMER" {
				continue
			}
			var tags map[string]string
			if len(key.Tags) != 0 {
				tags = make(map[string]string, len(key.Tags))
				for _, tag := range key.Tags {
					tags[tag.Key] = tag.Value
				}
			}
			out = append(out, tagging.Resource{ARN: key.ARN, ResourceType: "kms:key", Tags: tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingSSM(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.SSM.View(ctx, func(tx ssm.Reader) error {
		rows, err := tx.Parameters(ssm.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.ARN, ResourceType: "ssm:parameter", Tags: row.Tags})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = r.Backends.SSMDocuments.View(ctx, func(tx ssmdocuments.Reader) error {
		rows, err := tx.Documents(ssmdocuments.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "ssm", "document/"+row.Key.Name), ResourceType: "ssm:document", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingSecrets(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.SecretsManager.View(ctx, func(tx secretsmanager.Reader) error {
		rows, err := tx.Secrets(secretsmanager.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Deleted != nil {
				continue
			}
			out = append(out, tagging.Resource{ARN: row.ARN, ResourceType: "secretsmanager:secret", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingStates(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.StepFunctions.View(ctx, func(tx stepfunctions.Reader) error {
		machines, err := tx.Machines(stepfunctions.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range machines {
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "states", "stateMachine:"+row.Key.Name), ResourceType: "states:stateMachine", Tags: row.Tags})
		}
		activities, err := tx.Activities(stepfunctions.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range activities {
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "states", "activity:"+row.Key.Name), ResourceType: "states:activity", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingCognito(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.CognitoIDP.View(ctx, func(tx cognitoidp.Reader) error {
		rows, err := tx.Pools(cognitoidp.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "cognito-idp:userpool", Tags: resourceTaggingSnapshotMap(row.Data.UserPoolTags)})
		}
		return nil
	})
	return
}
