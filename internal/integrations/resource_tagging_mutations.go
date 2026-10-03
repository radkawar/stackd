package integrations

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	apigatewayapi "stackd/internal/awsapi/apigateway"
	apigatewayv2api "stackd/internal/awsapi/apigatewayv2"
	appconfigapi "stackd/internal/awsapi/appconfig"
	applicationautoscalingapi "stackd/internal/awsapi/applicationautoscaling"
	athenaapi "stackd/internal/awsapi/athena"
	autoscalingapi "stackd/internal/awsapi/autoscaling"
	cloudformationapi "stackd/internal/awsapi/cloudformation"
	cloudtrailapi "stackd/internal/awsapi/cloudtrail"
	cloudwatchapi "stackd/internal/awsapi/cloudwatch"
	codebuildapi "stackd/internal/awsapi/codebuild"
	cognitoidpapi "stackd/internal/awsapi/cognitoidp"
	configserviceapi "stackd/internal/awsapi/configservice"
	dynamodbapi "stackd/internal/awsapi/dynamodb"
	ec2api "stackd/internal/awsapi/ec2"
	ecrapi "stackd/internal/awsapi/ecr"
	ecsapi "stackd/internal/awsapi/ecs"
	eksapi "stackd/internal/awsapi/eks"
	elasticacheapi "stackd/internal/awsapi/elasticache"
	elbv2api "stackd/internal/awsapi/elbv2"
	eventbridgeapi "stackd/internal/awsapi/eventbridge"
	firehoseapi "stackd/internal/awsapi/firehose"
	glueapi "stackd/internal/awsapi/glue"
	iamapi "stackd/internal/awsapi/iam"
	kafkaapi "stackd/internal/awsapi/kafka"
	kinesisapi "stackd/internal/awsapi/kinesis"
	kmsapi "stackd/internal/awsapi/kms"
	lambdaapi "stackd/internal/awsapi/lambda"
	logsapi "stackd/internal/awsapi/logs"
	memorydbapi "stackd/internal/awsapi/memorydb"
	opensearchapi "stackd/internal/awsapi/opensearch"
	organizationsapi "stackd/internal/awsapi/organizations"
	pipesapi "stackd/internal/awsapi/pipes"
	rdsapi "stackd/internal/awsapi/rds"
	resourcegroupsapi "stackd/internal/awsapi/resourcegroups"
	s3api "stackd/internal/awsapi/s3"
	s3controlapi "stackd/internal/awsapi/s3control"
	schedulerapi "stackd/internal/awsapi/scheduler"
	secretsmanagerapi "stackd/internal/awsapi/secretsmanager"
	appregistryapi "stackd/internal/awsapi/servicecatalogappregistry"
	sesv2api "stackd/internal/awsapi/sesv2"
	snsapi "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	ssmapi "stackd/internal/awsapi/ssm"
	stepfunctionsapi "stackd/internal/awsapi/stepfunctions"
	xrayapi "stackd/internal/awsapi/xray"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/resourcegroupstaggingapi"
	autoscalingstore "stackd/storage/autoscaling"
	cloudformationstore "stackd/storage/cloudformation"
	codebuildstore "stackd/storage/codebuild"
	iamstore "stackd/storage/iam"
	s3store "stackd/storage/s3"
)

// Tag delegates mutation and authorization to the resource's native owner. The
// inventory snapshot supplies identity only; it never supplies authoritative tags.
func (r *ResourceTaggingResources) Tag(ctx context.Context, resource resourcegroupstaggingapi.Resource, tags map[string]string) error {
	return r.mutateResourceTags(ctx, resource, tags, nil, false)
}

// Untag retains the native owner's key validation and current IAM authority.
func (r *ResourceTaggingResources) Untag(ctx context.Context, resource resourcegroupstaggingapi.Resource, keys []string) error {
	return r.mutateResourceTags(ctx, resource, nil, keys, true)
}

func (r *ResourceTaggingResources) mutateResourceTags(ctx context.Context, resource resourcegroupstaggingapi.Resource, tags map[string]string, keys []string, remove bool) error {
	parts := strings.SplitN(resource.ARN, ":", 6)
	m := awsctx.FromContext(ctx)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != m.Partition || parts[5] == "" || (parts[3] != "" && parts[3] != m.Region) || (parts[4] != "" && parts[4] != m.AccountID) {
		return resourceTaggingInvalid("Resource ARN must identify a resource in the current account, partition and Region.")
	}
	arn, identity := resource.ARN, parts[5]
	switch parts[2] {
	case "servicecatalog":
		if !strings.HasPrefix(identity, "/applications/") && !strings.HasPrefix(identity, "/attribute-groups/") {
			return resourceTaggingUnsupported(resource)
		}
		if remove {
			in := &appregistryapi.UntagResourceRequest{ResourceArn: new(appregistryapi.Arn(arn))}
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "servicecatalogappregistry", "UntagResource", in)
		}
		in := &appregistryapi.TagResourceRequest{ResourceArn: new(appregistryapi.Arn(arn))}
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "servicecatalogappregistry", "TagResource", in)
	case "resource-groups":
		if remove {
			in := &resourcegroupsapi.UntagInput{}
			resourceTaggingString(&in.Arn, arn)
			resourceTaggingStrings(&in.Keys, keys)
			return r.callResourceTagging(ctx, "resourcegroups", "Untag", in)
		}
		in := &resourcegroupsapi.TagInput{}
		resourceTaggingString(&in.Arn, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "resourcegroups", "Tag", in)
	case "appconfig":
		if remove {
			in := &appconfigapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "appconfig", "UntagResource", in)
		}
		in := &appconfigapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "appconfig", "TagResource", in)
	case "config":
		if remove {
			in := &configserviceapi.UntagResourceInput{ResourceArn: new(configserviceapi.AmazonResourceName(arn))}
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "configservice", "UntagResource", in)
		}
		in := &configserviceapi.TagResourceInput{ResourceArn: new(configserviceapi.AmazonResourceName(arn))}
		in.Tags = resourceTaggingPairs(tags, func(key, value string) configserviceapi.Tag {
			return configserviceapi.Tag{Key: new(configserviceapi.TagKey(key)), Value: new(configserviceapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "configservice", "TagResource", in)
	case "application-autoscaling":
		if remove {
			in := &applicationautoscalingapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceARN, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "applicationautoscaling", "UntagResource", in)
		}
		in := &applicationautoscalingapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceARN, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "applicationautoscaling", "TagResource", in)
	case "athena":
		if remove {
			in := &athenaapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceARN, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "athena", "UntagResource", in)
		}
		in := &athenaapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceARN, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) athenaapi.Tag {
			return athenaapi.Tag{Key: new(athenaapi.TagKey(key)), Value: new(athenaapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "athena", "TagResource", in)
	case "cloudtrail":
		if remove {
			in := &cloudtrailapi.RemoveTagsInput{}
			resourceTaggingString(&in.ResourceId, arn)
			in.TagsList = make(cloudtrailapi.TagsList, len(keys))
			for i, key := range keys {
				in.TagsList[i].Key = new(cloudtrailapi.TagKey(key))
			}
			return r.callResourceTagging(ctx, "cloudtrail", "RemoveTags", in)
		}
		in := &cloudtrailapi.AddTagsInput{}
		resourceTaggingString(&in.ResourceId, arn)
		in.TagsList = resourceTaggingPairs(tags, func(key, value string) cloudtrailapi.Tag {
			return cloudtrailapi.Tag{Key: new(cloudtrailapi.TagKey(key)), Value: new(cloudtrailapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "cloudtrail", "AddTags", in)
	case "cloudwatch", "monitoring":
		// Resource Groups Tagging supports CloudWatch alarm mutations only;
		// dashboard tags remain discoverable and natively mutable in CloudWatch.
		if !strings.HasPrefix(identity, "alarm:") {
			return resourceTaggingUnsupported(resource)
		}
		if remove {
			in := &cloudwatchapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceARN, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "cloudwatch", "UntagResource", in)
		}
		in := &cloudwatchapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceARN, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) cloudwatchapi.Tag {
			return cloudwatchapi.Tag{Key: new(cloudwatchapi.TagKey(key)), Value: new(cloudwatchapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "cloudwatch", "TagResource", in)
	case "cognito-idp":
		if remove {
			in := &cognitoidpapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "cognitoidp", "UntagResource", in)
		}
		in := &cognitoidpapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "cognitoidp", "TagResource", in)
	case "dynamodb":
		if remove {
			in := &dynamodbapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "dynamodb", "UntagResource", in)
		}
		in := &dynamodbapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) dynamodbapi.Tag {
			return dynamodbapi.Tag{Key: new(dynamodbapi.TagKeyString(key)), Value: new(dynamodbapi.TagValueString(value))}
		})
		return r.callResourceTagging(ctx, "dynamodb", "TagResource", in)
	case "ecr":
		if remove {
			in := &ecrapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "ecr", "UntagResource", in)
		}
		in := &ecrapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) ecrapi.Tag {
			return ecrapi.Tag{Key: new(ecrapi.TagKey(key)), Value: new(ecrapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "ecr", "TagResource", in)
	case "ecs":
		if remove {
			in := &ecsapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "ecs", "UntagResource", in)
		}
		in := &ecsapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) ecsapi.Tag {
			return ecsapi.Tag{Key: new(ecsapi.TagKey(key)), Value: new(ecsapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "ecs", "TagResource", in)
	case "eks":
		if remove {
			in := &eksapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "eks", "UntagResource", in)
		}
		in := &eksapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "eks", "TagResource", in)
	case "elasticache":
		if remove {
			in := &elasticacheapi.RemoveTagsFromResourceInput{}
			resourceTaggingString(&in.ResourceName, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "elasticache", "RemoveTagsFromResource", in)
		}
		in := &elasticacheapi.AddTagsToResourceInput{}
		resourceTaggingString(&in.ResourceName, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) elasticacheapi.Tag {
			return elasticacheapi.Tag{Key: new(elasticacheapi.String(key)), Value: new(elasticacheapi.String(value))}
		})
		return r.callResourceTagging(ctx, "elasticache", "AddTagsToResource", in)
	case "events":
		if remove {
			in := &eventbridgeapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceARN, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "eventbridge", "UntagResource", in)
		}
		in := &eventbridgeapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceARN, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) eventbridgeapi.Tag {
			return eventbridgeapi.Tag{Key: new(eventbridgeapi.TagKey(key)), Value: new(eventbridgeapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "eventbridge", "TagResource", in)
	case "firehose":
		if !strings.HasPrefix(identity, "deliverystream/") {
			return resourceTaggingUnsupported(resource)
		}
		name := strings.TrimPrefix(identity, "deliverystream/")
		if remove {
			in := &firehoseapi.UntagDeliveryStreamInput{}
			resourceTaggingString(&in.DeliveryStreamName, name)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "firehose", "UntagDeliveryStream", in)
		}
		in := &firehoseapi.TagDeliveryStreamInput{}
		resourceTaggingString(&in.DeliveryStreamName, name)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) firehoseapi.Tag {
			return firehoseapi.Tag{Key: new(firehoseapi.TagKey(key)), Value: new(firehoseapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "firehose", "TagDeliveryStream", in)
	case "glue":
		if remove {
			in := &glueapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagsToRemove, keys)
			return r.callResourceTagging(ctx, "glue", "UntagResource", in)
		}
		in := &glueapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		resourceTaggingMap(&in.TagsToAdd, tags)
		return r.callResourceTagging(ctx, "glue", "TagResource", in)
	case "kafka":
		if remove {
			in := &kafkaapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "kafka", "UntagResource", in)
		}
		in := &kafkaapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "kafka", "TagResource", in)
	case "kinesis":
		if remove {
			in := &kinesisapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceARN, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "kinesis", "UntagResource", in)
		}
		in := &kinesisapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceARN, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "kinesis", "TagResource", in)
	case "kms":
		if remove {
			in := &kmsapi.UntagResourceInput{}
			resourceTaggingString(&in.KeyId, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "kms", "UntagResource", in)
		}
		in := &kmsapi.TagResourceInput{}
		resourceTaggingString(&in.KeyId, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) kmsapi.Tag {
			return kmsapi.Tag{TagKey: new(kmsapi.TagKeyType(key)), TagValue: new(kmsapi.TagValueType(value))}
		})
		return r.callResourceTagging(ctx, "kms", "TagResource", in)
	case "lambda":
		if remove {
			in := &lambdaapi.UntagResourceInput{}
			resourceTaggingString(&in.Resource, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "lambda", "UntagResource", in)
		}
		in := &lambdaapi.TagResourceInput{}
		resourceTaggingString(&in.Resource, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "lambda", "TagResource", in)
	case "logs":
		if remove {
			in := &logsapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "logs", "UntagResource", in)
		}
		in := &logsapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "logs", "TagResource", in)
	case "memorydb":
		if remove {
			in := &memorydbapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "memorydb", "UntagResource", in)
		}
		in := &memorydbapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) memorydbapi.Tag {
			return memorydbapi.Tag{Key: new(memorydbapi.String(key)), Value: new(memorydbapi.String(value))}
		})
		return r.callResourceTagging(ctx, "memorydb", "TagResource", in)
	case "es":
		if remove {
			in := &opensearchapi.RemoveTagsInput{}
			resourceTaggingString(&in.ARN, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "opensearch", "RemoveTags", in)
		}
		in := &opensearchapi.AddTagsInput{}
		resourceTaggingString(&in.ARN, arn)
		in.TagList = resourceTaggingPairs(tags, func(key, value string) opensearchapi.Tag {
			return opensearchapi.Tag{Key: new(opensearchapi.TagKey(key)), Value: new(opensearchapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "opensearch", "AddTags", in)
	case "organizations":
		name := identity[strings.LastIndexByte(identity, '/')+1:]
		if remove {
			in := &organizationsapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceId, name)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callOrganizationsResourceTagging(ctx, arn, name, "UntagResource", in)
		}
		in := &organizationsapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceId, name)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) organizationsapi.Tag {
			return organizationsapi.Tag{Key: new(organizationsapi.TagKey(key)), Value: new(organizationsapi.TagValue(value))}
		})
		return r.callOrganizationsResourceTagging(ctx, arn, name, "TagResource", in)
	case "pipes":
		if remove {
			in := &pipesapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "pipes", "UntagResource", in)
		}
		in := &pipesapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "pipes", "TagResource", in)
	case "rds":
		if remove {
			in := &rdsapi.RemoveTagsFromResourceInput{}
			resourceTaggingString(&in.ResourceName, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "rds", "RemoveTagsFromResource", in)
		}
		in := &rdsapi.AddTagsToResourceInput{}
		resourceTaggingString(&in.ResourceName, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) rdsapi.Tag {
			return rdsapi.Tag{Key: new(rdsapi.String(key)), Value: new(rdsapi.String(value))}
		})
		return r.callResourceTagging(ctx, "rds", "AddTagsToResource", in)
	case "scheduler":
		if remove {
			in := &schedulerapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "scheduler", "UntagResource", in)
		}
		in := &schedulerapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) schedulerapi.Tag {
			return schedulerapi.Tag{Key: new(schedulerapi.TagKey(key)), Value: new(schedulerapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "scheduler", "TagResource", in)
	case "secretsmanager":
		if remove {
			in := &secretsmanagerapi.UntagResourceInput{}
			resourceTaggingString(&in.SecretId, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "secretsmanager", "UntagResource", in)
		}
		in := &secretsmanagerapi.TagResourceInput{}
		resourceTaggingString(&in.SecretId, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) secretsmanagerapi.Tag {
			return secretsmanagerapi.Tag{Key: new(secretsmanagerapi.TagKeyType(key)), Value: new(secretsmanagerapi.TagValueType(value))}
		})
		return r.callResourceTagging(ctx, "secretsmanager", "TagResource", in)
	case "ses", "email":
		if remove {
			in := &sesv2api.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "sesv2", "UntagResource", in)
		}
		in := &sesv2api.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) sesv2api.Tag {
			return sesv2api.Tag{Key: new(sesv2api.TagKey(key)), Value: new(sesv2api.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "sesv2", "TagResource", in)
	case "sns":
		if remove {
			in := &snsapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "sns", "UntagResource", in)
		}
		in := &snsapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) snsapi.Tag {
			return snsapi.Tag{Key: new(snsapi.TagKey(key)), Value: new(snsapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "sns", "TagResource", in)
	case "sqs":
		suffix := "amazonaws.com"
		if m.Partition == "aws-cn" {
			suffix = "amazonaws.com.cn"
		}
		queueURL := "https://sqs." + m.Region + "." + suffix + "/" + m.AccountID + "/" + identity
		if remove {
			in := &sqsapi.UntagQueueInput{}
			resourceTaggingString(&in.QueueUrl, queueURL)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "sqs", "UntagQueue", in)
		}
		in := &sqsapi.TagQueueInput{}
		resourceTaggingString(&in.QueueUrl, queueURL)
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "sqs", "TagQueue", in)
	case "states":
		if remove {
			in := &stepfunctionsapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "stepfunctions", "UntagResource", in)
		}
		in := &stepfunctionsapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceArn, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) stepfunctionsapi.Tag {
			return stepfunctionsapi.Tag{Key: new(stepfunctionsapi.TagKey(key)), Value: new(stepfunctionsapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "stepfunctions", "TagResource", in)
	case "xray":
		if remove {
			in := &xrayapi.UntagResourceInput{}
			resourceTaggingString(&in.ResourceARN, arn)
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "xray", "UntagResource", in)
		}
		in := &xrayapi.TagResourceInput{}
		resourceTaggingString(&in.ResourceARN, arn)
		in.Tags = resourceTaggingPairs(tags, func(key, value string) xrayapi.Tag {
			return xrayapi.Tag{Key: new(xrayapi.TagKey(key)), Value: new(xrayapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "xray", "TagResource", in)
	case "ec2":
		kind, id, ok := strings.Cut(identity, "/")
		if !ok || !resourceTaggingEC2Identity(kind, id) {
			return resourceTaggingInvalid("EC2 resource ARN type must match its resource ID.")
		}
		if remove {
			in := &ec2api.DeleteTagsInput{Resources: ec2api.ResourceIdList{ec2api.TaggableResourceId(id)}, Tags: make(ec2api.TagList, len(keys))}
			for i, key := range keys {
				in.Tags[i].Key = new(ec2api.String(key))
			}
			return r.callResourceTagging(ctx, "ec2", "DeleteTags", in)
		}
		in := &ec2api.CreateTagsInput{Resources: ec2api.ResourceIdList{ec2api.TaggableResourceId(id)}}
		in.Tags = resourceTaggingPairs(tags, func(key, value string) ec2api.Tag {
			return ec2api.Tag{Key: new(ec2api.String(key)), Value: new(ec2api.String(value))}
		})
		return r.callResourceTagging(ctx, "ec2", "CreateTags", in)
	case "elasticloadbalancing":
		if remove {
			in := &elbv2api.RemoveTagsInput{}
			resourceTaggingStrings(&in.ResourceArns, []string{arn})
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "elbv2", "RemoveTags", in)
		}
		in := &elbv2api.AddTagsInput{}
		resourceTaggingStrings(&in.ResourceArns, []string{arn})
		in.Tags = resourceTaggingPairs(tags, func(key, value string) elbv2api.Tag {
			return elbv2api.Tag{Key: new(elbv2api.TagKey(key)), Value: new(elbv2api.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "elbv2", "AddTags", in)
	case "apigateway":
		if strings.HasPrefix(identity, "/apis/") {
			if remove {
				in := &apigatewayv2api.UntagResourceInput{}
				resourceTaggingString(&in.ResourceArn, arn)
				resourceTaggingStrings(&in.TagKeys, keys)
				return r.callResourceTagging(ctx, "apigatewayv2", "UntagResource", in)
			}
			in := &apigatewayv2api.TagResourceInput{}
			resourceTaggingString(&in.ResourceArn, arn)
			resourceTaggingMap(&in.Tags, tags)
			return r.callResourceTagging(ctx, "apigatewayv2", "TagResource", in)
		}
		if remove {
			in := &apigatewayapi.UntagResourceInput{ResourceArn: new(apigatewayapi.String(arn))}
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "apigateway", "UntagResource", in)
		}
		in := &apigatewayapi.TagResourceInput{ResourceArn: new(apigatewayapi.String(arn))}
		resourceTaggingMap(&in.Tags, tags)
		return r.callResourceTagging(ctx, "apigateway", "TagResource", in)
	case "ssm":
		kind, name, ok := strings.Cut(identity, "/")
		if !ok || name == "" {
			return resourceTaggingInvalid("SSM resource ARN must contain a resource type and ID.")
		}
		switch kind {
		case "parameter":
			kind, name = "Parameter", "/"+name
		case "document":
			kind = "Document"
		case "managed-instance":
			kind = "ManagedInstance"
		case "maintenancewindow":
			kind = "MaintenanceWindow"
		case "patchbaseline":
			kind = "PatchBaseline"
		default:
			return resourceTaggingUnsupported(resource)
		}
		if remove {
			in := &ssmapi.RemoveTagsFromResourceInput{ResourceId: new(ssmapi.ResourceId(name)), ResourceType: new(ssmapi.ResourceTypeForTagging(kind))}
			resourceTaggingStrings(&in.TagKeys, keys)
			return r.callResourceTagging(ctx, "ssm", "RemoveTagsFromResource", in)
		}
		in := &ssmapi.AddTagsToResourceInput{ResourceId: new(ssmapi.ResourceId(name)), ResourceType: new(ssmapi.ResourceTypeForTagging(kind))}
		in.Tags = resourceTaggingPairs(tags, func(key, value string) ssmapi.Tag {
			return ssmapi.Tag{Key: new(ssmapi.TagKey(key)), Value: new(ssmapi.TagValue(value))}
		})
		return r.callResourceTagging(ctx, "ssm", "AddTagsToResource", in)
	case "s3":
		return r.mutateS3ResourceTags(ctx, resource, identity, tags, keys, remove)
	case "codebuild":
		return r.mutateCodeBuildResourceTags(ctx, resource, identity, tags, keys)
	case "cloudformation":
		return r.mutateStackResourceTags(ctx, resource, tags, keys)
	case "autoscaling":
		return r.mutateAutoScalingResourceTags(ctx, resource, identity, tags, keys, remove)
	case "iam":
		return r.mutateIAMResourceTags(ctx, resource, identity, tags, keys, remove)
	default:
		return resourceTaggingUnsupported(resource)
	}
}

func (r *ResourceTaggingResources) callResourceTagging(ctx context.Context, service, operation string, input any) error {
	_, rejected := r.Commands.CallTyped(ctx, service, operation, input)
	if rejected != nil {
		return rejected
	}
	return nil
}

func resourceTaggingInvalid(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidParameterException", Message: message, StatusCode: 400}
}

func resourceTaggingUnsupported(resource resourcegroupstaggingapi.Resource) *awswire.Error {
	return &awswire.Error{Code: "UnsupportedOperation", Message: "The resource owner does not support tagging this resource: " + resource.ARN, StatusCode: 400}
}

// Generated Smithy string aliases include unexported names. Type inference keeps
// these conversions typed without reflection, JSON round trips or request maps.
func resourceTaggingString[T ~string](target **T, value string) {
	*target = new(T(value))
}

func resourceTaggingStrings[S ~[]T, T ~string](target *S, values []string) {
	out := make(S, len(values))
	for i, value := range values {
		out[i] = T(value)
	}
	*target = out
}

func resourceTaggingMap[M ~map[K]V, K ~string, V ~string](target *M, values map[string]string) {
	out := make(M, len(values))
	for key, value := range values {
		out[K(key)] = V(value)
	}
	*target = out
}

func resourceTaggingPairs[T any](tags map[string]string, pair func(string, string) T) []T {
	out := make([]T, 0, len(tags))
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, pair(key, tags[key]))
	}
	return out
}

func resourceTaggingMerge(current, tags map[string]string, keys []string) map[string]string {
	// Only detached, freshly read owner state is passed here, never Resource.Tags.
	if current == nil {
		current = make(map[string]string, len(tags))
	}
	maps.Copy(current, tags)
	for _, key := range keys {
		delete(current, key)
	}
	return current
}

func (r *ResourceTaggingResources) mutateS3ResourceTags(ctx context.Context, resource resourcegroupstaggingapi.Resource, identity string, tags map[string]string, keys []string, remove bool) error {
	m := awsctx.FromContext(ctx)
	return r.Backends.S3.Update(ctx, func(tx s3store.Transaction) error {
		ctx := tx.Context()
		control := strings.HasPrefix(identity, "accesspoint/")
		if !control {
			parts := strings.SplitN(resource.ARN, ":", 6)
			if parts[3] != "" || parts[4] != "" || strings.Contains(identity, "/") {
				return resourceTaggingInvalid("S3 bucket ARN must contain only the bucket name and partition.")
			}
			bucket, err := tx.Bucket(s3store.BucketKey{Partition: m.Partition, Name: identity})
			if err != nil && !errors.Is(err, s3store.ErrNotFound) {
				return err
			}
			if err == nil {
				if bucket.AccountID != m.AccountID || bucket.Region != m.Region {
					return resourceTaggingInvalid("Bucket must belong to the current account and Region.")
				}
				control = bucket.ABACEnabled
			}
		}
		if control {
			if remove {
				in := &s3controlapi.UntagResourceInput{AccountId: new(s3controlapi.AccountId(m.AccountID)), ResourceArn: new(s3controlapi.S3ResourceArn(resource.ARN))}
				resourceTaggingStrings(&in.TagKeys, keys)
				return r.callResourceTagging(ctx, "s3control", "UntagResource", in)
			}
			in := &s3controlapi.TagResourceInput{AccountId: new(s3controlapi.AccountId(m.AccountID)), ResourceArn: new(s3controlapi.S3ResourceArn(resource.ARN))}
			in.Tags = resourceTaggingPairs(tags, func(key, value string) s3controlapi.Tag {
				return s3controlapi.Tag{Key: new(s3controlapi.TagKeyString(key)), Value: new(s3controlapi.TagValueString(value))}
			})
			return r.callResourceTagging(ctx, "s3control", "TagResource", in)
		}
		// S3's legacy API replaces the entire set. Its read authorization and the
		// native write must share this transaction so concurrent tags are not lost.
		read := &s3api.GetBucketTaggingInput{Bucket: new(s3api.BucketName(identity)), ExpectedBucketOwner: new(s3api.AccountId(m.AccountID))}
		current := make(map[string]string)
		err := r.Backends.S3.Attempt(ctx, func(readTx s3store.Transaction) error {
			result, rejected := r.Commands.CallTyped(readTx.Context(), "s3", "GetBucketTagging", read)
			if rejected != nil {
				return rejected
			}
			out, ok := result.Output.(*s3api.GetBucketTaggingOutput)
			if !ok || out == nil {
				return &awswire.Error{Code: "InternalServiceException", Message: "S3 returned an invalid bucket tagging response.", StatusCode: 500}
			}
			for _, tag := range out.TagSet {
				if tag.Key != nil && tag.Value != nil {
					current[string(*tag.Key)] = string(*tag.Value)
				}
			}
			return nil
		})
		if err != nil {
			var rejected *awswire.Error
			if !errors.As(err, &rejected) || rejected.Code != "NoSuchTagSet" {
				return err
			}
		}
		current = resourceTaggingMerge(current, tags, keys)
		in := &s3api.PutBucketTaggingInput{Bucket: read.Bucket, ExpectedBucketOwner: read.ExpectedBucketOwner, Tagging: &s3api.Tagging{}}
		in.Tagging.TagSet = resourceTaggingPairs(current, func(key, value string) s3api.Tag {
			return s3api.Tag{Key: new(s3api.ObjectKey(key)), Value: new(s3api.Value(value))}
		})
		return r.callResourceTagging(ctx, "s3", "PutBucketTagging", in)
	})
}

func (r *ResourceTaggingResources) mutateCodeBuildResourceTags(ctx context.Context, resource resourcegroupstaggingapi.Resource, identity string, tags map[string]string, keys []string) error {
	if !strings.HasPrefix(identity, "project/") && !strings.HasPrefix(identity, "fleet/") {
		return resourceTaggingUnsupported(resource)
	}
	m := awsctx.FromContext(ctx)
	return r.Backends.CodeBuild.Update(ctx, func(tx codebuildstore.Transaction) error {
		scope := codebuildstore.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
		var currentTags codebuildapi.TagList
		if strings.HasPrefix(identity, "fleet/") {
			name, _, _ := strings.Cut(strings.TrimPrefix(identity, "fleet/"), ":")
			fleet, err := tx.Fleet(codebuildstore.FleetKey{Scope: scope, Name: name})
			if err != nil && !errors.Is(err, codebuildstore.ErrNotFound) {
				return err
			}
			currentTags = fleet.Data.Tags
		} else {
			project, err := tx.Project(codebuildstore.ProjectKey{Scope: scope, Name: strings.TrimPrefix(identity, "project/")})
			if err != nil && !errors.Is(err, codebuildstore.ErrNotFound) {
				return err
			}
			currentTags = project.Data.Tags
		}
		current := make(map[string]string, len(currentTags)+len(tags))
		for _, tag := range currentTags {
			if tag.Key != nil {
				v := ""
				if tag.Value != nil {
					v = string(*tag.Value)
				}
				current[string(*tag.Key)] = v
			}
		}
		current = resourceTaggingMerge(current, tags, keys)
		merged := resourceTaggingPairs(current, func(key, value string) codebuildapi.Tag {
			return codebuildapi.Tag{Key: new(codebuildapi.KeyInput(key)), Value: new(codebuildapi.ValueInput(value))}
		})
		if strings.HasPrefix(identity, "fleet/") {
			in := &codebuildapi.UpdateFleetInput{Arn: new(codebuildapi.NonEmptyString(resource.ARN)), Tags: merged}
			return r.callResourceTagging(tx.Context(), "codebuild", "UpdateFleet", in)
		}
		in := &codebuildapi.UpdateProjectInput{Name: new(codebuildapi.NonEmptyString(resource.ARN)), Tags: merged}
		return r.callResourceTagging(tx.Context(), "codebuild", "UpdateProject", in)
	})
}

func (r *ResourceTaggingResources) mutateStackResourceTags(ctx context.Context, resource resourcegroupstaggingapi.Resource, tags map[string]string, keys []string) error {
	return r.Backends.CloudFormation.Update(ctx, func(tx cloudformationstore.Transaction) error {
		stack, err := tx.Stack(resource.ARN)
		if err != nil && !errors.Is(err, cloudformationstore.ErrNotFound) {
			return err
		}
		in := &cloudformationapi.UpdateStackInput{StackName: new(cloudformationapi.StackName(resource.ARN)), UsePreviousTemplate: new(cloudformationapi.UsePreviousTemplate(true))}
		current := resourceTaggingMerge(stack.Tags, tags, keys)
		in.Tags = resourceTaggingPairs(current, func(key, value string) cloudformationapi.Tag {
			return cloudformationapi.Tag{Key: new(cloudformationapi.TagKey(key)), Value: new(cloudformationapi.TagValue(value))}
		})
		resourceTaggingStrings(&in.Capabilities, stack.Capabilities)
		for _, key := range slices.Sorted(maps.Keys(stack.Parameters)) {
			in.Parameters = append(in.Parameters, cloudformationapi.Parameter{ParameterKey: new(cloudformationapi.ParameterKey(key)), UsePreviousValue: new(cloudformationapi.UsePreviousValue(true))})
		}
		// UpdateStack retains its deployment admission and propagation semantics;
		// bypassing it would leave stack-owned resources with inconsistent tags.
		return r.callResourceTagging(tx.Context(), "cloudformation", "UpdateStack", in)
	})
}

func (r *ResourceTaggingResources) mutateAutoScalingResourceTags(ctx context.Context, resource resourcegroupstaggingapi.Resource, identity string, tags map[string]string, keys []string, remove bool) error {
	_, name, ok := strings.Cut(identity, ":autoScalingGroupName/")
	if !ok || name == "" || !strings.HasPrefix(identity, "autoScalingGroup:") {
		return resourceTaggingUnsupported(resource)
	}
	m := awsctx.FromContext(ctx)
	return r.Backends.AutoScaling.Update(ctx, func(tx autoscalingstore.Transaction) error {
		key := autoscalingstore.GroupKey{Scope: autoscalingstore.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, Name: name}
		group, err := tx.Group(key)
		if err != nil && !errors.Is(err, autoscalingstore.ErrNotFound) {
			return err
		}
		if err == nil && key.ARN(group.ID) != resource.ARN {
			return resourceTaggingInvalid("Auto Scaling group ARN does not identify the current group.")
		}
		if remove {
			in := &autoscalingapi.DeleteTagsInput{Tags: make(autoscalingapi.Tags, len(keys))}
			for i, key := range keys {
				in.Tags[i] = autoscalingapi.Tag{Key: new(autoscalingapi.TagKey(key)), ResourceId: new(autoscalingapi.XmlString(name)), ResourceType: new(autoscalingapi.XmlString("auto-scaling-group"))}
			}
			return r.callResourceTagging(tx.Context(), "autoscaling", "DeleteTags", in)
		}
		in := &autoscalingapi.CreateOrUpdateTagsInput{}
		in.Tags = resourceTaggingPairs(tags, func(key, value string) autoscalingapi.Tag {
			tag := autoscalingapi.Tag{Key: new(autoscalingapi.TagKey(key)), Value: new(autoscalingapi.TagValue(value)), ResourceId: new(autoscalingapi.XmlString(name)), ResourceType: new(autoscalingapi.XmlString("auto-scaling-group"))}
			for _, current := range group.Data.Tags {
				if current.Key != nil && string(*current.Key) == key {
					tag.PropagateAtLaunch = current.PropagateAtLaunch
					break
				}
			}
			return tag
		})
		return r.callResourceTagging(tx.Context(), "autoscaling", "CreateOrUpdateTags", in)
	})
}

func (r *ResourceTaggingResources) mutateIAMResourceTags(ctx context.Context, resource resourcegroupstaggingapi.Resource, identity string, tags map[string]string, keys []string, remove bool) error {
	kind, _, ok := strings.Cut(identity, "/")
	if !ok {
		return resourceTaggingUnsupported(resource)
	}
	name := identity[strings.LastIndexByte(identity, '/')+1:]
	m := awsctx.FromContext(ctx)
	return r.Backends.IAM.Update(ctx, func(tx iamstore.WriteTx) error {
		// These four native APIs address resources by name, not ARN. Pin their
		// full path identity before dropping the path; a different path is not
		// permission to mutate a same-named resource.
		scope := iamstore.Scope{Partition: m.Partition, AccountID: m.AccountID}
		var currentARN string
		var err error
		switch kind {
		case "user":
			var current iamstore.User
			current, err = tx.User(scope, name)
			currentARN = current.Arn
		case "role":
			var current iamstore.Role
			current, err = tx.Role(scope, name)
			currentARN = current.Arn
		case "instance-profile":
			var current iamstore.InstanceProfile
			current, err = tx.InstanceProfile(scope, name)
			currentARN = current.Arn
		case "server-certificate":
			var current iamstore.ServerCertificateRecord
			current, err = tx.ServerCertificate(scope, name)
			currentARN = current.ARN
		}
		if err != nil && !errors.Is(err, iamstore.ErrRecordNotFound) {
			return err
		}
		if currentARN != "" && currentARN != resource.ARN {
			return &awswire.Error{Code: "NoSuchEntity", Message: "The IAM resource ARN does not exist.", StatusCode: 404}
		}
		ctx := tx.Context()
		if remove {
			var tagKeys iamapi.TagKeyListType
			resourceTaggingStrings(&tagKeys, keys)
			switch kind {
			case "user":
				return r.callResourceTagging(ctx, "iam", "UntagUser", &iamapi.UntagUserInput{UserName: new(iamapi.ExistingUserNameType(name)), TagKeys: tagKeys})
			case "role":
				return r.callResourceTagging(ctx, "iam", "UntagRole", &iamapi.UntagRoleInput{RoleName: new(iamapi.RoleNameType(name)), TagKeys: tagKeys})
			case "instance-profile":
				return r.callResourceTagging(ctx, "iam", "UntagInstanceProfile", &iamapi.UntagInstanceProfileInput{InstanceProfileName: new(iamapi.InstanceProfileNameType(name)), TagKeys: tagKeys})
			case "server-certificate":
				return r.callResourceTagging(ctx, "iam", "UntagServerCertificate", &iamapi.UntagServerCertificateInput{ServerCertificateName: new(iamapi.ServerCertificateNameType(name)), TagKeys: tagKeys})
			case "policy":
				return r.callResourceTagging(ctx, "iam", "UntagPolicy", &iamapi.UntagPolicyInput{PolicyArn: new(iamapi.ArnType(resource.ARN)), TagKeys: tagKeys})
			case "mfa":
				return r.callResourceTagging(ctx, "iam", "UntagMFADevice", &iamapi.UntagMFADeviceInput{SerialNumber: new(iamapi.SerialNumberType(resource.ARN)), TagKeys: tagKeys})
			case "oidc-provider":
				return r.callResourceTagging(ctx, "iam", "UntagOpenIDConnectProvider", &iamapi.UntagOpenIDConnectProviderInput{OpenIDConnectProviderArn: new(iamapi.ArnType(resource.ARN)), TagKeys: tagKeys})
			case "saml-provider":
				return r.callResourceTagging(ctx, "iam", "UntagSAMLProvider", &iamapi.UntagSAMLProviderInput{SAMLProviderArn: new(iamapi.ArnType(resource.ARN)), TagKeys: tagKeys})
			default:
				return resourceTaggingUnsupported(resource)
			}
		}
		pairs := resourceTaggingPairs(tags, func(key, value string) iamapi.Tag {
			return iamapi.Tag{Key: new(iamapi.TagKeyType(key)), Value: new(iamapi.TagValueType(value))}
		})
		switch kind {
		case "user":
			return r.callResourceTagging(ctx, "iam", "TagUser", &iamapi.TagUserInput{UserName: new(iamapi.ExistingUserNameType(name)), Tags: pairs})
		case "role":
			return r.callResourceTagging(ctx, "iam", "TagRole", &iamapi.TagRoleInput{RoleName: new(iamapi.RoleNameType(name)), Tags: pairs})
		case "instance-profile":
			return r.callResourceTagging(ctx, "iam", "TagInstanceProfile", &iamapi.TagInstanceProfileInput{InstanceProfileName: new(iamapi.InstanceProfileNameType(name)), Tags: pairs})
		case "server-certificate":
			return r.callResourceTagging(ctx, "iam", "TagServerCertificate", &iamapi.TagServerCertificateInput{ServerCertificateName: new(iamapi.ServerCertificateNameType(name)), Tags: pairs})
		case "policy":
			return r.callResourceTagging(ctx, "iam", "TagPolicy", &iamapi.TagPolicyInput{PolicyArn: new(iamapi.ArnType(resource.ARN)), Tags: pairs})
		case "mfa":
			return r.callResourceTagging(ctx, "iam", "TagMFADevice", &iamapi.TagMFADeviceInput{SerialNumber: new(iamapi.SerialNumberType(resource.ARN)), Tags: pairs})
		case "oidc-provider":
			return r.callResourceTagging(ctx, "iam", "TagOpenIDConnectProvider", &iamapi.TagOpenIDConnectProviderInput{OpenIDConnectProviderArn: new(iamapi.ArnType(resource.ARN)), Tags: pairs})
		case "saml-provider":
			return r.callResourceTagging(ctx, "iam", "TagSAMLProvider", &iamapi.TagSAMLProviderInput{SAMLProviderArn: new(iamapi.ArnType(resource.ARN)), Tags: pairs})
		default:
			return resourceTaggingUnsupported(resource)
		}
	})
}

func resourceTaggingEC2Identity(kind, id string) bool {
	prefix := ""
	switch kind {
	case "launch-template":
		prefix = "lt-"
	case "elastic-ip":
		prefix = "eipalloc-"
	case "instance":
		prefix = "i-"
	case "image":
		prefix = "ami-"
	case "key-pair":
		prefix = "key-"
	case "vpc":
		prefix = "vpc-"
	case "subnet":
		prefix = "subnet-"
	case "security-group-rule":
		prefix = "sgr-"
	case "security-group":
		prefix = "sg-"
	case "route-table":
		prefix = "rtb-"
	case "internet-gateway":
		prefix = "igw-"
	case "network-interface":
		prefix = "eni-"
	case "network-acl":
		prefix = "acl-"
	case "dhcp-options":
		prefix = "dopt-"
	case "snapshot":
		prefix = "snap-"
	case "volume":
		prefix = "vol-"
	default:
		return false
	}
	return strings.HasPrefix(id, prefix) && len(id) > len(prefix) && !strings.ContainsAny(id, "/:")
}

func (r *ResourceTaggingResources) callOrganizationsResourceTagging(ctx context.Context, arn, id, operation string, input any) error {
	// Organizations exposes native ID-based mutations. Its partition state joins
	// the IAM transaction, allowing us to retain the full organization ARN identity.
	return r.Backends.IAM.Update(ctx, func(tx iamstore.WriteTx) error {
		m := awsctx.FromContext(tx.Context())
		state, _, err := r.Backends.Organizations.Load(tx.Context(), m.Partition)
		if err != nil {
			return err
		}
		for _, org := range state.Organizations {
			if org.Organization.MasterAccountID != m.AccountID {
				continue
			}
			current := ""
			if org.Root.ID == id {
				current = org.Root.ARN
			}
			if org.ResourcePolicy.ID == id {
				current = org.ResourcePolicy.ARN
			}
			for _, account := range org.Accounts {
				if account.ID == id {
					current = account.ARN
					break
				}
			}
			for _, unit := range org.Units {
				if unit.ID == id {
					current = unit.ARN
					break
				}
			}
			for _, policy := range org.Policies {
				if policy.PolicySummary.ID == id {
					current = policy.PolicySummary.ARN
					break
				}
			}
			if current != "" && current != arn {
				return &awswire.Error{Code: "TargetNotFoundException", Message: "The Organizations resource ARN does not exist.", StatusCode: 400}
			}
			break
		}
		return r.callResourceTagging(tx.Context(), "organizations", operation, input)
	})
}
