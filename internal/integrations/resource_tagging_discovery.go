package integrations

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"stackd/internal/awsctx"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/storage"
)

// ResourceTaggingResources reads current service-owned tag stores and invokes
// ordinary service commands for mutations. Sources extend inventory for owners
// whose repository is not part of the shared storage bundle.
type ResourceTaggingResources struct {
	Backends *storage.Backends
	Commands StepFunctionsCommands
	Sources  map[string]tagging.Source
}

// List deliberately includes untagged resources. The tagging owner applies its
// previously-tagged membership and AWS read exclusions to this current snapshot.
// Inventory never borrows native list permissions; mutations reauthorize natively.
func (r ResourceTaggingResources) List(ctx context.Context, service string) ([]tagging.Resource, error) {
	if r.Backends == nil || r.Backends.Read == nil {
		return nil, fmt.Errorf("resource tagging requires coordinated storage backends")
	}
	m := awsctx.FromContext(ctx)
	scope := tagging.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
	var resources []tagging.Resource
	err := r.Backends.Read(ctx, func(ctx context.Context) error {
		appendService := func(service string) error {
			rows, err := r.listTaggingService(ctx, scope, service)
			if err != nil {
				return fmt.Errorf("listing %s tagging resources: %w", service, err)
			}
			resources = append(resources, rows...)
			return nil
		}
		if service != "" {
			if err := appendService(service); err != nil {
				return err
			}
		} else {
			for _, name := range []string{
				"ec2", "s3", "sqs", "sns", "lambda", "events", "logs", "kms", "ssm", "secretsmanager", "states", "cognito-idp", "ecs", "eks", "elasticloadbalancing", "autoscaling", "application-autoscaling", "dynamodb", "kinesis", "firehose", "monitoring", "cloudtrail", "xray", "ecr", "codebuild", "glue", "athena", "rds", "scheduler", "pipes", "elasticache", "memorydb", "es", "kafka", "apigateway", "cloudformation", "iam", "organizations",
			} {
				if err := appendService(name); err != nil {
					return err
				}
			}
		}
		for name, source := range r.Sources {
			if service != "" && service != name {
				continue
			}
			rows, err := source.ListTaggingResources(ctx)
			if err != nil {
				return fmt.Errorf("listing %s tagging resources: %w", name, err)
			}
			resources = append(resources, rows...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(resources, func(a, b tagging.Resource) int { return strings.Compare(a.ARN, b.ARN) })
	return resources, nil
}

func (r ResourceTaggingResources) listTaggingService(ctx context.Context, scope tagging.Scope, service string) ([]tagging.Resource, error) {
	switch service {
	case "ec2", "ebs":
		return r.listTaggingEC2(ctx, scope)
	case "s3", "s3control":
		return r.listTaggingS3(ctx, scope)
	case "sqs":
		return r.listTaggingSQS(ctx, scope)
	case "sns":
		return r.listTaggingSNS(ctx, scope)
	case "lambda":
		return r.listTaggingLambda(ctx, scope)
	case "events":
		return r.listTaggingEvents(ctx, scope)
	case "logs":
		return r.listTaggingLogs(ctx, scope)
	case "kms":
		return r.listTaggingKMS(ctx, scope)
	case "ssm":
		return r.listTaggingSSM(ctx, scope)
	case "secretsmanager":
		return r.listTaggingSecrets(ctx, scope)
	case "states":
		return r.listTaggingStates(ctx, scope)
	case "cognito-idp":
		return r.listTaggingCognito(ctx, scope)
	case "ecs":
		return r.listTaggingECS(ctx, scope)
	case "eks":
		return r.listTaggingEKS(ctx, scope)
	case "elasticloadbalancing":
		return r.listTaggingELB(ctx, scope)
	case "autoscaling":
		return r.listTaggingAutoScaling(ctx, scope)
	case "application-autoscaling":
		return r.listTaggingApplicationAutoScaling(ctx, scope)
	case "dynamodb":
		return r.listTaggingDynamoDB(ctx, scope)
	case "kinesis":
		return r.listTaggingKinesis(ctx, scope)
	case "firehose":
		return r.listTaggingFirehose(ctx, scope)
	case "monitoring":
		return r.listTaggingCloudWatch(ctx, scope)
	case "cloudtrail":
		return r.listTaggingCloudTrail(ctx, scope)
	case "xray":
		return r.listTaggingXRay(ctx, scope)
	case "ecr":
		return r.listTaggingECR(ctx, scope)
	case "codebuild":
		return r.listTaggingCodeBuild(ctx, scope)
	case "glue":
		return r.listTaggingGlue(ctx, scope)
	case "athena":
		return r.listTaggingAthena(ctx, scope)
	case "rds":
		return r.listTaggingRDS(ctx, scope)
	case "scheduler":
		return r.listTaggingScheduler(ctx, scope)
	case "pipes":
		return r.listTaggingPipes(ctx, scope)
	case "elasticache":
		return r.listTaggingElastiCache(ctx, scope)
	case "memorydb":
		return r.listTaggingMemoryDB(ctx, scope)
	case "es":
		return r.listTaggingOpenSearch(ctx, scope)
	case "kafka":
		return r.listTaggingKafka(ctx, scope)
	case "apigateway":
		return r.listTaggingAPIGateway(ctx, scope)
	case "cloudformation":
		return r.listTaggingCloudFormation(ctx, scope)
	case "iam":
		return r.listTaggingIAM(ctx, scope)
	case "organizations":
		return r.listTaggingOrganizations(ctx, scope)
	default:
		return nil, nil
	}
}

func resourceTaggingARN(scope tagging.Scope, service, resource string) string {
	return "arn:" + scope.Partition + ":" + service + ":" + scope.Region + ":" + scope.AccountID + ":" + resource
}

func resourceTaggingText[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func resourceTaggingSnapshotMap[K, V ~string](tags map[K]V) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for key, value := range tags {
		out[string(key)] = string(value)
	}
	return out
}
