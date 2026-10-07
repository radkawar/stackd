// Package storage assembles the typed storage dependencies of an emulator.
// Backend selection happens here, independently of service behavior.
package storage

import (
	"context"
	"fmt"
	"reflect"

	"stackd/journal"
	"stackd/storage/account"
	"stackd/storage/acm"
	"stackd/storage/apigateway"
	"stackd/storage/apigatewayv2"
	"stackd/storage/appconfig"
	"stackd/storage/applicationautoscaling"
	"stackd/storage/appsync"
	"stackd/storage/athena"
	"stackd/storage/autoscaling"
	"stackd/storage/cloudcontrol"
	"stackd/storage/cloudformation"
	"stackd/storage/cloudtrail"
	"stackd/storage/cloudwatch"
	"stackd/storage/codebuild"
	"stackd/storage/codepipeline"
	"stackd/storage/cognitoidentity"
	"stackd/storage/cognitoidp"
	"stackd/storage/configservice"
	"stackd/storage/docdb"
	"stackd/storage/dynamodb"
	"stackd/storage/ebs"
	"stackd/storage/ec2"
	"stackd/storage/ecr"
	"stackd/storage/ecs"
	"stackd/storage/eks"
	"stackd/storage/elasticache"
	"stackd/storage/elbv2"
	"stackd/storage/eventbridge"
	"stackd/storage/firehose"
	"stackd/storage/glue"
	"stackd/storage/guardduty"
	"stackd/storage/iam"
	"stackd/storage/identitycenter"
	"stackd/storage/identitystore"
	"stackd/storage/kafka"
	"stackd/storage/kinesis"
	"stackd/storage/kms"
	"stackd/storage/lambda"
	"stackd/storage/logs"
	"stackd/storage/memory"
	"stackd/storage/memorydb"
	"stackd/storage/mq"
	"stackd/storage/opensearch"
	"stackd/storage/organizations"
	"stackd/storage/pipes"
	"stackd/storage/ram"
	"stackd/storage/rds"
	"stackd/storage/resourcegroups"
	"stackd/storage/resourcegroupstaggingapi"
	"stackd/storage/route53"
	"stackd/storage/s3"
	"stackd/storage/scheduler"
	"stackd/storage/secretsmanager"
	"stackd/storage/servicecatalogappregistry"
	"stackd/storage/sesv2"
	"stackd/storage/signer"
	"stackd/storage/sns"
	"stackd/storage/sqs"
	"stackd/storage/ssm"
	"stackd/storage/ssmcommands"
	"stackd/storage/ssmdocuments"
	"stackd/storage/stepfunctions"
	"stackd/storage/wafv2"
	"stackd/storage/xray"
)

// Backends supplies the transaction domains of one active Stack. IAM owns both
// IAM resources and credentials: splitting them would break atomic identity
// mutations. STS uses those same credentials and needs no separate repository.
//
// Every field is required. Use NewMemory or supply a coordinated implementation
// of the typed contracts. Decorators must preserve transaction contexts.
// The caller owns backend lifecycle; Stack.Close
// stops service workers without closing injected backends. Backends may be reused
// after that Stack closes, but must not be shared by simultaneously active stacks.
// Replacements must preserve the shared transaction boundary for related service
// calls: repositories join the context supplied by the owning callback. This
// includes credentials and provisioning journal events, account/access-role publication,
// KMS service-role creation and current IAM principal bindings in key/queue
// policies. External effects must run outside repository callbacks.
type Backends struct {
	// Read supplies a shared read snapshot for cross-service job discovery.
	// The callback must use its context and perform no writes or external effects.
	Read                      func(context.Context, func(context.Context) error) error
	Journal                   journal.Storage
	Account                   account.Repository
	ACM                       acm.Repository
	APIGateway                apigateway.Repository
	APIGatewayV2              apigatewayv2.Repository
	AppConfig                 appconfig.Repository
	ApplicationAutoScaling    applicationautoscaling.Repository
	AppSync                   appsync.Repository
	Athena                    athena.Repository
	AutoScaling               autoscaling.Repository
	CloudControl              cloudcontrol.Repository
	CloudFormation            cloudformation.Repository
	CloudTrail                cloudtrail.Repository
	CloudWatch                cloudwatch.Repository
	CodeBuild                 codebuild.Repository
	CodePipeline              codepipeline.Repository
	CognitoIDP                cognitoidp.Repository
	ConfigService             configservice.Repository
	CognitoIdentity           cognitoidentity.Repository
	IdentityCenter            identitycenter.Repository
	IdentityStore             identitystore.Repository
	DynamoDB                  dynamodb.Repository
	EBS                       ebs.Repository
	EC2                       ec2.Repository
	ECR                       ecr.Repository
	ECS                       ecs.Repository
	EKS                       eks.Repository
	ElastiCache               elasticache.Repository
	ELBv2                     elbv2.Repository
	EventBridge               eventbridge.Repository
	Firehose                  firehose.Repository
	Glue                      glue.Repository
	GuardDuty                 guardduty.Repository
	IAM                       iam.Repository
	Kafka                     kafka.Repository
	Kinesis                   kinesis.Repository
	KMS                       kms.Storage
	Lambda                    lambda.Repository
	Logs                      logs.Repository
	OpenSearch                opensearch.Repository
	MemoryDB                  memorydb.Repository
	Organizations             organizations.Storage
	RAM                       ram.Repository
	RDS                       rds.Repository
	DocumentDB                docdb.Repository
	Pipes                     pipes.Repository
	ResourceGroups            resourcegroups.Repository
	ResourceGroupsTaggingAPI  resourcegroupstaggingapi.Repository
	Route53                   route53.Repository
	S3                        s3.Repository
	Scheduler                 scheduler.Repository
	SecretsManager            secretsmanager.Repository
	ServiceCatalogAppRegistry servicecatalogappregistry.Repository
	SESv2                     sesv2.Repository
	SNS                       sns.Repository
	SQS                       sqs.Repository
	SSM                       ssm.Repository
	SSMCommands               ssmcommands.Repository
	SSMDocuments              ssmdocuments.Repository
	StepFunctions             stepfunctions.Repository
	WAFv2                     wafv2.Repository
	XRay                      xray.Repository
	MQ                        mq.Repository
	Signer                    signer.Repository
}

// NewMemory constructs isolated typed repositories in one transaction domain.
// Related calls use the same staged state and commit or roll back together.
func NewMemory() *Backends {
	domain := memory.NewDomain()
	return &Backends{
		Read:                      domain.View,
		Journal:                   journal.NewMemory(domain),
		Account:                   account.NewMemory(domain),
		ACM:                       acm.NewMemory(domain),
		APIGateway:                apigateway.NewMemory(domain),
		APIGatewayV2:              apigatewayv2.NewMemory(domain),
		AppConfig:                 appconfig.NewMemory(domain),
		ApplicationAutoScaling:    applicationautoscaling.NewMemory(domain),
		AppSync:                   appsync.NewMemory(domain),
		Athena:                    athena.NewMemory(domain),
		AutoScaling:               autoscaling.NewMemory(domain),
		CloudControl:              cloudcontrol.NewMemory(domain),
		CloudFormation:            cloudformation.NewMemory(domain),
		CloudTrail:                cloudtrail.NewMemory(domain),
		CloudWatch:                cloudwatch.NewMemory(domain),
		CodeBuild:                 codebuild.NewMemory(domain),
		CodePipeline:              codepipeline.NewMemory(domain),
		CognitoIDP:                cognitoidp.NewMemory(domain),
		ConfigService:             configservice.NewMemory(domain),
		CognitoIdentity:           cognitoidentity.NewMemory(domain),
		IdentityCenter:            identitycenter.NewMemory(domain),
		IdentityStore:             identitystore.NewMemory(domain),
		DynamoDB:                  dynamodb.NewMemory(domain),
		EBS:                       ebs.NewMemory(domain),
		EC2:                       ec2.NewMemory(domain),
		ECR:                       ecr.NewMemory(domain),
		ECS:                       ecs.NewMemory(domain),
		EKS:                       eks.NewMemory(domain),
		ElastiCache:               elasticache.NewMemory(domain),
		ELBv2:                     elbv2.NewMemory(domain),
		EventBridge:               eventbridge.NewMemory(domain),
		Firehose:                  firehose.NewMemory(domain),
		Glue:                      glue.NewMemory(domain),
		GuardDuty:                 guardduty.NewMemory(domain),
		IAM:                       iam.NewMemory(domain),
		Kafka:                     kafka.NewMemory(domain),
		Kinesis:                   kinesis.NewMemory(domain),
		KMS:                       kms.NewMemory(domain),
		Lambda:                    lambda.NewMemory(domain),
		Logs:                      logs.NewMemory(domain),
		OpenSearch:                opensearch.NewMemory(domain),
		MemoryDB:                  memorydb.NewMemory(domain),
		Organizations:             organizations.NewMemory(domain),
		RAM:                       ram.NewMemory(domain),
		RDS:                       rds.NewMemory(domain),
		DocumentDB:                docdb.NewMemory(domain),
		Pipes:                     pipes.NewMemory(domain),
		ResourceGroups:            resourcegroups.NewMemory(domain),
		ResourceGroupsTaggingAPI:  resourcegroupstaggingapi.NewMemory(domain),
		Route53:                   route53.NewMemory(domain),
		S3:                        s3.NewMemory(domain),
		Scheduler:                 scheduler.NewMemory(domain),
		SecretsManager:            secretsmanager.NewMemory(domain),
		ServiceCatalogAppRegistry: servicecatalogappregistry.NewMemory(domain),
		SESv2:                     sesv2.NewMemory(domain),
		SNS:                       sns.NewMemory(domain),
		SQS:                       sqs.NewMemory(domain),
		SSM:                       ssm.NewMemory(domain),
		SSMCommands:               ssmcommands.NewMemory(domain),
		SSMDocuments:              ssmdocuments.NewMemory(domain),
		StepFunctions:             stepfunctions.NewMemory(domain),
		WAFv2:                     wafv2.NewMemory(domain),
		XRay:                      xray.NewMemory(domain),
		MQ:                        mq.NewMemory(domain),
		Signer:                    signer.NewMemory(domain),
	}
}

// Validate rejects incomplete bundles before any service or worker is started.
func (b *Backends) Validate() error {
	if b == nil {
		return fmt.Errorf("storage backends are required")
	}
	for _, field := range []struct {
		name  string
		value any
	}{
		{"Read", b.Read},
		{"Journal", b.Journal}, {"Account", b.Account}, {"EventBridge", b.EventBridge}, {"IAM", b.IAM}, {"KMS", b.KMS}, {"Organizations", b.Organizations}, {"SQS", b.SQS},
		{"APIGateway", b.APIGateway}, {"APIGatewayV2", b.APIGatewayV2},
		{"ACM", b.ACM}, {"Route53", b.Route53},
		{"AppSync", b.AppSync},
		{"Lambda", b.Lambda},
		{"Logs", b.Logs},
		{"CloudWatch", b.CloudWatch},
		{"CloudControl", b.CloudControl},
		{"CloudFormation", b.CloudFormation},
		{"CodeBuild", b.CodeBuild},
		{"CodePipeline", b.CodePipeline},
		{"CognitoIDP", b.CognitoIDP},
		{"ConfigService", b.ConfigService},
		{"CognitoIdentity", b.CognitoIdentity},
		{"IdentityCenter", b.IdentityCenter},
		{"IdentityStore", b.IdentityStore},
		{"ApplicationAutoScaling", b.ApplicationAutoScaling},
		{"Athena", b.Athena},
		{"AutoScaling", b.AutoScaling},
		{"DynamoDB", b.DynamoDB},
		{"EBS", b.EBS},
		{"EKS", b.EKS},
		{"Kafka", b.Kafka},
		{"Kinesis", b.Kinesis},
		{"Firehose", b.Firehose},
		{"Glue", b.Glue},
		{"EC2", b.EC2},
		{"ECR", b.ECR},
		{"ECS", b.ECS},
		{"ELBv2", b.ELBv2},
		{"OpenSearch", b.OpenSearch},
		{"ElastiCache", b.ElastiCache},
		{"MemoryDB", b.MemoryDB},
		{"MQ", b.MQ},
		{"GuardDuty", b.GuardDuty},
		{"Signer", b.Signer},
		{"RDS", b.RDS},
		{"DocumentDB", b.DocumentDB},
		{"RAM", b.RAM},
		{"S3", b.S3}, {"CloudTrail", b.CloudTrail},
		{"SecretsManager", b.SecretsManager},
		{"ServiceCatalogAppRegistry", b.ServiceCatalogAppRegistry},
		{"SNS", b.SNS},
		{"SSM", b.SSM},
		{"SSMCommands", b.SSMCommands},
		{"SSMDocuments", b.SSMDocuments},
		{"Scheduler", b.Scheduler},
		{"Pipes", b.Pipes},
		{"StepFunctions", b.StepFunctions},
		{"WAFv2", b.WAFv2},
		{"XRay", b.XRay},
	} {
		if nilBackend(field.value) {
			return fmt.Errorf("%s storage backend is required", field.name)
		}
	}
	return nil
}

func nilBackend(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
