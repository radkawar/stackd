// Package backends assembles typed repositories sharing one SQLite transaction domain.
package backends

import (
	"context"
	"database/sql"
	"fmt"

	"stackd/storage"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/account"
	"stackd/storage/sqlite/acm"
	"stackd/storage/sqlite/apigateway"
	"stackd/storage/sqlite/apigatewayv2"
	"stackd/storage/sqlite/appconfig"
	"stackd/storage/sqlite/applicationautoscaling"
	"stackd/storage/sqlite/appsync"
	"stackd/storage/sqlite/athena"
	"stackd/storage/sqlite/autoscaling"
	"stackd/storage/sqlite/cloudcontrol"
	"stackd/storage/sqlite/cloudformation"
	"stackd/storage/sqlite/cloudtrail"
	"stackd/storage/sqlite/cloudwatch"
	"stackd/storage/sqlite/codebuild"
	"stackd/storage/sqlite/codepipeline"
	"stackd/storage/sqlite/cognitoidentity"
	"stackd/storage/sqlite/cognitoidp"
	"stackd/storage/sqlite/configservice"
	"stackd/storage/sqlite/docdb"
	"stackd/storage/sqlite/dynamodb"
	"stackd/storage/sqlite/ebs"
	"stackd/storage/sqlite/ec2"
	"stackd/storage/sqlite/ecr"
	"stackd/storage/sqlite/ecs"
	"stackd/storage/sqlite/eks"
	"stackd/storage/sqlite/elasticache"
	"stackd/storage/sqlite/elbv2"
	"stackd/storage/sqlite/eventbridge"
	"stackd/storage/sqlite/firehose"
	"stackd/storage/sqlite/glue"
	"stackd/storage/sqlite/guardduty"
	"stackd/storage/sqlite/iam"
	"stackd/storage/sqlite/identitycenter"
	"stackd/storage/sqlite/identitystore"
	"stackd/storage/sqlite/journal"
	"stackd/storage/sqlite/kafka"
	"stackd/storage/sqlite/kinesis"
	"stackd/storage/sqlite/kms"
	"stackd/storage/sqlite/lambda"
	"stackd/storage/sqlite/logs"
	"stackd/storage/sqlite/memorydb"
	"stackd/storage/sqlite/mq"
	"stackd/storage/sqlite/opensearch"
	"stackd/storage/sqlite/organizations"
	"stackd/storage/sqlite/pipes"
	"stackd/storage/sqlite/ram"
	"stackd/storage/sqlite/rds"
	"stackd/storage/sqlite/resourcegroups"
	"stackd/storage/sqlite/resourcegroupstaggingapi"
	"stackd/storage/sqlite/route53"
	"stackd/storage/sqlite/s3"
	"stackd/storage/sqlite/scheduler"
	"stackd/storage/sqlite/secretsmanager"
	"stackd/storage/sqlite/servicecatalogappregistry"
	"stackd/storage/sqlite/sesv2"
	"stackd/storage/sqlite/signer"
	"stackd/storage/sqlite/sns"
	"stackd/storage/sqlite/sqs"
	"stackd/storage/sqlite/ssm"
	"stackd/storage/sqlite/ssmcommands"
	"stackd/storage/sqlite/ssmdocuments"
	"stackd/storage/sqlite/stepfunctions"
	"stackd/storage/sqlite/wafv2"
	"stackd/storage/sqlite/xray"
)

// New binds every service and the journal to db. The caller owns its lifecycle;
// closing a Stack does not close the database or the retained service clock.
func New(ctx context.Context, db *sql.DB) (*storage.Backends, error) {
	workflows, err := stepfunctions.New(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("prepare workflow storage: %w", err)
	}
	return &storage.Backends{
		Read: func(ctx context.Context, fn func(context.Context) error) error {
			return sqlite.Transact(ctx, db, true, func(ctx context.Context, _ *sql.Tx) error {
				return fn(ctx)
			})
		},
		Account:                   account.New(db),
		ACM:                       acm.New(db),
		APIGateway:                apigateway.New(db),
		APIGatewayV2:              apigatewayv2.New(db),
		ApplicationAutoScaling:    applicationautoscaling.New(db),
		AppConfig:                 appconfig.New(db),
		AppSync:                   appsync.New(db),
		Athena:                    athena.New(db),
		AutoScaling:               autoscaling.New(db),
		CloudControl:              cloudcontrol.New(db),
		CloudFormation:            cloudformation.New(db),
		CloudTrail:                cloudtrail.New(db),
		CloudWatch:                cloudwatch.New(db),
		CodeBuild:                 codebuild.New(db),
		CodePipeline:              codepipeline.New(db),
		CognitoIDP:                cognitoidp.New(db),
		ConfigService:             configservice.New(db),
		CognitoIdentity:           cognitoidentity.New(db),
		IdentityCenter:            identitycenter.New(db),
		IdentityStore:             identitystore.New(db),
		DynamoDB:                  dynamodb.New(db),
		EBS:                       ebs.New(db),
		EC2:                       ec2.New(db),
		ECR:                       ecr.New(db),
		ECS:                       ecs.New(db),
		EKS:                       eks.New(db),
		ElastiCache:               elasticache.New(db),
		ELBv2:                     elbv2.New(db),
		EventBridge:               eventbridge.New(db),
		Firehose:                  firehose.New(db),
		Glue:                      glue.New(db),
		GuardDuty:                 guardduty.New(db),
		IAM:                       iam.New(db),
		Journal:                   journal.New(db),
		Kafka:                     kafka.New(db),
		Kinesis:                   kinesis.New(db),
		KMS:                       kms.New(db),
		Lambda:                    lambda.New(db),
		Logs:                      logs.New(db),
		OpenSearch:                opensearch.New(db),
		MemoryDB:                  memorydb.New(db),
		Organizations:             organizations.New(db),
		RAM:                       ram.New(db),
		RDS:                       rds.New(db),
		DocumentDB:                docdb.New(db),
		Pipes:                     pipes.New(db),
		ResourceGroups:            resourcegroups.New(db),
		ResourceGroupsTaggingAPI:  resourcegroupstaggingapi.New(db),
		Route53:                   route53.New(db),
		S3:                        s3.New(db),
		Scheduler:                 scheduler.New(db),
		SecretsManager:            secretsmanager.New(db),
		ServiceCatalogAppRegistry: servicecatalogappregistry.New(db),
		SESv2:                     sesv2.New(db),
		SNS:                       sns.New(db),
		SQS:                       sqs.New(db),
		SSM:                       ssm.New(db),
		SSMCommands:               ssmcommands.New(db),
		SSMDocuments:              ssmdocuments.New(db),
		StepFunctions:             workflows,
		WAFv2:                     wafv2.New(db),
		XRay:                      xray.New(db),
		MQ:                        mq.New(db),
		Signer:                    signer.New(db),
	}, nil
}
