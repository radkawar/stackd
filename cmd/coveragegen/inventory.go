package main

// Inventory describes a target, not a conformance result. A registered operation
// is only partial, even when every target operation of its service is registered.
type Inventory struct {
	Source               Source       `json:"source"`
	Target               string       `json:"target"`
	Interpretation       string       `json:"interpretation"`
	Evidence             []string     `json:"evidence"`
	Totals               Totals       `json:"totals"`
	Services             []Service    `json:"services"`
	AdditionalRegistered []Registered `json:"additional_registered"`
}

type Source struct {
	Repository string       `json:"repository"`
	Path       string       `json:"path"`
	Revision   string       `json:"revision"`
	Selection  string       `json:"selection"`
	Totals     SourceTotals `json:"totals"`
}

type SourceTotals struct {
	Services   int `json:"services"`
	Operations int `json:"operations"`
}

type Totals struct {
	TargetOperations     int `json:"target_operations"`
	Partial              int `json:"partial"`
	Unimplemented        int `json:"unimplemented"`
	AdditionalRegistered int `json:"additional_registered"`
}

type Service struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Model      string      `json:"model"`
	Revision   string      `json:"revision,omitempty"`
	Evidence   []string    `json:"evidence,omitempty"`
	Operations []Operation `json:"operations"`
}

type Operation struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Registered struct {
	Service    string           `json:"service"`
	Operations []ExtraOperation `json:"operations"`
}

type ExtraOperation struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Keep evidence in the existing semantic audits, rather than copying their
// conclusions into operation-registration status.
var evidence = map[string][]string{
	"account":                   {"docs/account-contacts.md", "docs/account-information.md", "docs/account-primary-email.md", "docs/account-regions.md"},
	"acm":                       {"docs/acm.md"},
	"apigateway":                {"docs/behavior-references.md"},
	"apigatewaymanagementapi":   {"docs/behavior-references.md", "testdata/aws/apigateway/websocket_management.json"},
	"apigatewayv2":              {"docs/behavior-references.md"},
	"appconfig":                 {"docs/appconfig.md"},
	"appconfigdata":             {"docs/appconfig.md"},
	"applicationautoscaling":    {"docs/ecs.md"},
	"appsync":                   {"docs/appsync.md"},
	"athena":                    {"docs/behavior-references.md"},
	"autoscaling":               {"docs/ec2.md"},
	"cloudcontrol":              {"docs/behavior-references.md"},
	"cloudformation":            {"docs/behavior-references.md"},
	"cloudtrail":                {"docs/cloudtrail.md", "docs/event-journal.md"},
	"cloudwatch":                {"docs/cloudwatch.md"},
	"codebuild":                 {"docs/behavior-references.md", "integration/codebuild_folder_test.go", "integration/codebuild_git_secondaries_test.go", "integration/codebuild_source_admission_test.go", "testdata/integration/codebuild_folder_executable.json", "testdata/integration/codebuild_folder_directory_executable.json", "testdata/integration/codebuild_git_secondary_executable.json", "testdata/integration/codebuild_secondary_directory_executable.json", "testdata/integration/codebuild_source_admission.json", "testdata/aws/codebuild/stackd-cb-git-secondary-4c4fb322e510.json", "testdata/aws/codebuild/stackd-cb-source-51143e720af345e9.json", "testdata/aws/codebuild/stackd-cb-source-104ba4096e17466c.json"},
	"codepipeline":              {"docs/codepipeline.md"},
	"cognitoidentity":           {"docs/cognito-identity.md"},
	"cognitoidp":                {"docs/cognito.md"},
	"configservice":             {"docs/config.md"},
	"docdb":                     {"docs/documentdb.md"},
	"dynamodb":                  {"docs/behavior-references.md"},
	"dynamodbstreams":           {"docs/behavior-references.md"},
	"ebs":                       {"docs/ec2.md"},
	"ec2":                       {"docs/ec2.md"},
	"ecr":                       {"docs/behavior-references.md"},
	"ecs":                       {"docs/ecs.md"},
	"eks":                       {"docs/eks.md"},
	"eksauth":                   {"docs/eks.md"},
	"elasticache":               {"docs/behavior-references.md"},
	"elbv2":                     {"docs/behavior-references.md", "docs/ecs.md"},
	"es":                        {"docs/behavior-references.md"},
	"eventbridge":               {"docs/eventbridge.md"},
	"firehose":                  {"docs/firehose.md"},
	"glue":                      {"docs/behavior-references.md"},
	"guardduty":                 {"docs/guardduty.md"},
	"iam":                       {"docs/iam-completion.md"},
	"identitystore":             {"docs/identity-store.md"},
	"kafka":                     {"docs/behavior-references.md"},
	"kinesis":                   {"docs/behavior-references.md"},
	"kms":                       {"docs/kms-cryptography.md", "docs/kms-grants.md", "docs/kms-imports.md", "docs/kms-multi-region.md"},
	"lambda":                    {"docs/lambda.md", "integration/lambda_async_recreation_test.go", "storage/sqlite/lambda_async_detached_migration_test.go", "testdata/aws/lambda/async_deleted_targets_analysis.json", "testdata/aws/lambda/async_recreation_order_analysis.json", "testdata/integration/lambda_async_deleted_targets_20261001.json", "testdata/integration/lambda_async_alias_preserved_20261001.json"},
	"logs":                      {"docs/logs.md"},
	"memorydb":                  {"docs/behavior-references.md"},
	"mq":                        {"docs/mq.md"},
	"opensearch":                {"docs/behavior-references.md"},
	"organizations":             {"docs/organizations-account-access.md", "docs/organizations-api.md", "docs/organizations-delegation.md", "docs/organizations-effective-policies.md", "docs/organizations-features.md", "docs/organizations-invitations.md"},
	"pipes":                     {"docs/pipes.md"},
	"ram":                       {"docs/behavior-references.md"},
	"rds":                       {"docs/rds.md"},
	"rdsdata":                   {"docs/rds.md"},
	"resourcegroups":            {"docs/resourcegroups.md", "integration/ssm_resource_groups_test.go", "testdata/integration/ssm_resource_groups_guest.json"},
	"route53":                   {"docs/route53.md"},
	"resourcegroupstaggingapi":  {"docs/behavior-references.md"},
	"s3":                        {"docs/cloudtrail.md"},
	"s3control":                 {"docs/cloudtrail.md"},
	"servicecatalogappregistry": {"docs/resourcegroups.md"},
	"scheduler":                 {"docs/scheduler.md"},
	"secretsmanager":            {"docs/secretsmanager.md"},
	"ses":                       {"docs/cognito.md"},
	"sesv2":                     {"docs/cognito.md"},
	"signer":                    {"docs/lambda.md"},
	"sns":                       {"docs/sns.md"},
	"sqs":                       {"docs/sqs-delivery.md"},
	"ssm":                       {"docs/ssm.md", "integration/ssm_notifications_test.go", "integration/ssm_resource_groups_test.go", "integration/ssm_alarms_test.go", "testdata/aws/ssm/notifications_native_20261001.json", "testdata/aws/ssm/stackd-ssm-rg-3347d1af0988.json", "testdata/aws/ssm/stackd-ssm-rg-boundary-7f5ed62afe.json", "testdata/aws/ssm/alarms_native_20261001.json", "testdata/aws/ssm/alarms_native_lifecycle_20261001.json", "testdata/integration/ssm_resource_groups_guest.json", "testdata/integration/ssm_alarms_guest_20261001_final.json"},
	"ssmmessages":               {"docs/ssm.md"},
	"sso":                       {"docs/identity-center.md"},
	"ssoadmin":                  {"docs/identity-center.md"},
	"ssooidc":                   {"docs/identity-center.md"},
	"stepfunctions":             {"docs/stepfunctions.md"},
	"sts":                       {"docs/iam-completion.md", "docs/oidc-federation.md", "docs/saml-federation.md", "docs/sqlite-state.md"},
	"xray":                      {"integration/xray_native_test.go", "testdata/aws/xray/trace_queries.json", "testdata/aws/xray/sampling.json", "integration/xray_time_series_test.go", "testdata/aws/xray/time_series_settled.json", "testdata/integration/xray_time_series.json"},
}
