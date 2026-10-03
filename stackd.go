// Package stackd assembles an embeddable local AWS emulator.
package stackd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"stackd/clock"
	codebuildruntime "stackd/compute/codebuild"
	dnsruntime "stackd/compute/dns"
	ec2runtime "stackd/compute/ec2"
	ecsruntime "stackd/compute/ecs"
	eksruntime "stackd/compute/eks"
	elbv2runtime "stackd/compute/elbv2"
	glueruntime "stackd/compute/glue"
	lambdaruntime "stackd/compute/lambda"
	athenaruntime "stackd/engine/athena"
	docdbruntime "stackd/engine/docdb"
	dynamoruntime "stackd/engine/dynamodb"
	kinesisruntime "stackd/engine/kinesis"
	rdsruntime "stackd/engine/rds"
	valkeyruntime "stackd/engine/valkey"
	"stackd/extension"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	accountapi "stackd/internal/awsapi/account"
	acmapi "stackd/internal/awsapi/acm"
	apigatewayapi "stackd/internal/awsapi/apigateway"
	apigatewaymanagementapi "stackd/internal/awsapi/apigatewaymanagementapi"
	apigatewayv2api "stackd/internal/awsapi/apigatewayv2"
	appconfigapi "stackd/internal/awsapi/appconfig"
	appconfigdataapi "stackd/internal/awsapi/appconfigdata"
	applicationautoscalingapi "stackd/internal/awsapi/applicationautoscaling"
	appsyncapi "stackd/internal/awsapi/appsync"
	athenaapi "stackd/internal/awsapi/athena"
	autoscalingapi "stackd/internal/awsapi/autoscaling"
	cloudcontrolapi "stackd/internal/awsapi/cloudcontrol"
	cloudformationapi "stackd/internal/awsapi/cloudformation"
	cloudtrailapi "stackd/internal/awsapi/cloudtrail"
	cloudwatchapi "stackd/internal/awsapi/cloudwatch"
	codebuildapi "stackd/internal/awsapi/codebuild"
	codepipelineapi "stackd/internal/awsapi/codepipeline"
	cognitoidentityapi "stackd/internal/awsapi/cognitoidentity"
	cognitoidpapi "stackd/internal/awsapi/cognitoidp"
	configserviceapi "stackd/internal/awsapi/configservice"
	docdbapi "stackd/internal/awsapi/docdb"
	dynamodbapi "stackd/internal/awsapi/dynamodb"
	dynamodbstreamsapi "stackd/internal/awsapi/dynamodbstreams"
	ebsapi "stackd/internal/awsapi/ebs"
	ec2api "stackd/internal/awsapi/ec2"
	ecrapi "stackd/internal/awsapi/ecr"
	ecsapi "stackd/internal/awsapi/ecs"
	eksapi "stackd/internal/awsapi/eks"
	eksauthapi "stackd/internal/awsapi/eksauth"
	elasticacheapi "stackd/internal/awsapi/elasticache"
	elbv2api "stackd/internal/awsapi/elbv2"
	esapi "stackd/internal/awsapi/es"
	eventbridgeapi "stackd/internal/awsapi/eventbridge"
	firehoseapi "stackd/internal/awsapi/firehose"
	glueapi "stackd/internal/awsapi/glue"
	guarddutyapi "stackd/internal/awsapi/guardduty"
	iamapi "stackd/internal/awsapi/iam"
	identitystoreapi "stackd/internal/awsapi/identitystore"
	kafkaapi "stackd/internal/awsapi/kafka"
	kinesisapi "stackd/internal/awsapi/kinesis"
	kmsapi "stackd/internal/awsapi/kms"
	lambdaapi "stackd/internal/awsapi/lambda"
	logsapi "stackd/internal/awsapi/logs"
	memorydbapi "stackd/internal/awsapi/memorydb"
	mqapi "stackd/internal/awsapi/mq"
	opensearchapi "stackd/internal/awsapi/opensearch"
	organizationsapi "stackd/internal/awsapi/organizations"
	pipesapi "stackd/internal/awsapi/pipes"
	ramapi "stackd/internal/awsapi/ram"
	rdsapi "stackd/internal/awsapi/rds"
	rdsdataapi "stackd/internal/awsapi/rdsdata"
	resourcegroupsapi "stackd/internal/awsapi/resourcegroups"
	resourcegroupstaggingapiapi "stackd/internal/awsapi/resourcegroupstaggingapi"
	route53api "stackd/internal/awsapi/route53"
	s3api "stackd/internal/awsapi/s3"
	s3controlapi "stackd/internal/awsapi/s3control"
	schedulerapi "stackd/internal/awsapi/scheduler"
	secretsmanagerapi "stackd/internal/awsapi/secretsmanager"
	servicecatalogappregistryapi "stackd/internal/awsapi/servicecatalogappregistry"
	sesapi "stackd/internal/awsapi/ses"
	sesv2api "stackd/internal/awsapi/sesv2"
	signerapi "stackd/internal/awsapi/signer"
	snsapi "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	ssmapi "stackd/internal/awsapi/ssm"
	ssoapi "stackd/internal/awsapi/sso"
	ssoadminapi "stackd/internal/awsapi/ssoadmin"
	ssooidcapi "stackd/internal/awsapi/ssooidc"
	stepfunctionsapi "stackd/internal/awsapi/stepfunctions"
	stsapi "stackd/internal/awsapi/sts"
	xrayapi "stackd/internal/awsapi/xray"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/iam/catalog"
	"stackd/internal/identity"
	"stackd/internal/integrations"
	"stackd/internal/scheduler"
	"stackd/internal/services/account"
	"stackd/internal/services/acm"
	"stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/apigatewaywebsocket"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/applicationautoscaling"
	"stackd/internal/services/appsync"
	"stackd/internal/services/athena"
	"stackd/internal/services/autoscaling"
	"stackd/internal/services/cloudcontrol"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/cloudwatch"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/codepipeline"
	"stackd/internal/services/cognitoidentity"
	"stackd/internal/services/cognitoidp"
	"stackd/internal/services/configservice"
	"stackd/internal/services/docdb"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	"stackd/internal/services/ecr"
	"stackd/internal/services/ecs"
	"stackd/internal/services/eks"
	"stackd/internal/services/elasticache"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/firehose"
	"stackd/internal/services/glue"
	"stackd/internal/services/guardduty"
	"stackd/internal/services/iam"
	"stackd/internal/services/identitycenter"
	"stackd/internal/services/identitystore"
	"stackd/internal/services/kafka"
	"stackd/internal/services/kinesis"
	"stackd/internal/services/kms"
	"stackd/internal/services/lambda"
	"stackd/internal/services/logs"
	"stackd/internal/services/memorydb"
	"stackd/internal/services/mq"
	"stackd/internal/services/opensearch"
	"stackd/internal/services/organizations"
	"stackd/internal/services/pipes"
	"stackd/internal/services/ram"
	"stackd/internal/services/rds"
	"stackd/internal/services/rdsdata"
	"stackd/internal/services/resourcegroups"
	"stackd/internal/services/resourcegroupstaggingapi"
	"stackd/internal/services/route53"
	"stackd/internal/services/s3"
	schedulerservice "stackd/internal/services/scheduler"
	"stackd/internal/services/secretsmanager"
	"stackd/internal/services/servicecatalogappregistry"
	"stackd/internal/services/sesv2"
	"stackd/internal/services/signer"
	"stackd/internal/services/sns"
	"stackd/internal/services/sqs"
	"stackd/internal/services/ssm"
	"stackd/internal/services/ssmcommands"
	"stackd/internal/services/ssmdocuments"
	"stackd/internal/services/ssmfrontend"
	"stackd/internal/services/ssmmessages"
	"stackd/internal/services/stepfunctions"
	"stackd/internal/services/sts"
	"stackd/internal/services/xray"
	"stackd/journal"
	"stackd/storage"
)

// Config configures an emulator instance. Defaults create isolated state; callers
// may inject typed storage implementations through Storage.
type Config struct {
	AccountID    string
	MaxBodyBytes int64
	Extensions   []extension.Service
	// Storage selects every service backend. Nil constructs isolated memory
	// storage; a supplied bundle must be complete and remains caller-owned.
	Storage *storage.Backends
	// Clock drives modeled service time and timers. Nil uses real time. Manual
	// clocks advance service lifecycles without changing SDK signature skew or
	// real network/context deadlines. The caller owns the injected clock.
	Clock clock.Clock
	// EmailSender delivers verification messages outside storage transactions.
	// Nil rejects requests that need delivery; it never drops mail as success.
	EmailSender EmailSender
	// SESEmailDirectory captures accepted SES/Cognito mail as private RFC 5322
	// files. Empty leaves local delivery unconfigured; mail is never discarded.
	SESEmailDirectory string
	// SSOUserPoolClientID selects the existing Cognito password-auth client used
	// by the local Identity Center browser. Empty rejects browser sign-in.
	SSOUserPoolClientID string
	// OrganizationAccountQuotas sets applied account-count quotas by management
	// account and partition. Unspecified scopes use AWS's default of ten. Values
	// apply to both new requests and pending jobs recovered from Storage.
	OrganizationAccountQuotas []OrganizationAccountQuota
	// OIDCDiscovery supplies explicitly configured issuer discovery. Nil keeps
	// federation-provider administration independent of outbound networking.
	OIDCDiscovery OIDCDiscovery
	// OAuthTokens explicitly configures verification of opaque Amazon/Facebook tokens.
	OAuthTokens OAuthTokenSource
	// UnsignedRegion selects the endpoint region of unsigned STS and S3 requests.
	// Empty uses us-east-1. Signed requests use their verified SigV4 region.
	UnsignedRegion string
	// PublicEndpoint is the trusted HTTP(S) origin serving this Stack. Outbound
	// identity federation, SNS delivery and Lambda code retrieval require this
	// fetchable origin. Keep it stable when reusing Storage. Empty leaves those
	// features unconfigured; other AWS APIs remain available.
	PublicEndpoint string
	// OutboundHTTP supplies instance-owned transport for Connection OAuth and
	// HTTP Tasks. Nil uses the standard client; each caller owns its deadline.
	OutboundHTTP *http.Client
	// LambdaExecutor is the instance-owned real container runtime boundary. Nil
	// keeps control-plane embedding independent of Docker; execution is rejected.
	// Stack closes environments it creates, but never closes the injected executor.
	LambdaExecutor lambdaruntime.Executor
	// LambdaSourceNetworks owns real poller sockets in EC2 network namespaces.
	LambdaSourceNetworks  *lambdaruntime.SourceNetworkRuntime
	LambdaManagedCapacity LambdaManagedCapacityConfig
	// ECSExecutor owns real task containers. Close detaches running tasks so a
	// retained store can reconnect; StopTask owns native resource destruction.
	ECSExecutor ecsruntime.Executor
	// CodeBuildExecutor owns real build containers; closing the Stack detaches
	// retained executions so a replacement controller can observe their result.
	CodeBuildExecutor codebuildruntime.Executor
	// CodeBuildFleetImage is the installed image used for native idle capacity.
	CodeBuildFleetImage string
	// EC2Executor owns real guest processes, separate from the API/state kernel.
	// EBSDisks owns native mutable disk bytes after hydration; Close preserves
	// them for restart. EBSVolumeDirectory is the native disk storage root.
	EC2Executor        ec2runtime.Executor
	EBSDisks           ebs.NativeDisks
	EBSVolumeDirectory string
	// DynamoDBRuntime owns native item storage and expression execution.
	// Close detaches handles; table deletion owns engine/volume retirement.
	DynamoDBRuntime dynamoruntime.Runtime
	// KinesisRuntime owns durable native shard logs. Close detaches handles;
	// stream deletion removes the owned broker and its data volume.
	KinesisRuntime kinesisruntime.Runtime
	// MSKRuntime owns public native Kafka clusters independently of private
	// Kinesis logs. Controller shutdown detaches; cluster deletion removes data.
	MSKRuntime kafka.Runtime
	// MQRuntime owns native RabbitMQ/ActiveMQ broker data and protocol consumers.
	MQRuntime mq.Runtime
	// RDSRuntime owns native PostgreSQL/MySQL processes and durable backups.
	// It remains caller-owned; Stack.Close detaches the controller, not the data.
	RDSRuntime rdsruntime.Runtime
	// DocumentDBRuntime owns a native TLS/SCRAM document compatibility engine.
	DocumentDBRuntime docdbruntime.Runtime
	// OpenSearchRuntime owns private native engines. Public traffic goes through
	// the gateway and current domain/IAM authority. Close detaches durable data.
	OpenSearchRuntime opensearch.Runtime
	// ValkeyRuntime is shared by ElastiCache and MemoryDB. It remains caller-owned;
	// controller shutdown detaches without stopping retained native engines.
	ValkeyRuntime valkeyruntime.Runtime
	// EKSRuntime owns real Kubernetes clusters and their authenticated API proxy.
	// The caller owns runtime lifecycle; cluster deletion retires native resources.
	EKSRuntime eksruntime.Runtime
	// EKSNodeImages maps Kubernetes minor versions to operator-imported worker
	// images. Custom launch-template images do not require this mapping.
	EKSNodeImages map[string]eksruntime.NodeImage
	// ELBV2Runtime supplies real ALB node sockets. Its Docker/network dependencies
	// must outlive the Stack; service shutdown detaches, while deletion removes nodes.
	ELBV2Runtime elbv2runtime.Runtime
	// DNSListenAddress binds the owned authoritative UDP/TCP DNS endpoint.
	// Empty uses loopback with an ephemeral port when ELBV2Runtime is configured.
	DNSListenAddress string
	// ECRScanner supplies explicitly configured offline vulnerability analysis.
	// Nil leaves scan execution unavailable; no clean-image findings are invented.
	ECRScanner ecr.Scanner
	// GlueRuntime executes real ETL job processes. Nil keeps catalog controls
	// available but rejects execution; supplied runtimes remain caller-owned.
	GlueRuntime glueruntime.Runtime
	// AthenaRuntime runs native SQL against the built-in Glue and S3 owners.
	// Nil rejects query execution instead of manufacturing results.
	AthenaRuntime athenaruntime.Runtime
	// InventoryORC encodes S3 ORC reports outside storage transactions.
	// Nil leaves CSV/Parquet generation independent of container execution.
	InventoryORC InventoryORCEncoder
	// ComputeEndpoint is this Stack's HTTP(S) origin reachable from its containers.
	ComputeEndpoint string
	// LambdaKeepAlive controls warm reuse using service time. Zero forces cold calls.
	LambdaKeepAlive time.Duration
}

// New creates the built-in service providers and the shared AWS HTTP endpoint.
func New(config Config) (stack *Stack, err error) {
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	if _, err := catalog.Load(); err != nil {
		return nil, fmt.Errorf("load IAM authorization catalogue: %w", err)
	}
	if config.AccountID != "" && (len(config.AccountID) != 12 || strings.Trim(config.AccountID, "0123456789") != "") {
		return nil, fmt.Errorf("account ID must have 12 digits")
	}
	if config.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("maximum body size must be positive")
	}
	if config.LambdaKeepAlive < 0 {
		return nil, fmt.Errorf("lambda keep-alive must not be negative")
	}
	if (config.LambdaExecutor != nil || config.ECSExecutor != nil || config.CodeBuildExecutor != nil) && config.ComputeEndpoint == "" {
		return nil, fmt.Errorf("compute endpoint is required with a container executor")
	}
	if config.PublicEndpoint != "" {
		origin, err := url.Parse(config.PublicEndpoint)
		if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
			return nil, fmt.Errorf("public endpoint must be an absolute HTTP(S) origin without credentials, path, query or fragment")
		}
		origin.Path, origin.RawPath = "", ""
		config.PublicEndpoint = origin.String()
	}
	issuerCertificate, _ := config.EKSRuntime.(integrations.EKSServiceAccountIssuerCertificate)
	oidcDiscovery, err := integrations.NewEKSServiceAccountIssuers(issuerCertificate, config.OIDCDiscovery, config.Clock)
	if err != nil {
		return nil, err
	}
	organizationQuotas, err := organizations.NewAccountQuotas(config.OrganizationAccountQuotas)
	if err != nil {
		return nil, err
	}
	backends := config.Storage
	if backends == nil {
		backends = storage.NewMemory()
	}
	if err := backends.Validate(); err != nil {
		return nil, err
	}
	var dnsServer *dnsruntime.Server
	var dnsAuthority elbv2.DNSAuthority
	var certificateDNS acm.DNSResolver
	if config.DNSListenAddress != "" || config.ELBV2Runtime != nil {
		address := config.DNSListenAddress
		if address == "" {
			address = "127.0.0.1:0"
		}
		dnsServer, err = dnsruntime.Listen(address)
		if err != nil {
			return nil, fmt.Errorf("listen for service DNS: %w", err)
		}
		dnsAuthority = dnsServer
		defer func() {
			if stack == nil {
				err = errors.Join(err, dnsServer.Close())
			}
		}()
		target, parseErr := netip.ParseAddrPort(dnsServer.Address())
		if parseErr != nil {
			return nil, fmt.Errorf("parse bound DNS endpoint: %w", parseErr)
		}
		if target.Addr().IsUnspecified() {
			target = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), target.Port())
		}
		certificateDNS, err = dnsruntime.NewClient(target.String())
		if err != nil {
			return nil, fmt.Errorf("configure certificate DNS resolver: %w", err)
		}
	}
	registry := &gateway.Registry{}
	observationJobs := scheduler.New(config.Clock)
	servicePublisher := &eventbridge.ServicePublisher{Repository: backends.EventBridge, Events: backends.Journal, Clock: config.Clock}
	detectionEvents := &integrations.GuardDutyEvents{Journal: backends.Journal, Trails: backends.CloudTrail, Buckets: backends.S3}
	trailEvents := &cloudtrail.APIEvents{Repository: backends.CloudTrail, Journal: detectionEvents, Clock: config.Clock, Jobs: observationJobs, Publisher: servicePublisher}
	taggingResources := &integrations.ResourceTaggingResources{Backends: backends, Sources: map[string]resourcegroupstaggingapi.Source{}}
	apiEvents := resourcegroupstaggingapi.NewRecorder(apievents.New(trailEvents), backends.ResourceGroupsTaggingAPI, taggingResources)
	// TODO: Comeback extend committed service/API events and EventBridge delivery to remaining transitions and consumers; add retention, consumer checkpoints and consistent snapshot/fork/restore with worker fencing.
	// TODO: Comeback extend joined service draining to remaining service-time work, durable attempts and seeded resource IDs; keep transport deadlines and external runtime execution at explicit real-time boundaries.
	iamRepository := backends.IAM
	credentials := identity.NewWithConfig(identity.Config{AccountID: config.AccountID, Repository: iam.NewCredentialRepository(iamRepository, backends.Journal), Clock: config.Clock})
	organizationEvents := &cloudtrail.OrganizationEvents{OrganizationEventLog: backends.Journal, Repository: backends.CloudTrail}
	organizationsService := organizations.NewWithConfig(organizations.Config{Storage: backends.Organizations, Events: organizationEvents, APIEvents: apiEvents, Clock: config.Clock, AccountQuotas: organizationQuotas})
	iamService := iam.NewWithConfig(iam.Config{CredentialEvents: backends.Journal, APICallEvents: apiEvents, Credentials: credentials, Repository: iamRepository, Clock: config.Clock, SimulationControls: organizationControls{organizationsService}, OrganizationReports: organizationsService, RootAccess: organizationsService, PublicEndpoint: config.PublicEndpoint})
	organizationsService.SetRoleInspector(iamService)
	iamService.SetAccountIdentitySource(organizationsService)
	if err := iamService.RegisterServiceLinkedRole(organizationRoleTemplate(), organizationRoleUsage{organizationsService, iamRepository}); err != nil {
		_ = iamService.Close()
		return nil, fmt.Errorf("register Organizations service-linked role: %w", err)
	}
	authorizer := authorization.NewWithClock(iamService, organizationControls{organizationsService}, config.Clock)
	iamService.SetAuthorizer(authorizer)
	organizationsService.SetAuthorizer(authorizer)
	accountService := account.New(account.Config{Repository: backends.Account, Authorizer: authorizer, Organizations: organizationsService, CreationTimes: iamService, EmailSender: config.EmailSender, APIEvents: apiEvents, Clock: config.Clock})
	organizationsService.SetAccountProvisioner(organizationAccounts{identity: iamService, accounts: accountService})
	trailOrganizations := integrations.CloudTrailOrganizations{Storage: backends.Organizations, Regions: accountService, Clock: config.Clock}
	trailRoles := integrations.CloudTrailOrganizationRoles{Organizations: backends.Organizations, IdentityRepository: iamRepository, Trails: backends.CloudTrail, IAM: iamService}
	trailEvents.Organizations, trailEvents.OrganizationRoles = trailOrganizations, trailRoles
	organizationEvents.Organizations, organizationEvents.Roles = trailOrganizations, trailRoles
	kmsService := kms.NewWithConfig(kms.Config{Storage: backends.KMS, Authorizer: authorizer, APIEvents: apiEvents, Clock: config.Clock, Regions: accountService, Roles: iamService})
	if err := iamService.RegisterServiceLinkedRole(kmsRoleTemplate(), kmsRoleUsage{kmsService}); err != nil {
		_ = iamService.Close()
		return nil, fmt.Errorf("register KMS service-linked role: %w", err)
	}
	federation := iamFederation{service: iamService, credentials: credentials, discovery: config.OIDCDiscovery}
	stsService := sts.NewWithDependencies(sts.Dependencies{Credentials: credentials, APIEvents: apiEvents, Roles: iamRoles{iamService}, RootSessions: organizationsService, OutboundWebIdentity: iamService, TokenPreferences: iamService, Regions: accountService, Identity: iamService, Organizations: organizationsService, Authorizer: authorizer, MFA: iamService, Federation: federation, Sessions: iamSessions{iamService, credentials, organizationsService}, OIDCProviders: federation, SAMLProviders: federation, OAuthTokens: config.OAuthTokens, Clock: config.Clock})
	serviceRoles := integrations.ServiceRoles{IAM: iamService, Credentials: credentials, Authorizer: authorizer, STS: stsService}
	configResources := integrations.ConfigResources{Backends: backends}
	configEffects := &integrations.ConfigEffects{Roles: serviceRoles, Resources: configResources}
	configService := configservice.New(configservice.Config{Repository: backends.ConfigService, Resources: configResources, Effects: configEffects, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock})
	taggingResources.Sources["config"] = configService
	apiEvents = configservice.NewRecorder(apiEvents, configService)
	alarmActions := &integrations.CloudWatchAlarmActions{}
	cloudwatchService := cloudwatch.New(cloudwatch.Config{Repository: backends.CloudWatch, Authorizer: authorizer, APIEvents: apiEvents, Clock: config.Clock, Events: integrations.CloudWatchEvents{Publisher: servicePublisher}, Actions: alarmActions})
	servicePublisher.Metrics = cloudwatchService
	sqsService := sqs.NewWithConfig(sqs.Config{Repository: backends.SQS, KMS: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "sqs"}, Authorizer: authorizer, Clock: config.Clock, Journal: backends.Journal, APIEvents: apiEvents, Metrics: cloudwatchService})
	logSubscriptions := &integrations.LogsSubscriptions{}
	logsService := logs.New(logs.Config{Repository: backends.Logs, Authorizer: authorizer, APIEvents: apiEvents, Clock: config.Clock, Subscriptions: logSubscriptions, Events: backends.Journal, Metrics: cloudwatchService})
	s3Notifications := &integrations.S3Notifications{SQS: sqsService}
	s3Service := s3.New(s3.Config{Repository: backends.S3, Authorizer: authorizer, AccountPolicies: organizationsService, APIEvents: apiEvents, Clock: config.Clock, Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "s3"}, Notifications: s3Notifications, ObjectEvents: integrations.S3Events{Publisher: servicePublisher}, ReplicationRoles: &integrations.S3ReplicationRoles{Roles: serviceRoles}, Metrics: cloudwatchService, InventoryORC: config.InventoryORC})
	scalingResources := &integrations.ApplicationScaling{CloudWatch: cloudwatchService, Roles: serviceRoles}
	kinesisService := kinesis.New(kinesis.Config{Repository: backends.Kinesis, Runtime: config.KinesisRuntime, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, Keys: integrations.KinesisKeys{KMS: kmsService, Activity: iamService}, Metrics: cloudwatchService})
	firehoseDestination := &integrations.FirehoseS3{Roles: serviceRoles, S3: s3Service, Logs: logsService, Clock: config.Clock}
	firehoseProcessor := &integrations.FirehoseLambda{Roles: serviceRoles}
	firehoseService := firehose.New(firehose.Config{Repository: backends.Firehose, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Destination: firehoseDestination, Source: &integrations.FirehoseKinesis{Roles: serviceRoles, Streams: kinesisService}, Diagnostics: firehoseDestination, Metrics: cloudwatchService, Processor: firehoseProcessor})
	logSubscriptions.Firehose = firehoseService
	logSubscriptions.Roles, logSubscriptions.Kinesis = serviceRoles, kinesisService
	dynamoService := dynamodb.New(dynamodb.Config{Repository: backends.DynamoDB, Runtime: config.DynamoDBRuntime, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, CapacityState: scalingResources, ReplicaScaling: scalingResources, Metrics: cloudwatchService, Regions: accountService, Roles: iamService, ReplicationIdentity: &integrations.DynamoDBReplication{Roles: serviceRoles}, Kinesis: kinesisService, KinesisIdentity: &integrations.DynamoDBKinesis{Roles: serviceRoles}})
	dynamoStreams := dynamoService.Streams()
	scalingResources.DynamoDB = dynamoService
	lambdaOutcomes := &integrations.LambdaOutcomes{Roles: serviceRoles, SQS: sqsService}
	lambdaKafka := &integrations.LambdaKafka{Roles: serviceRoles}
	lambdaNetworks := &integrations.LambdaSourceNetworks{Roles: serviceRoles}
	if config.LambdaSourceNetworks != nil {
		lambdaNetworks.Runtime = config.LambdaSourceNetworks
	}
	lambdaKafka.Networks = lambdaNetworks
	lambdaMQ := &integrations.LambdaMQ{Roles: serviceRoles, Authorizer: authorizer}
	lambdaDocuments := &integrations.LambdaDocumentDB{Roles: serviceRoles}
	lambdaMQ.Native, _ = config.MQRuntime.(integrations.LambdaMQNative)
	lambdaCapacity := &integrations.LambdaCapacity{Roles: serviceRoles, LinkedRoles: iamService, Config: config.LambdaManagedCapacity}
	signerService := signer.New(signer.Config{Repository: backends.Signer, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Objects: integrations.SignerS3Objects{S3: s3Service}})
	lambdaService := lambda.New(lambda.Config{
		Repository: backends.Lambda, FilterEncryption: integrations.LambdaFilterEncryption{KMS: kmsService, Activity: iamService},
		Executor: config.LambdaExecutor, CodeSource: integrations.LambdaS3Code{S3: s3Service}, Roles: integrations.LambdaRoles{ServiceRoles: serviceRoles},
		SQS:      integrations.LambdaSQS{Roles: serviceRoles, Queues: sqsService},
		DynamoDB: integrations.LambdaDynamoDB{Roles: serviceRoles, Streams: dynamoStreams},
		Kinesis:  integrations.LambdaKinesis{Roles: serviceRoles, Streams: kinesisService},
		Kafka:    lambdaKafka, MQ: lambdaMQ, DocumentDB: lambdaDocuments, SourceNetworks: lambdaNetworks,
		CodeSigningAuthority: integrations.LambdaSignerAuthority{Signer: signerService},
		Capacity:             lambdaCapacity,
		DurableEncryption:    integrations.LambdaDurableEncryption{KMS: kmsService, Activity: iamService},
		StreamTargets:        lambdaOutcomes, Logs: integrations.LambdaLogs{Logs: logsService, Credentials: credentials, Clock: config.Clock},
		Targets: lambdaOutcomes, Metrics: cloudwatchService, Authorizer: authorizer, Clock: config.Clock,
		Endpoint: config.ComputeEndpoint, PublicEndpoint: config.PublicEndpoint, KeepAlive: config.LambdaKeepAlive,
		Events: backends.Journal, APIEvents: apiEvents,
	})
	secretsManagerService := secretsmanager.New(secretsmanager.Config{Repository: backends.SecretsManager, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, Regions: accountService, Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "secretsmanager"}, Rotation: integrations.SecretRotation{Lambda: lambdaService}})
	lambdaDocuments.Secrets = secretsManagerService
	parameterImages := &integrations.SSMImages{}
	parameterService := ssm.New(ssm.Config{Repository: backends.SSM, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "ssm"}, Events: integrations.SSMEvents{Publisher: servicePublisher}, Images: parameterImages, Secrets: integrations.SSMSecrets{Secrets: secretsManagerService}})
	ssmDocuments := ssmdocuments.New(ssmdocuments.Config{Repository: backends.SSMDocuments, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, PublicSharing: parameterService})
	ssmNotifications := &integrations.SSMNotifications{Roles: serviceRoles}
	ssmResourceGroups := &integrations.SSMResourceGroups{}
	ssmAlarms := &integrations.SSMAlarms{CloudWatch: cloudwatchService, Roles: serviceRoles, Provisioner: iamService}
	ssmCommands := ssmcommands.New(ssmcommands.Config{Repository: backends.SSMCommands, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Documents: ssmDocuments, Instances: integrations.SSMInstances{EC2: backends.EC2}, Credentials: credentials, Notifications: ssmNotifications, ResourceGroups: ssmResourceGroups, Alarms: ssmAlarms})
	lambdaCapacity.SSM = ssmCommands
	ssmService := ssmfrontend.New(parameterService, ssmDocuments, ssmCommands)
	sesService := sesv2.NewWithConfig(sesv2.Config{Repository: backends.SESv2, Authorizer: authorizer, APIEvents: apiEvents, Clock: config.Clock, CaptureDirectory: config.SESEmailDirectory, PublicEndpoint: config.PublicEndpoint})
	taggingResources.Sources["ses"] = sesService
	taggingService := resourcegroupstaggingapi.New(resourcegroupstaggingapi.Config{Repository: backends.ResourceGroupsTaggingAPI, Resources: taggingResources, Policies: integrations.ResourceTaggingPolicies{Organizations: backends.Organizations}, Governance: integrations.ResourceTaggingGovernance{Organizations: backends.Organizations, Account: accountService, Clock: config.Clock}, Reports: integrations.ResourceTaggingReports{S3: s3Service}, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock})
	appResources := integrations.AppRegistryResources{Backends: backends, Tagging: taggingResources}
	resourceGroupsRoles := integrations.ResourceGroupsRoles{Roles: serviceRoles, IAM: iamService, Repository: backends.ResourceGroups}
	resourceGroupsService := resourcegroups.New(resourcegroups.Config{Repository: backends.ResourceGroups, Resources: integrations.ResourceGroupsResources{Tagging: *taggingResources}, ApplicationResources: appResources, Roles: resourceGroupsRoles, Publisher: servicePublisher, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock})
	ssmResourceGroups.ResourceGroups = resourceGroupsService
	taggingResources.Sources["resource-groups"] = resourceGroupsService
	appRegistryService := servicecatalogappregistry.New(servicecatalogappregistry.Config{Repository: backends.ServiceCatalogAppRegistry, Groups: resourceGroupsService, Resources: appResources, Roles: &integrations.AppRegistryRoles{Roles: serviceRoles, Provisioner: iamService}, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock})
	taggingResources.Sources["servicecatalog"] = appRegistryService
	cognitoEmail := &integrations.CognitoEmail{SES: sesService, Roles: serviceRoles, Provisioner: iamService}
	cognitoService := cognitoidp.New(cognitoidp.Config{Repository: backends.CognitoIDP, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, PublicEndpoint: config.PublicEndpoint, EmailSender: cognitoEmail, EmailSetup: cognitoEmail})
	identityStoreService := identitystore.NewWithConfig(identitystore.Config{Repository: backends.IdentityStore, Authorizer: authorizer, APIEvents: apiEvents, Clock: config.Clock})
	identityCenterService := identitycenter.New(identitycenter.Config{Repository: backends.IdentityCenter, Directory: identityStoreService, Login: integrations.SSOCognitoLogin{Cognito: cognitoService, ClientID: config.SSOUserPoolClientID}, Roles: integrations.IdentityCenterRoles{IAM: iamService, Sessions: serviceRoles}, Accounts: integrations.IdentityCenterAccounts{Storage: backends.Organizations}, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, PublicEndpoint: config.PublicEndpoint})
	identityPoolService := cognitoidentity.New(cognitoidentity.Config{Repository: backends.CognitoIdentity, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Tokens: integrations.CognitoIdentityTokens{Cognito: cognitoService}, Credentials: integrations.CognitoIdentityCredentials{STS: stsService}})
	ecrService := ecr.New(ecr.Config{Repository: backends.ECR, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, PublicEndpoint: config.PublicEndpoint, Keys: integrations.ECRKeys{KMS: kmsService, Activity: iamService}, Scanner: config.ECRScanner, ReplicationRoles: &integrations.ECRReplication{Roles: serviceRoles, Provisioner: iamService}, Events: integrations.ECREvents{Publisher: servicePublisher}})
	pipelineArtifacts := integrations.CodePipelineArtifacts{Repository: backends.CodePipeline}
	buildService := codebuild.New(codebuild.Config{PipelineArtifacts: pipelineArtifacts, Repository: backends.CodeBuild, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Executor: config.CodeBuildExecutor, Roles: integrations.CodeBuildRoles{ServiceRoles: serviceRoles}, Objects: integrations.CodeBuildObjects{S3: s3Service}, SourceBuckets: integrations.CodeBuildSourceBuckets{Repository: backends.S3}, Secrets: integrations.CodeBuildSecrets{Secrets: secretsManagerService}, Parameters: integrations.CodeBuildParameters{Parameters: parameterService}, Cipher: integrations.CodeBuildCredentialCipher{Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "codebuild"}}, Logs: integrations.CodeBuildLogs{Logs: logsService}, Registry: integrations.CodeBuildRegistry{ECR: ecrService, Endpoint: config.PublicEndpoint}, Events: integrations.CodeBuildEvents{Publisher: servicePublisher}, Endpoint: config.ComputeEndpoint, FleetImage: config.CodeBuildFleetImage})
	gatewayLogs := &integrations.GatewayLogs{Logs: logsService, Roles: serviceRoles}
	apiGatewayService := apigateway.New(apigateway.Config{Repository: backends.APIGateway, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, Endpoint: config.PublicEndpoint, Metrics: cloudwatchService, Logs: gatewayLogs})
	gatewayLogs.Accounts = apiGatewayService
	apiGatewayV2Service := apigatewayv2.New(apigatewayv2.Config{Repository: backends.APIGatewayV2, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, Endpoint: config.PublicEndpoint, Logs: gatewayLogs})
	gatewayInvocationRoles := integrations.GatewayInvocationRoles{Roles: serviceRoles, Clock: config.Clock}
	apiGatewayWebSocketService := apigatewaywebsocket.New(apigatewaywebsocket.Config{Resolver: apiGatewayV2Service, Functions: lambdaService, Roles: gatewayInvocationRoles, Authorization: authorizer, Clock: config.Clock, Metrics: apiGatewayService, Logs: gatewayLogs})
	firehoseProcessor.Functions = lambdaService
	logSubscriptions.Lambda = lambdaService
	alarmActions.Lambda = lambdaService
	snsFirehose := &integrations.SNSFirehose{Roles: serviceRoles, Firehose: firehoseService}
	snsService := sns.New(sns.Config{Repository: backends.SNS, Authorizer: authorizer, PolicyBinder: authorizer, APIEvents: apiEvents, Clock: config.Clock, Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "sns"}, Roles: integrations.SNSRoles{Roles: serviceRoles}, Delivery: integrations.SNSSubscriptions{SQS: sqsService, Lambda: lambdaService, HTTP: &integrations.SNSHTTP{}, Firehose: snsFirehose}, Metrics: cloudwatchService, Feedback: &integrations.SNSFeedback{Logs: logsService, Roles: serviceRoles, Clock: config.Clock}, PublicEndpoint: config.PublicEndpoint})
	ssmNotifications.SNS = snsService
	s3Notifications.SNS, s3Notifications.Lambda = snsService, lambdaService
	configEffects.S3, configEffects.SNS, configEffects.Functions = s3Service, snsService, lambdaService
	diskKeys := integrations.EC2DiskKeys{KMS: kmsService, Activity: iamService, Infrastructure: iamService}
	ebsService := ebs.New(ebs.Config{Repository: backends.EBS, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Keys: integrations.EBSSnapshotKeys{KMS: kmsService, Activity: iamService}, EC2Keys: diskKeys, InstanceKeys: diskKeys, Policies: organizationsService, Images: &integrations.EBSImages{Repository: backends.EC2}, Attachments: integrations.EBSInstances{Repository: backends.EC2}, NativeDisks: config.EBSDisks, NativeVolumeDirectory: config.EBSVolumeDirectory, Events: integrations.EBSEvents{Publisher: servicePublisher}})
	ec2Metrics := &integrations.EC2Metrics{Publisher: cloudwatchService}
	ec2Service := ec2.New(ec2.Config{Repository: backends.EC2, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Regions: accountService, Snapshots: ebsService, Volumes: ebsService, ImageSnapshots: ebsService, InstanceRuntime: config.EC2Executor, InstanceVolumes: ebsService, InstanceImages: ebsService, InstanceProfiles: &integrations.EC2InstanceProfiles{IAM: iamService, Roles: serviceRoles}, InstanceIdentities: &integrations.EC2InstanceIdentityCredentials{IAM: iamService, Credentials: credentials}, InstanceEvents: integrations.EC2Events{Publisher: servicePublisher}, InstanceMetrics: ec2Metrics})
	parameterImages.EC2 = ec2Service
	lambdaNetworks.EC2 = ec2Service
	lambdaCapacity.EC2 = ec2Service
	ramOrganizations := integrations.RAMOrganizations{Storage: backends.Organizations, IdentityRepository: iamRepository, Organizations: organizationsService, IAM: iamService}
	// TODO: Comeback connect remaining RAM resource families through their service owners.
	ramService := ram.New(ram.Config{
		Repository: backends.RAM, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock,
		Resources:    integrations.RAMResources{SSM: parameterService, EC2: ec2Service, CodeBuild: buildService},
		Organization: ramOrganizations, ResourceTypes: []string{"ssm:Parameter", "ec2:Subnet", "codebuild:Project"},
	})
	parameterService.SetSharing(integrations.RAMParameters{RAM: ramService})
	buildService.SetResourceShares(integrations.CodeBuildResourceShares{RAM: ramService})
	ec2Service.SetSharedSubnets(integrations.RAMSharedSubnets{RAM: ramService})
	var endpoint *gateway.Gateway
	certificateUsage := &integrations.ELBV2CertificateUsage{}
	acmService := acm.New(acm.Config{Repository: backends.ACM, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, DNS: certificateDNS, Usage: certificateUsage})
	acmJobs := scheduler.New(config.Clock, acmService.JobSource())
	acmService.SetWake(acmJobs.Wake)
	var route53Service *route53.Service
	elbv2Service := elbv2.New(elbv2.Config{
		Repository: backends.ELBv2, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.ELBV2Runtime,
		DNS:          dnsAuthority,
		Networks:     &integrations.ELBV2Networks{EC2: ec2Service, Roles: iamService, Sessions: serviceRoles},
		Certificates: integrations.ELBV2Certificates{IAM: iamService, ACM: acmService}, Metrics: cloudwatchService,
	})
	certificateUsage.ELBV2 = elbv2Service
	iamService.SetServerCertificateUsage(certificateUsage)
	ecsService := ecs.New(ecs.Config{Repository: backends.ECS, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Roles: iamService, Executor: config.ECSExecutor, TaskRoles: integrations.ECSTaskRoles{ServiceRoles: serviceRoles}, Networks: &integrations.ECSTaskNetworks{EC2: ec2Service, Roles: serviceRoles}, LoadBalancers: &integrations.ECSLoadBalancers{ELBv2: elbv2Service, EC2: ec2Service, Roles: serviceRoles}, Logs: integrations.ECSLogs{Logs: logsService, Clock: config.Clock}, Parameters: integrations.ECSParameters{Parameters: parameterService, Secrets: secretsManagerService}, EnvironmentFiles: integrations.ECSEnvironmentFiles{S3: s3Service}, Events: integrations.ECSEvents{Publisher: servicePublisher}, Metrics: cloudwatchService, ServiceState: scalingResources, Endpoint: config.ComputeEndpoint})
	scalingResources.ECS = ecsService
	scalingService := applicationautoscaling.New(applicationautoscaling.Config{Repository: backends.ApplicationAutoScaling, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Roles: iamService, Resources: scalingResources, Identity: scalingResources, Alarms: scalingResources})
	scalingResources.Scaling = scalingService
	alarmActions.Scaling = scalingResources
	autoScalingInstances := &integrations.AutoScaling{EC2: ec2Service, Roles: serviceRoles}
	autoScalingService := autoscaling.New(autoscaling.Config{
		Repository: backends.AutoScaling, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock,
		Roles: iamService, Instances: autoScalingInstances, Identity: autoScalingInstances,
		TargetGroups: integrations.AutoScalingTargetGroups{ELBv2: elbv2Service},
		Events:       integrations.AutoScalingEvents{Publisher: servicePublisher, SNS: snsService, SQS: sqsService, Roles: serviceRoles, Clock: config.Clock},
		Alarms:       scalingResources, Metrics: cloudwatchService,
		TerminationSelector: integrations.AutoScalingTermination{Functions: lambdaService},
	})
	ec2Metrics.Groups = autoScalingService
	alarmActions.AutoScaling = autoScalingService
	guarddutyService := guardduty.New(guardduty.Config{
		Repository: backends.GuardDuty, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Roles: iamService,
		AuditJournal:           backends.Journal,
		Findings:               integrations.GuardDutyFindings{Publisher: servicePublisher},
		IPLists:                integrations.GuardDutyIPLists{IAM: iamService, Roles: serviceRoles, S3: s3Service, Authorizer: authorizer},
		PublishingDestinations: integrations.GuardDutyDestinations{S3: s3Service},
	})
	detectionEvents.Detector = guarddutyService
	eksService := eks.New(eks.Config{
		Repository: backends.EKS, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.EKSRuntime,
		Authenticator: func(r *http.Request, _ string, region string) (*http.Request, *awswire.Error) {
			return endpoint.AuthenticateEKS(r, region)
		},
		Networks:            integrations.EKSNetworks{Roles: serviceRoles, EC2: ec2Service},
		Principals:          integrations.EKSPrincipals{IAM: iamService},
		NodeNames:           integrations.EKSNodeNames{EC2: backends.EC2},
		Nodegroups:          &integrations.EKSNodes{EC2: ec2Service, AutoScaling: autoScalingService, IAM: iamService, Roles: serviceRoles, Images: config.EKSNodeImages},
		WorkloadRoles:       integrations.EKSWorkloadRoles{Roles: serviceRoles, EC2: backends.EC2, ECR: ecrService, RegistryEndpoint: config.PublicEndpoint},
		Logs:                integrations.EKSLogs{Roles: serviceRoles, Logs: logsService},
		Audit:               guarddutyService,
		ServiceLinkedRoles:  iamService,
		PodIdentityRoles:    integrations.EKSPodIdentityRoles{Roles: serviceRoles, STS: stsService},
		PodIdentityEndpoint: config.ComputeEndpoint,
	})
	oidcDiscovery.EKS = eksService
	iamService.SetOIDCDiscovery(oidcDiscovery)
	alarmActions.SNS = snsService
	eventTargets := &integrations.EventBridgeTargets{SQS: sqsService, SNS: snsService, Lambda: lambdaService, Logs: logsService, ECS: ecsService, Kinesis: kinesisService, Firehose: firehoseService, Roles: serviceRoles}
	eventbridgeService := eventbridge.NewWithConfig(eventbridge.Config{Repository: backends.EventBridge, Authorizer: authorizer, Accounts: iamService, Clock: config.Clock, Delivery: eventTargets, Roles: eventTargets, Keys: integrations.EventBridgeArchiveKeys{KMS: kmsService, Activity: iamService}, BusKeys: integrations.EventBridgeBusKeys{KMS: kmsService, Activity: iamService}, ConnectionSecrets: &integrations.EventBridgeSecrets{Secrets: secretsManagerService, Roles: serviceRoles, Provisioner: iamService}, HTTPClient: config.OutboundHTTP, Metrics: cloudwatchService, Events: backends.Journal, APIEvents: apiEvents})
	eventTargets.Events = eventbridgeService
	appconfigEffects := &integrations.AppConfigEffects{PipelineArtifacts: pipelineArtifacts, Roles: serviceRoles, Parameters: parameterService, Documents: ssmDocuments, Objects: s3Service, Secrets: secretsManagerService, Functions: lambdaService, Alarms: cloudwatchService, Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "appconfig"}, SNS: snsService, SQS: sqsService, Events: servicePublisher, Clock: config.Clock}
	appconfigService := appconfig.New(appconfig.Config{Repository: backends.AppConfig, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Effects: appconfigEffects, StrategyDocuments: appconfigEffects})
	taggingResources.Sources["appconfig"] = appconfigService
	pipelineActions := &integrations.CodePipelineActions{Roles: serviceRoles, S3: s3Service, CodeBuild: buildService, AppConfig: appconfigService, STS: stsService, SNS: snsService, Lambda: lambdaService}
	pipelineService := codepipeline.New(codepipeline.Config{Repository: backends.CodePipeline, Executor: pipelineActions, Sources: pipelineActions, Roles: integrations.CodePipelineRoles{ServiceRoles: serviceRoles}, Events: integrations.CodePipelineEvents{Publisher: servicePublisher, Clock: config.Clock}, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock})
	eventTargets.CodePipeline = pipelineService
	eventTargets.APIDestinations = eventbridgeService
	lambdaOutcomes.Lambda, lambdaOutcomes.SNS, lambdaOutcomes.Events, lambdaOutcomes.S3 = lambdaService, snsService, eventbridgeService, s3Service
	glueEvents := integrations.GlueEvents{Publisher: servicePublisher, Clock: config.Clock}
	glueService := glue.New(glue.Config{
		Repository: backends.Glue, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock,
		JobRuntime: config.GlueRuntime, JobDependencies: &integrations.GlueJobs{Roles: serviceRoles, S3: s3Service, Logs: logsService, Metrics: cloudwatchService, Clock: config.Clock},
		CrawlerSource: &integrations.GlueCrawlers{Roles: serviceRoles, S3: s3Service},
		JobEvents:     glueEvents, CrawlerEvents: glueEvents, CatalogEvents: glueEvents,
		ConnectionSecrets: integrations.GlueConnectionSecrets{Secrets: secretsManagerService},
		ConnectionCrypto:  integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "glue"},
	})
	var athenaEngine athena.Engine
	if config.AthenaRuntime != nil {
		athenaEngine = &integrations.AthenaEngine{Runtime: config.AthenaRuntime, Glue: glueService, S3: s3Service}
	}
	athenaService := athena.New(athena.Config{
		Repository: backends.Athena, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Engine: athenaEngine,
		Results: integrations.AthenaS3{S3: s3Service}, Catalog: integrations.AthenaGlue{Glue: glueService},
		Events: integrations.AthenaEvents{Publisher: servicePublisher, Clock: config.Clock}, Metrics: cloudwatchService,
	})
	rdsRoles := &integrations.RDSRoles{Roles: serviceRoles, Provisioner: iamService}
	docdbService := docdb.New(docdb.Config{
		Repository: backends.DocumentDB, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.DocumentDBRuntime,
		Cipher: integrations.RDSCredentialCipher{Roles: rdsRoles, Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "rds"}},
		Names:  integrations.RDSNames{Repository: backends.RDS},
	})
	lambdaDocuments.Clusters = docdbService
	rdsService := rds.New(rds.Config{
		Repository: backends.RDS, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.RDSRuntime,
		Cipher:   integrations.RDSCredentialCipher{Roles: rdsRoles, Keys: integrations.ServiceDataKeys{KMS: kmsService, Activity: iamService, Service: "rds"}},
		Networks: integrations.RDSNetworks{Roles: rdsRoles, EC2: ec2Service},
		Events:   integrations.RDSEvents{Publisher: servicePublisher}, Metrics: integrations.RDSMetrics{Metrics: cloudwatchService},
		DocumentDB: integrations.DocumentDBQuery{Documents: docdbService},
	})
	rdsDataService := rdsdata.New(rdsdata.Config{Clusters: integrations.RDSDataClusters{Databases: rdsService}, Secrets: integrations.RDSDataSecrets{Secrets: secretsManagerService}, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock})
	appsyncIAM := &integrations.AppSyncIAM{Credentials: credentials}
	appsyncService := appsync.NewWithConfig(appsync.Config{
		Repository: backends.AppSync, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Endpoint: config.PublicEndpoint,
		Sources: &integrations.AppSyncSources{Roles: serviceRoles, Lambda: lambdaService, DynamoDB: dynamoService, RDSData: rdsDataService, HTTPClient: config.OutboundHTTP},
		Auth:    appsync.NewAuthenticator(appsync.AuthConfig{Clock: config.Clock, IAM: appsyncIAM, Keys: integrations.AppSyncKeys{Cognito: cognitoService, Discovery: config.OIDCDiscovery}}),
	})
	searchService := opensearch.New(opensearch.Config{Repository: backends.OpenSearch, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.OpenSearchRuntime, PublicEndpoint: config.PublicEndpoint, Metrics: integrations.OpenSearchMetrics{Metrics: cloudwatchService}})
	kafkaService := kafka.New(kafka.Config{
		Repository: backends.Kafka, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock,
		Runtime: config.MSKRuntime, Secrets: integrations.KafkaSecrets{Secrets: secretsManagerService, KMS: kmsService, Activity: iamService},
	})
	lambdaKafka.Clusters, lambdaKafka.Secrets = kafkaService, secretsManagerService
	mqService := mq.New(mq.Config{Repository: backends.MQ, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.MQRuntime, Logs: integrations.MQLogs{Logs: logsService, Roles: serviceRoles}, ServiceLinkedRoles: iamService, Metrics: integrations.MQMetrics{Metrics: cloudwatchService}})
	lambdaMQ.Brokers, lambdaMQ.Secrets = mqService, secretsManagerService
	elasticacheService := elasticache.New(elasticache.Config{
		Repository: backends.ElastiCache, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.ValkeyRuntime,
		Networks: integrations.ElastiCacheNetworks{EC2: ec2Service}, Metrics: integrations.ElastiCacheMetrics{Metrics: cloudwatchService},
	})
	memorydbService := memorydb.New(memorydb.Config{
		Repository: backends.MemoryDB, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Runtime: config.ValkeyRuntime,
		Networks: integrations.MemoryDBNetworks{EC2: ec2Service}, Metrics: integrations.MemoryDBMetrics{Metrics: cloudwatchService},
	})
	cloudtrailService := cloudtrail.New(cloudtrail.Config{Repository: backends.CloudTrail, Organizations: trailOrganizations, OrganizationRoles: trailRoles, Journal: backends.Journal, Destination: integrations.CloudTrailS3{S3: s3Service}, LogsDestination: integrations.CloudTrailLogs{Logs: logsService, Roles: serviceRoles, Clock: config.Clock}, Notifications: integrations.CloudTrailSNS{SNS: snsService}, APIEvents: apiEvents, Authorizer: authorizer, Clock: config.Clock})
	xrayService := xray.New(xray.Config{Repository: backends.XRay, Authorizer: authorizer, PolicyBinder: authorizer, Recorder: apiEvents, Clock: config.Clock, Metrics: cloudwatchService})
	workflowTracing := &integrations.StepFunctionsTracing{Roles: serviceRoles, Clock: config.Clock}
	workflowTasks := &integrations.StepFunctionsTasks{Roles: serviceRoles, ECS: ecsService, SyncRules: eventbridgeService, Tracing: workflowTracing, Connections: eventbridgeService, HTTPClient: config.OutboundHTTP}
	workflowService := stepfunctions.New(stepfunctions.Config{Repository: backends.StepFunctions, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, Tasks: workflowTasks, TaskDependencies: workflowTasks, Events: integrations.StepFunctionsEvents{Publisher: servicePublisher}, History: &integrations.StepFunctionsLogs{Logs: logsService, Roles: serviceRoles, KMS: kmsService, Activity: iamService}, Metrics: cloudwatchService, Tracing: workflowTracing, EncryptionKeys: integrations.StepFunctionsKeys{KMS: kmsService, Activity: iamService, Roles: serviceRoles}})
	workflowTasks.Executions = workflowService
	eventTargets.StepFunctions = workflowService
	eventTargets.StepFunctionsCompletions = workflowTasks
	schedulerTargets := &integrations.SchedulerTargets{Roles: serviceRoles}
	schedulerService := schedulerservice.NewWithConfig(schedulerservice.Config{
		Repository: backends.Scheduler, Authorizer: authorizer, Clock: config.Clock,
		Delivery: schedulerTargets, Roles: schedulerTargets,
		Keys:    integrations.SchedulerKeys{KMS: kmsService, Activity: iamService, Roles: serviceRoles},
		Metrics: cloudwatchService, APIEvents: apiEvents,
	})
	pipesTargets := &integrations.PipesTargets{Roles: serviceRoles, Functions: lambdaService, APIDestinations: eventbridgeService}
	pipesDiagnostics := &integrations.PipesDiagnostics{Logs: logsService}
	pipesSources := &integrations.PipesSources{Roles: serviceRoles, Queues: sqsService}
	if config.KinesisRuntime != nil {
		pipesSources.KinesisStreams = kinesisService
	}
	if config.DynamoDBRuntime != nil {
		pipesSources.DynamoDBStreams = dynamoStreams
	}
	pipesService := pipes.NewWithConfig(pipes.Config{
		Repository: backends.Pipes, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock,
		Sources:      pipesSources,
		KafkaSources: &integrations.PipesKafka{Roles: serviceRoles, Clusters: kafkaService, Secrets: secretsManagerService},
		Targets:      pipesTargets, Metrics: cloudwatchService,
		Keys:        &integrations.PipesKeys{Roles: serviceRoles, KMS: kmsService},
		Diagnostics: pipesDiagnostics,
	})
	cloudformationService := cloudformation.New(cloudformation.Config{Repository: backends.CloudFormation, Authorizer: authorizer, Clock: config.Clock, Recorder: apiEvents, Roles: integrations.CloudFormationRoles{Roles: serviceRoles}})
	cloudcontrolService := cloudcontrol.New(cloudcontrol.Config{Repository: backends.CloudControl, Authorizer: authorizer, Clock: config.Clock, Recorder: apiEvents, Roles: integrations.CloudFormationRoles{Roles: serviceRoles}})
	var ssmMessages *ssmmessages.Service
	closeServices := func() error {
		acmJobs.Close()
		var messageError error
		if route53Service != nil {
			messageError = route53Service.Close()
		}
		if ssmMessages != nil {
			messageError = errors.Join(messageError, ssmMessages.Close())
		}
		messageError = errors.Join(messageError, appsyncService.Close(), docdbService.Close(), mqService.Close())
		messageError = errors.Join(messageError, pipelineService.Close(), appconfigService.Close(), resourceGroupsService.Close())
		messageError = errors.Join(messageError, guarddutyService.Close())
		return errors.Join(messageError, configService.Close(), taggingService.Close(), sesService.Close(), autoScalingService.Close(), ssmCommands.Close(), ssmDocuments.Close(), cloudcontrolService.Close(), cloudformationService.Close(), eksService.Close(), elasticacheService.Close(), memorydbService.Close(), searchService.Close(), schedulerService.Close(), pipesService.Close(), kafkaService.Close(), parameterService.Close(), rdsDataService.Close(), rdsService.Close(), buildService.Close(), apiGatewayWebSocketService.Close(), apiGatewayService.Close(), workflowService.Close(), athenaService.Close(), glueService.Close(), secretsManagerService.Close(), scalingService.Close(), ecsService.Close(), elbv2Service.Close(), ec2Service.Close(), ebsService.Close(), ecrService.Close(), firehoseService.Close(), lambdaService.Close(), dynamoService.Close(), logsService.Close(), cloudwatchService.Close(), cloudtrailService.Close(), eventbridgeService.Close(), kinesisService.Close(), snsService.Close(), s3Service.Close(), organizationsService.Close(), accountService.Close(), sqsService.Close(), kmsService.Close(), iamService.Close(), xrayService.Close())
	}
	if dnsAuthority != nil {
		if err := elbv2Service.RegisterDNS(context.Background()); err != nil {
			_ = closeServices()
			return nil, fmt.Errorf("register managed ALB DNS authority: %w", err)
		}
	}
	route53Service, err = route53.New(route53.Config{Repository: backends.Route53, Authorizer: authorizer, Recorder: apiEvents, Clock: config.Clock, DNSAuthority: dnsAuthority, Aliases: integrations.Route53Aliases{ELBV2: elbv2Service}})
	if err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register Route 53 DNS authority: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.SSMRoleTemplate(), integrations.SSMRoleUsage{Commands: ssmCommands}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register SSM service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.ResourceGroupsRoleTemplate(), resourceGroupsRoles); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register Resource Groups service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.AppRegistryRoleTemplate(), integrations.AppRegistryRoleUsage{Applications: appRegistryService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register AppRegistry service-linked role: %w", err)
	}
	if err := registerLambdaCapacityRoleUsage(iamService, lambdaService); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register Lambda capacity service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.CognitoEmailRoleTemplate(), integrations.CognitoEmailRoleUsage{Pools: cognitoService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register Cognito email service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.EventBridgeConnectionRoleTemplate(), integrations.EventBridgeConnectionRoleUsage{Connections: eventbridgeService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register EventBridge connection service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.ECRReplicationRoleTemplate(), integrations.ECRReplicationRoleUsage{Registries: ecrService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register ECR replication service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.RDSRoleTemplate(), integrations.RDSRoleUsage{Databases: rdsService, Documents: docdbService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register RDS service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.EKSClusterRoleTemplate(), integrations.EKSClusterRoleUsage{Clusters: eksService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register EKS cluster service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.NodegroupRoleTemplate(), integrations.NodegroupRoleUsage{Groups: eksService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register EKS nodegroup service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.MQRoleTemplate(), integrations.MQRoleUsage{Brokers: mqService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register MQ service-linked role: %w", err)
	}
	if err := iamService.RegisterServiceLinkedRole(integrations.GuardDutyRoleTemplate(), integrations.GuardDutyRoleUsage{Detectors: guarddutyService}); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("register GuardDuty service-linked role: %w", err)
	}
	for _, template := range iamService.ServiceLinkedRoleTemplates() {
		var usage iam.ServiceLinkedRoleUsageProvider
		switch template.ServiceName {
		case "cloudtrail.amazonaws.com":
			usage = trailRoles
		case elbv2.ServicePrincipal:
			usage = integrations.ELBV2RoleUsage{LoadBalancers: elbv2Service}
		case ecs.ServicePrincipal:
			usage = integrations.ECSRoleUsage{Clusters: ecsService}
		case applicationautoscaling.ECSServicePrincipal, applicationautoscaling.DynamoDBServicePrincipal:
			usage = integrations.ApplicationScalingRoleUsage{Targets: scalingService}
		case autoscaling.ServicePrincipal:
			usage = integrations.AutoScalingRoleUsage{Groups: autoScalingService}
		case dynamodb.ReplicationServicePrincipal:
			usage = integrations.DynamoDBReplicaRoleUsage{Tables: dynamoService}
		case dynamodb.KinesisServicePrincipal:
			usage = integrations.DynamoDBKinesisRoleUsage{Tables: dynamoService}
		case "ram.amazonaws.com":
			usage = ramOrganizations
		default:
			continue
		}
		if err := iamService.RegisterServiceLinkedRole(template, usage); err != nil {
			_ = closeServices()
			return nil, fmt.Errorf("register %s service-linked role: %w", template.ServiceName, err)
		}
	}
	jobs, err := scheduler.Join(backends.Read, guarddutyService.JobDriver(), pipelineService.JobDriver(), observationJobs, acmJobs, resourceGroupsService.JobDriver(), appconfigService.JobDriver(), configService.JobDriver(), taggingService.JobDriver(), sesService.JobDriver(), autoScalingService.JobDriver(), cloudcontrolService.JobDriver(), cloudformationService.JobDriver(), eksService.JobDriver(), elasticacheService.JobDriver(), memorydbService.JobDriver(), searchService.JobDriver(), iamService.JobDriver(), organizationsService.JobDriver(), sqsService.JobDriver(), kmsService.JobDriver(), eventbridgeService.JobDriver(), lambdaService.JobDriver(), logsService.JobDriver(), cloudtrailService.JobDriver(), dynamoService.JobDriver(), kinesisService.JobDriver(), kafkaService.JobDriver(), firehoseService.JobDriver(), cloudwatchService.JobDriver(), snsService.JobDriver(), s3Service.JobDriver(), ecsService.JobDriver(), elbv2Service.JobDriver(), ebsService.JobDriver(), ec2Service.JobDriver(), ecrService.JobDriver(), buildService.JobDriver(), scalingService.JobDriver(), xrayService.JobDriver(), workflowService.JobDriver(), secretsManagerService.JobDriver(), parameterService.JobDriver(), ssmDocuments.JobDriver(), ssmCommands.JobDriver(), apiGatewayService.JobDriver(), glueService.JobDriver(), athenaService.JobDriver(), rdsService.JobDriver(), rdsDataService.JobDriver(), docdbService.JobDriver(), mqService.JobDriver(), schedulerService.JobDriver(), pipesService.JobDriver())
	if err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("join service jobs: %w", err)
	}
	services := []struct {
		name     string
		provider interface {
			gateway.Provider
			awscommands.CommandExecutor
		}
		decode func(string, awsapi.Request) (awsapi.DecodedRequest, error)
	}{
		{"account", accountService, accountapi.DecodeRequest},
		{"acm", acmService, acmapi.DecodeRequest},
		{"apigateway", apiGatewayService, apigatewayapi.DecodeRequest},
		{"apigatewaymanagementapi", apiGatewayWebSocketService, apigatewaymanagementapi.DecodeRequest},
		{"apigatewayv2", apiGatewayV2Service, apigatewayv2api.DecodeRequest},
		{"appconfig", appconfigService, appconfigapi.DecodeRequest},
		{"appconfigdata", appconfigService.DataHandler(), appconfigdataapi.DecodeRequest},
		{"applicationautoscaling", scalingService, applicationautoscalingapi.DecodeRequest},
		{"appsync", appsyncService, appsyncapi.DecodeRequest},
		{"athena", athenaService, athenaapi.DecodeRequest},
		{"autoscaling", autoScalingService, autoscalingapi.DecodeRequest},
		{"cloudcontrol", cloudcontrolService, cloudcontrolapi.DecodeRequest},
		{"cloudformation", cloudformationService, cloudformationapi.DecodeRequest},
		{"cloudtrail", cloudtrailService, cloudtrailapi.DecodeRequest},
		{"cloudwatch", cloudwatchService, cloudwatchapi.DecodeRequest},
		{"codebuild", buildService, codebuildapi.DecodeRequest},
		{"codepipeline", pipelineService, codepipelineapi.DecodeRequest},
		{"cognitoidp", cognitoService, cognitoidpapi.DecodeRequest},
		{"configservice", configService, configserviceapi.DecodeRequest},
		{"cognitoidentity", identityPoolService, cognitoidentityapi.DecodeRequest},
		{"identitystore", identityStoreService, identitystoreapi.DecodeRequest},
		{"ssoadmin", identityCenterService.Frontend("ssoadmin"), ssoadminapi.DecodeRequest},
		{"ssooidc", identityCenterService.Frontend("ssooidc"), ssooidcapi.DecodeRequest},
		{"sso", identityCenterService.Frontend("sso"), ssoapi.DecodeRequest},
		{"dynamodb", dynamoService, dynamodbapi.DecodeRequest},
		{"dynamodbstreams", dynamoStreams, dynamodbstreamsapi.DecodeRequest},
		{"ebs", ebsService, ebsapi.DecodeRequest},
		{"ec2", ec2Service, ec2api.DecodeRequest},
		{"ecr", ecrService, ecrapi.DecodeRequest},
		{"ecs", ecsService, ecsapi.DecodeRequest},
		{"eks", eksService, eksapi.DecodeRequest},
		{"eksauth", eksService.PodIdentityAuth(), eksauthapi.DecodeRequest},
		{"es", searchService.Legacy(), esapi.DecodeRequest},
		{"elasticache", elasticacheService, elasticacheapi.DecodeRequest},
		{"elbv2", elbv2Service, elbv2api.DecodeRequest},
		{"eventbridge", eventbridgeService, eventbridgeapi.DecodeRequest},
		{"firehose", firehoseService, firehoseapi.DecodeRequest},
		{"glue", glueService, glueapi.DecodeRequest},
		{"guardduty", guarddutyService, guarddutyapi.DecodeRequest},
		{"iam", iamService, iamapi.DecodeRequest},
		{"kafka", kafkaService, kafkaapi.DecodeRequest},
		{"kinesis", kinesisService, kinesisapi.DecodeRequest},
		{"kms", kmsService, kmsapi.DecodeRequest},
		{"lambda", lambdaService, lambdaapi.DecodeRequest},
		{"logs", logsService, logsapi.DecodeRequest},
		{"opensearch", searchService, opensearchapi.DecodeRequest},
		{"memorydb", memorydbService, memorydbapi.DecodeRequest},
		{"mq", mqService, mqapi.DecodeRequest},
		{"signer", signerService, signerapi.DecodeRequest},
		{"organizations", organizationsService, organizationsapi.DecodeRequest},
		{"ram", ramService, ramapi.DecodeRequest},
		{"rds", rdsService, rdsapi.DecodeRequest},
		{"rdsdata", rdsDataService, rdsdataapi.DecodeRequest},
		{"docdb", docdbService, docdbapi.DecodeRequest},
		{"pipes", pipesService, pipesapi.DecodeRequest},
		{"resourcegroups", resourceGroupsService, resourcegroupsapi.DecodeRequest},
		{"resourcegroupstaggingapi", taggingService, resourcegroupstaggingapiapi.DecodeRequest},
		{"route53", route53Service, route53api.DecodeRequest},
		{"s3", s3Service, s3api.DecodeRequest},
		{"s3control", s3Service.Control(), s3controlapi.DecodeRequest},
		{"scheduler", schedulerService, schedulerapi.DecodeRequest},
		{"secretsmanager", secretsManagerService, secretsmanagerapi.DecodeRequest},
		{"servicecatalogappregistry", appRegistryService, servicecatalogappregistryapi.DecodeRequest},
		{"ses", sesService.Classic(), sesapi.DecodeRequest},
		{"sesv2", sesService, sesv2api.DecodeRequest},
		{"sns", snsService, snsapi.DecodeRequest},
		{"sqs", sqsService, sqsapi.DecodeRequest},
		{"ssm", ssmService, ssmapi.DecodeRequest},
		{"stepfunctions", workflowService, stepfunctionsapi.DecodeRequest},
		{"sts", stsService, stsapi.DecodeRequest},
		{"xray", xrayService, xrayapi.DecodeRequest},
	}
	commands := make(map[string]awscommands.CommandExecutor, len(services))
	for _, registration := range services {
		service, err := modeledService(registration.name, registration.provider, registration.decode)
		if err != nil {
			_ = closeServices()
			return nil, err
		}
		if err := registry.Register(service); err != nil {
			_ = closeServices()
			return nil, err
		}
		commands[registration.name] = registration.provider
	}
	workflowTasks.Commands = integrations.NewStepFunctionsCommands(commands)
	taggingResources.Commands = workflowTasks.Commands
	workflowTracing.Commands = workflowTasks.Commands
	schedulerTargets.Commands = workflowTasks.Commands
	pipesTargets.Commands = workflowTasks.Commands
	pipesDiagnostics.Commands = workflowTasks.Commands
	cloudformationHandlers := integrations.CloudFormationMessagingHandlers(workflowTasks.Commands)
	for name, handler := range integrations.CloudFormationComputeHandlers(workflowTasks.Commands) {
		cloudformationHandlers[name] = handler
	}
	for name, handler := range integrations.CloudFormationBootstrapHandlers(workflowTasks.Commands) {
		cloudformationHandlers[name] = handler
	}
	for name, handler := range integrations.CloudFormationKMSHandlers(workflowTasks.Commands) {
		cloudformationHandlers[name] = handler
	}
	cloudformationService.SetTemplateSources(integrations.CloudFormationTemplateSource{S3: s3Service}, integrations.CloudFormationParameterSource{Commands: workflowTasks.Commands})
	cloudcontrolService.SetHandlers(cloudformationHandlers)
	cloudformationService.SetHandlers(cloudformationHandlers)
	for _, service := range config.Extensions {
		if err := registerExtension(registry, service); err != nil {
			_ = closeServices()
			return nil, err
		}
	}
	// TODO: Comeback add supervised process extensions with startup, health, cancellation and shutdown hooks.
	// TODO: Comeback extend container-backed Lambda execution with remaining runtime protocols and imported compute/database engines, health, quotas and network-policy enforcement; no microVM or in-process fallback.
	// TODO: Comeback implement the community/pro operation target and required data planes in docs/services.json; registration alone is not semantic completion.
	endpoint, err = gateway.New(registry, gateway.Config{AccountID: config.AccountID, MaxBodyBytes: config.MaxBodyBytes, Credentials: credentials, UnsignedRegion: config.UnsignedRegion, Activity: iamService, Regions: accountService, Clock: config.Clock, Origin: lambdaService})
	if err != nil {
		_ = closeServices()
		return nil, err
	}
	appsyncIAM.Gateway = endpoint
	ssmMessages = ssmmessages.New(ssmmessages.Config{Backend: ssmCommands, Authenticate: endpoint.Authenticate, Clock: config.Clock})
	sqsService.StartWorkers()
	organizationsService.StartWorkers()
	iamService.StartWorkers()
	kmsService.StartWorkers()
	if err := ec2Service.ResumeInstanceControllers(context.Background()); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume EC2 controllers: %w", err)
	}
	if err := elbv2Service.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume ALB nodes: %w", err)
	}
	if err := lambdaService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume Lambda deployments: %w", err)
	}
	if err := ecsService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume ECS tasks: %w", err)
	}
	if err := autoScalingService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume Auto Scaling groups: %w", err)
	}
	if err := eksService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume EKS clusters: %w", err)
	}
	if err := buildService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume CodeBuild executions: %w", err)
	}
	if err := kinesisService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume Kinesis engines: %w", err)
	}
	if err := dynamoService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume DynamoDB engines: %w", err)
	}
	if err := firehoseService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume Firehose processing: %w", err)
	}
	if err := glueService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume Glue work: %w", err)
	}
	if err := athenaService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume Athena queries: %w", err)
	}
	if err := rdsService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume RDS databases: %w", err)
	}
	if err := kafkaService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume MSK clusters: %w", err)
	}
	if err := mqService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume MQ brokers: %w", err)
	}
	if err := rdsDataService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("start RDS Data sessions: %w", err)
	}
	if err := docdbService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume DocumentDB databases: %w", err)
	}
	if err := searchService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume OpenSearch domains: %w", err)
	}
	if err := elasticacheService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume ElastiCache engines: %w", err)
	}
	if err := memorydbService.Start(); err != nil {
		_ = closeServices()
		return nil, fmt.Errorf("resume MemoryDB engines: %w", err)
	}
	issuer := iamService.OutboundIdentityHandler()
	functionURLs := lambda.NewFunctionURLHandler(lambdaService, endpoint, iamService, organizationsService)
	apiExecution := apigatewayexec.New(apigatewayexec.Config{HTTP: apiGatewayV2Service, REST: apiGatewayService, Authentication: endpoint, Authorization: authorizer, Functions: lambdaService, Roles: gatewayInvocationRoles, UsagePlans: apiGatewayService, Metrics: apiGatewayService, Keys: integrations.GatewayKeys{Cognito: cognitoService, Discovery: oidcDiscovery}, Clock: config.Clock, Logs: gatewayLogs})
	websocketExecution := apigatewaywebsocket.NewHandler(apiGatewayWebSocketService, endpoint)
	registryHandler := ecrService.RegistryHandler()
	buildCredentials := buildService.CredentialsHandler()
	sesVerification := sesService.VerificationHandler()
	ssoAuthorization := identityCenterService.AuthorizationHandler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browser authorization shares this listener with S3. Do not reserve a
		// valid bucket/object name or intercept signed and presigned API calls.
		if r.URL.Path == identitycenter.AuthorizePath && r.Header.Get("Authorization") == "" && r.Header.Get("X-Amz-Target") == "" {
			query := r.URL.Query()
			browserGet := r.Method == http.MethodGet && (query.Has("client_id") || query.Has("response_type"))
			browserPost := r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
			if !query.Has("X-Amz-Signature") && (browserGet || browserPost) {
				ssoAuthorization.ServeHTTP(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, identitycenter.AuthorizationPath) {
			ssoAuthorization.ServeHTTP(w, r)
			return
		}
		if appsyncService.HandlesDataRequest(r) {
			appsyncService.ServeDataHTTP(w, r)
			return
		}
		if r.URL.Path == sesv2.VerificationPath {
			sesVerification.ServeHTTP(w, r)
			return
		}
		if ssmmessages.Handles(r) {
			ssmMessages.ServeHTTP(w, r)
			return
		}
		if ecr.IsRegistryRequest(r) {
			registryHandler.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_stackd/codebuild/credentials/") {
			buildCredentials.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, apigatewayexec.Prefix) {
			if websocketExecution.ServeExecution(w, r) {
				return
			}
			apiExecution.ServeHTTP(w, r)
			return
		}
		if s3Service.ServeWebsite(w, r) {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_stackd/oidc/") {
			issuer.ServeHTTP(w, r)
			return
		}
		if eksService.ServeOIDCIssuer(w, r) {
			return
		}
		if ec2Service.ServeInstanceIdentityCertificate(w, r) {
			return
		}
		if snsService.ServeSigningCertificate(w, r) {
			return
		}
		if lambdaService.ServeCodeDownload(w, r) {
			return
		}
		if functionURLs.ServeFunctionURL(w, r) {
			return
		}
		endpoint.ServeHTTP(w, r)
	})
	return &Stack{handler: handler, close: closeServices, clock: config.Clock, journal: backends.Journal, jobs: jobs, dns: dnsServer}, nil
}

// Stack is an isolated HTTP endpoint and its background service workers. Close
// stops workers and detaches retained ECS tasks; callers own their HTTP listeners.
type Stack struct {
	handler http.Handler
	close   func() error
	once    sync.Once
	err     error
	clock   clock.Clock
	journal journal.Storage
	jobs    *scheduler.Driver
	dns     *dnsruntime.Server
}

func (s *Stack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_stackd/events":
		s.serveEvents(w, r)
	case "/_stackd/clock":
		s.serveClock(w, r)
	case "/_stackd/jobs/drain":
		s.serveJobDrain(w, r)
	default:
		s.handler.ServeHTTP(w, r)
	}
}

// DNSAddress returns the owned UDP/TCP DNS endpoint, or empty when unconfigured.
// Callers configure their resolver explicitly; Stack never changes host DNS.
func (s *Stack) DNSAddress() string {
	if s.dns == nil {
		return ""
	}
	return s.dns.Address()
}

func (s *Stack) Close() error {
	s.once.Do(func() {
		s.err = s.close()
		if s.dns != nil {
			s.err = errors.Join(s.err, s.dns.Close())
		}
	})
	return s.err
}
