package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/clock"
	"stackd/internal/awsapi"
	cloudwatchapi "stackd/internal/awsapi/cloudwatch"
	lambdaapi "stackd/internal/awsapi/lambda"
	s3api "stackd/internal/awsapi/s3"
	secretsapi "stackd/internal/awsapi/secretsmanager"
	ssmapi "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/s3"
)

// AppConfigCommands enters an owner's generated command boundary, including its
// current authorization and audit. It never reads another service's repository.
type AppConfigCommands interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}
type AppConfigObjects interface {
	GetObject(context.Context, *s3api.GetObjectInput) (*s3.ObjectResponse[s3api.GetObjectOutput], *awswire.Error)
}
type AppConfigFunctions interface {
	Invoke(context.Context, *lambdaapi.InvokeInput) (*lambdaapi.InvokeOutput, string, *awswire.Error)
}
type AppConfigAlarms interface {
	DescribeAlarms(context.Context, *cloudwatchapi.DescribeAlarmsInput) (*cloudwatchapi.DescribeAlarmsOutput, *awswire.Error)
}
type AppConfigSecrets interface {
	GetSecretValue(context.Context, *secretsapi.GetSecretValueInput) (*secretsapi.GetSecretValueOutput, *awswire.Error)
}

// AppConfigEffects retains no external metadata, roles or authorization results.
// Role-based sources use fresh trust; CodePipeline preserves the caller's authority.
type AppConfigEffects struct {
	Roles                 ServiceRoles
	Parameters, Documents AppConfigCommands
	Objects               AppConfigObjects
	PipelineArtifacts     AppConfigPipelineArtifacts
	Secrets               AppConfigSecrets
	Functions             AppConfigFunctions
	Alarms                AppConfigAlarms
	Keys                  ServiceDataKeys
	SNS, SQS              AppConfigCommands
	Events                EventBridgeEventPublisher
	Clock                 clock.Clock
}

var _ appconfig.Effects = (*AppConfigEffects)(nil)

func appConfigARN(scope appconfig.Scope, resource string) string {
	return "arn:" + scope.Partition + ":appconfig:" + scope.Region + ":" + scope.AccountID + ":" + resource
}
func appConfigPrincipal(scope appconfig.Scope, source string) awsctx.ServicePrincipal {
	return awsctx.ServicePrincipal{Name: "appconfig.amazonaws.com", SourceARN: source, Type: "AWSService"}
}
func appConfigScopeContext(ctx context.Context, scope appconfig.Scope) context.Context {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = scope.Partition, scope.AccountID, scope.Region
	return awsctx.WithMetadata(ctx, m)
}
func (a *AppConfigEffects) roleContext(ctx context.Context, scope appconfig.Scope, role, source string) (context.Context, error) {
	if role == "" {
		return nil, appConfigFailure("A retrieval or action role is required.")
	}
	ctx = appConfigScopeContext(ctx, scope)
	credential, rejected := a.Roles.assume(ctx, appConfigPrincipal(scope, source), role, identity.RoleSessionSpec{SessionName: "AppConfig"}, "")
	if rejected != nil {
		return nil, rejected
	}
	result, rejected := serviceRoleRequestContext(ctx, credential, scope.Region, "appconfig.amazonaws.com")
	if rejected != nil {
		return nil, rejected
	}
	return result, nil
}

func (a *AppConfigEffects) AssumeRetrievalRole(ctx context.Context, scope appconfig.Scope, role string) error {
	_, err := a.roleContext(ctx, scope, role, awsctx.FromContext(ctx).ServicePrincipal.SourceARN)
	return err
}
func appConfigCommand(ctx context.Context, owner AppConfigCommands, service, action string, in any) (any, error) {
	if owner == nil {
		return nil, fmt.Errorf("AppConfig %s owner is unavailable", service)
	}
	model, _ := awscatalog.LookupService(service)
	operation, _ := model.Operation(action)
	out, rejected := owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: in})
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}
func appConfigFailure(message string) *awswire.Error {
	return &awswire.Error{Code: "BadRequestException", Message: message, StatusCode: 400}
}
func appConfigString[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

func (a *AppConfigEffects) Retrieve(ctx context.Context, p appconfig.Profile, version string) (appconfig.ConfigurationContent, error) {
	if strings.HasPrefix(p.LocationURI, "codepipeline://") {
		return a.retrievePipeline(ctx, p, version)
	}
	var result appconfig.ConfigurationContent
	source := appConfigARN(p.Scope, "application/"+p.ApplicationID+"/configurationprofile/"+p.ID)
	ctx, err := a.roleContext(ctx, p.Scope, p.RetrievalRoleARN, source)
	if err != nil {
		return result, err
	}
	kind, reference, ok := strings.Cut(p.LocationURI, "://")
	if !ok {
		parsed, e := arn.Parse(p.LocationURI)
		if e != nil {
			return result, appConfigFailure("Invalid configuration location URI.")
		}
		reference = p.LocationURI
		switch {
		case parsed.Service == "ssm" && strings.HasPrefix(parsed.Resource, "parameter/"):
			kind = "ssm-parameter"
		case parsed.Service == "ssm" && strings.HasPrefix(parsed.Resource, "document/"):
			kind = "ssm-document"
		case parsed.Service == "secretsmanager":
			kind = "secretsmanager"
		default:
			return result, appConfigFailure("Unsupported configuration location URI.")
		}
	}
	switch kind {
	case "ssm-parameter":
		if version != "" {
			reference += ":" + version
		}
		raw, e := appConfigCommand(ctx, a.Parameters, "ssm", "GetParameter", &ssmapi.GetParameterRequest{Name: new(ssmapi.PSParameterName(reference)), WithDecryption: new(ssmapi.Boolean(true))})
		if e != nil {
			return result, e
		}
		out := raw.(*ssmapi.GetParameterResult)
		if out.Parameter == nil || out.Parameter.Value == nil || out.Parameter.Version == nil {
			return result, fmt.Errorf("SSM returned an incomplete parameter")
		}
		result.Content = []byte(*out.Parameter.Value)
		result.Version = strconv.FormatInt(int64(*out.Parameter.Version), 10)
		result.ContentType = "application/octet-stream"
	case "ssm-document":
		in := &ssmapi.GetDocumentRequest{Name: new(ssmapi.DocumentARN(reference))}
		if version != "" {
			in.DocumentVersion = new(ssmapi.DocumentVersion(version))
		}
		raw, e := appConfigCommand(ctx, a.Documents, "ssm", "GetDocument", in)
		if e != nil {
			return result, e
		}
		out := raw.(*ssmapi.GetDocumentResult)
		if appConfigString(out.DocumentType) != "ApplicationConfiguration" {
			return result, appConfigFailure("The SSM document must have type ApplicationConfiguration.")
		}
		if out.Content == nil || out.DocumentVersion == nil {
			return result, fmt.Errorf("SSM returned an incomplete configuration document")
		}
		result.Content = []byte(*out.Content)
		result.Version = string(*out.DocumentVersion)
		result.ContentType = "application/json"
		if appConfigString(out.DocumentFormat) == "YAML" {
			result.ContentType = "application/x-yaml"
		}
	case "s3":
		if a.Objects == nil {
			return result, fmt.Errorf("AppConfig S3 owner is unavailable")
		}
		u, e := url.Parse(p.LocationURI)
		if e != nil || u.Host == "" || u.Path == "" {
			return result, appConfigFailure("Invalid S3 configuration URI.")
		}
		in := &s3api.GetObjectInput{Bucket: new(s3api.BucketName(u.Host)), Key: new(s3api.ObjectKey(strings.TrimPrefix(u.Path, "/")))}
		if version != "" {
			in.VersionId = new(s3api.ObjectVersionId(version))
		}
		out, rejected := a.Objects.GetObject(ctx, in)
		if rejected != nil {
			return result, rejected
		}
		result.Content = out.Output.Body
		result.ContentType = appConfigString(out.Output.ContentType)
		result.Version = appConfigString(out.Output.VersionId)
		if result.Version == "" {
			return result, appConfigFailure("The S3 configuration object must be versioned.")
		}
	case "secretsmanager":
		if a.Secrets == nil {
			return result, fmt.Errorf("AppConfig Secrets Manager owner is unavailable")
		}
		in := &secretsapi.GetSecretValueInput{SecretId: new(secretsapi.SecretIdType(reference))}
		if version != "" {
			in.VersionId = new(secretsapi.SecretVersionIdType(version))
		}
		out, rejected := a.Secrets.GetSecretValue(ctx, in)
		if rejected != nil {
			return result, rejected
		}
		result.Content = out.SecretBinary
		if out.SecretString != nil {
			result.Content = []byte(*out.SecretString)
		}
		result.Version = appConfigString(out.VersionId)
		result.ContentType = "application/octet-stream"
	default:
		return result, appConfigFailure("The configuration source has no available execution owner: " + kind)
	}
	return result, nil
}

func (a *AppConfigEffects) ValidateLambda(ctx context.Context, p appconfig.Profile, function, version string, content []byte) error {
	if a.Functions == nil {
		return fmt.Errorf("AppConfig Lambda owner is unavailable")
	}
	payload, err := json.Marshal(struct {
		ApplicationID string `json:"applicationId"`
		ProfileID     string `json:"configurationProfileId"`
		Version       string `json:"configurationVersion"`
		Content       []byte `json:"content"`
		URI           string `json:"uri"`
	}{p.ApplicationID, p.ID, version, content, p.LocationURI})
	if err != nil {
		return err
	}
	// Validators use a Lambda resource-policy grant to AppConfig, not the profile retrieval role.
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: appConfigPrincipal(p.Scope, appConfigARN(p.Scope, "application/"+p.ApplicationID+"/configurationprofile/"+p.ID))})
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _, rejected := a.Functions.Invoke(ctx, &lambdaapi.InvokeInput{FunctionName: new(lambdaapi.NamespacedFunctionName(function)), InvocationType: new(lambdaapi.InvocationType("RequestResponse")), Payload: payload})
	if rejected != nil {
		return rejected
	}
	if appConfigString(out.FunctionError) != "" {
		return appConfigFailure("Lambda validator rejected configuration: " + string(out.Payload))
	}
	return nil
}

func (a *AppConfigEffects) Alarm(ctx context.Context, scope appconfig.Scope, monitor appconfig.Monitor) (string, error) {
	if a.Alarms == nil {
		return "", fmt.Errorf("AppConfig CloudWatch owner is unavailable")
	}
	parsed, err := arn.Parse(monitor.AlarmARN)
	if err != nil || parsed.Service != "cloudwatch" || parsed.Partition != scope.Partition || parsed.Region != scope.Region || !strings.HasPrefix(parsed.Resource, "alarm:") {
		return "", appConfigFailure("Invalid CloudWatch alarm ARN.")
	}
	ctx, err = a.roleContext(ctx, scope, monitor.RoleARN, awsctx.FromContext(ctx).ServicePrincipal.SourceARN)
	if err != nil {
		return "", err
	}
	out, rejected := a.Alarms.DescribeAlarms(ctx, &cloudwatchapi.DescribeAlarmsInput{AlarmNames: cloudwatchapi.AlarmNames{cloudwatchapi.AlarmName(strings.TrimPrefix(parsed.Resource, "alarm:"))}, AlarmTypes: cloudwatchapi.AlarmTypes{"MetricAlarm", "CompositeAlarm"}})
	if rejected != nil {
		return "", rejected
	}
	for _, alarm := range out.MetricAlarms {
		if appConfigString(alarm.AlarmArn) == monitor.AlarmARN {
			return appConfigString(alarm.StateValue), nil
		}
	}
	for _, alarm := range out.CompositeAlarms {
		if appConfigString(alarm.AlarmArn) == monitor.AlarmARN {
			return appConfigString(alarm.StateValue), nil
		}
	}
	return "", appConfigFailure("The CloudWatch alarm does not exist: " + monitor.AlarmARN)
}
