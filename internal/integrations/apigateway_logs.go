package integrations

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/apigatewayexec"
	"stackd/internal/services/logs"
)

// GatewayLogsAPI keeps destination state, admission and ingestion in Logs.
// Role-backed admission checks real write authority without synthetic events.
type GatewayLogsAPI interface {
	ConfigureServiceDelivery(context.Context, string) *awswire.Error
	EnsureLogGroup(context.Context, string) *awswire.Error
	EnsureLogStream(context.Context, string, string) *awswire.Error
	CheckPutLogEvents(context.Context, string, string) *awswire.Error
	PutLogEvents(context.Context, *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error)
}

// GatewayLogAccounts resolves the current regional account setting without
// authenticating the invoking client or copying account state into this adapter.
type GatewayLogAccounts interface {
	CloudWatchRole(context.Context) (string, error)
}

// GatewayLogs uses caller authority only for configuration. Delivery uses the
// HTTP Logs delivery principal or a newly assumed REST/WebSocket account role.
type GatewayLogs struct {
	Logs     GatewayLogsAPI
	Roles    ServiceRoles
	Accounts GatewayLogAccounts

	streamOnce sync.Once
	stream     string
}

var (
	_ apigatewayexec.LoggingConfiguration = (*GatewayLogs)(nil)
	_ apigatewayexec.LogPublisher         = (*GatewayLogs)(nil)
)

// ConfigureAccessLogs joins the configuring service's transaction. HTTP uses
// caller-authorized vended delivery; REST/WebSocket use the regional account role.
func (a *GatewayLogs) ConfigureAccessLogs(ctx context.Context, protocol string, settings apigatewayexec.AccessLogSettings) error {
	if settings.DestinationARN == "" && settings.Format == "" && protocol == "REST" {
		return nil
	}
	if protocol != "REST" && (settings.DestinationARN == "" || settings.Format == "") {
		return gatewayLogBadRequest("Access Log value missing. Expected destinationArn and format.")
	}
	var group string
	if settings.DestinationARN != "" {
		var err error
		group, err = gatewayLogGroup(ctx, settings.DestinationARN)
		if err != nil {
			return err
		}
	}
	var role context.Context
	// Native REST checks the regional role before the format, while V2 checks
	// format first. Malformed destination ARNs precede both prerequisites.
	if protocol == "REST" && settings.DestinationARN != "" {
		var err error
		role, err = a.loggingRoleContext(ctx)
		if err != nil {
			return err
		}
	}
	if settings.Format != "" {
		if err := apigatewayexec.ValidateAccessLogFormat(protocol, settings.Format); err != nil {
			return err
		}
	}
	if settings.DestinationARN == "" || settings.Format == "" {
		return nil
	}
	if a.Logs == nil {
		return errors.New("API Gateway CloudWatch Logs dependency is not configured")
	}
	switch protocol {
	case "HTTP":
		if wire := a.Logs.ConfigureServiceDelivery(ctx, settings.DestinationARN); wire != nil {
			return gatewayLogAdmissionError(ctx, protocol, group, wire)
		}
		return nil
	case "WEBSOCKET":
		var err error
		role, err = a.loggingRoleContext(ctx)
		if err != nil {
			return err
		}
	case "REST":
	default:
		return gatewayLogBadRequest("Unsupported API Gateway logging protocol: " + protocol)
	}
	stream := a.streamName()
	if wire := a.Logs.EnsureLogStream(gatewayLogCommand(role), group, stream); wire != nil {
		return gatewayLogAdmissionError(ctx, protocol, group, wire)
	}
	if wire := a.Logs.CheckPutLogEvents(role, group, stream); wire != nil {
		return gatewayLogAdmissionError(ctx, protocol, group, wire)
	}
	return nil
}

func (a *GatewayLogs) RequireLoggingRole(ctx context.Context) error {
	_, err := a.loggingRoleContext(ctx)
	return err
}

// ConfigureLoggingRole validates PassRole as the caller, then trust and the
// documented logging policy as API Gateway. No role credentials are cached.
func (a *GatewayLogs) ConfigureLoggingRole(ctx context.Context, roleARN string) error {
	if roleARN == "" {
		return nil
	}
	if err := gatewayLoggingRoleScope(ctx, roleARN); err != nil {
		return err
	}
	if a.Roles.Authorizer == nil {
		return errors.New("API Gateway logging role authority is not configured")
	}
	if wire := a.Roles.Authorizer.Authorize(ctx, authorization.Request{
		Action: "iam:PassRole", ResourceARN: roleARN,
		Context: map[string][]string{"iam:PassedToService": {"apigateway.amazonaws.com"}},
	}); wire != nil {
		return wire
	}
	role, err := a.assumeLoggingRole(ctx, roleARN)
	if err != nil {
		return err
	}
	// The capture rejected a policy containing these seven actions, with all
	// except DescribeLogGroups restricted to named groups. The documented
	// AmazonAPIGatewayPushToCloudWatchLogs policy succeeded on all resources.
	// TODO: Comeback measure minimum role-admission actions and resource scopes;
	// these two policies do not isolate which restrictions caused rejection.
	for _, action := range [...]string{
		"logs:CreateLogGroup", "logs:CreateLogStream", "logs:DescribeLogGroups",
		"logs:DescribeLogStreams", "logs:PutLogEvents", "logs:GetLogEvents", "logs:FilterLogEvents",
	} {
		if wire := a.Roles.Authorizer.Authorize(role, authorization.Request{Action: action, ResourceARN: "*"}); wire != nil {
			return gatewayLoggingRoleError(wire)
		}
	}
	return nil
}

func (a *GatewayLogs) loggingRoleContext(ctx context.Context) (context.Context, error) {
	if a.Accounts == nil {
		return nil, errors.New("API Gateway account logging dependency is not configured")
	}
	roleARN, err := a.Accounts.CloudWatchRole(ctx)
	if err != nil {
		return nil, err
	}
	if roleARN == "" {
		return nil, gatewayLogBadRequest("CloudWatch Logs role ARN must be set in account settings to enable logging")
	}
	return a.assumeLoggingRole(ctx, roleARN)
}

func (a *GatewayLogs) assumeLoggingRole(ctx context.Context, roleARN string) (context.Context, error) {
	// Scope and causality survive; caller identity, session policies and transport
	// attributes do not authorize the service's assumption or ingestion.
	m := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, ParentEventID: gatewayLogParent(ctx),
	})
	credential, wire := a.Roles.assume(ctx,
		awsctx.ServicePrincipal{Name: "apigateway.amazonaws.com", Type: "AssumedRole"},
		roleARN, identity.RoleSessionSpec{SessionName: "APIGatewayPushToCloudWatchLogs"}, "")
	if wire != nil {
		return nil, gatewayLoggingRoleError(wire)
	}
	role, wire := serviceRoleRequestContext(ctx, credential, m.Region, "apigateway.amazonaws.com")
	if wire != nil {
		return nil, wire
	}
	return role, nil
}

// PublishLogs writes observations supplied by execution after its state commits.
// Both channels are attempted independently; the runtime owns best-effort failure
// diagnostics and must not change the client response when this returns an error.
func (a *GatewayLogs) PublishLogs(ctx context.Context, route *apigatewayexec.Route, at time.Time, access string, execution []string) error {
	if access == "" && len(execution) == 0 {
		return nil
	}
	if a.Logs == nil {
		return errors.New("API Gateway CloudWatch Logs dependency is not configured")
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: route.Partition, AccountID: route.AccountID, Region: route.Region, ParentEventID: gatewayLogParent(ctx),
	})
	if route.ProtocolType != "HTTP" {
		if route.ProtocolType != "REST" && route.ProtocolType != "WEBSOCKET" {
			return fmt.Errorf("unsupported API Gateway logging protocol %q", route.ProtocolType)
		}
		var err error
		ctx, err = a.loggingRoleContext(ctx)
		if err != nil {
			return err
		}
	}
	var accessErr, executionErr error
	if access != "" {
		group, err := gatewayLogGroup(ctx, route.Logging.Access.DestinationARN)
		if err != nil {
			accessErr = err
		} else {
			delivery := ctx
			if route.ProtocolType == "HTTP" {
				delivery = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{
					Name: "delivery.logs.amazonaws.com", SourceARN: strings.TrimSuffix(route.Logging.Access.DestinationARN, ":*"), Type: "AWSService",
				})
				m := awsctx.FromContext(delivery)
				m.SourceIP, m.UserAgent = "delivery.logs.amazonaws.com", "delivery.logs.amazonaws.com"
				delivery = awsctx.WithMetadata(delivery, m)
			}
			accessErr = a.publish(delivery, group, at, []string{access})
		}
	}
	if len(execution) != 0 {
		var group string
		switch route.ProtocolType {
		case "REST":
			group = "API-Gateway-Execution-Logs_" + route.APIID + "/" + route.Stage
		case "WEBSOCKET":
			group = "/aws/apigateway/" + route.APIID + "/" + route.Stage
		default:
			executionErr = errors.New("execution logs are not supported on protocolType HTTP")
		}
		if group != "" {
			if wire := a.Logs.EnsureLogGroup(gatewayLogCommand(ctx), group); wire != nil {
				executionErr = wire
			} else {
				executionErr = a.publish(ctx, group, at, execution)
			}
		}
	}
	return errors.Join(accessErr, executionErr)
}

func (a *GatewayLogs) publish(ctx context.Context, group string, at time.Time, messages []string) error {
	stream := a.streamName()
	if wire := a.Logs.EnsureLogStream(gatewayLogCommand(ctx), group, stream); wire != nil {
		return wire
	}
	timestamp := api.Timestamp(at.UnixMilli())
	events := make(api.InputLogEvents, 0, min(len(messages), logs.MaxBatchEvents))
	bytes := 0
	flush := func() error {
		out, wire := a.Logs.PutLogEvents(gatewayLogCommand(ctx), &api.PutLogEventsRequest{
			LogGroupName: new(api.LogGroupName(group)), LogStreamName: new(api.LogStreamName(stream)), LogEvents: events,
		})
		if wire != nil {
			return wire
		}
		if out.RejectedLogEventsInfo != nil {
			return errors.New("CloudWatch Logs rejected API Gateway log timestamps")
		}
		events, bytes = events[:0], 0
		return nil
	}
	for _, message := range messages {
		size := len(message) + logs.EventOverheadBytes
		if size > logs.MaxBatchBytes {
			return errors.New("API Gateway log event exceeds the CloudWatch Logs size limit")
		}
		if len(events) == logs.MaxBatchEvents || bytes+size > logs.MaxBatchBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		events = append(events, api.InputLogEvent{Timestamp: &timestamp, Message: new(api.EventMessage(message))})
		bytes += size
	}
	return flush()
}

func (a *GatewayLogs) streamName() string {
	// One opaque delivery shard; stream existence remains owned by Logs.
	// TODO: Comeback model native API Gateway stream allocation and sharding once measured.
	a.streamOnce.Do(func() { a.stream = strings.ReplaceAll(uuid.NewString(), "-", "") })
	return a.stream
}

func gatewayLogGroup(ctx context.Context, destination string) (string, error) {
	if !strings.HasPrefix(destination, "arn:") {
		return "", gatewayLogBadRequest("Invalid ARN specified in the request. ARNs must start with 'arn:': " + destination)
	}
	parsed, err := arn.Parse(destination)
	if err == nil && parsed.Service == "firehose" {
		// TODO: Comeback implement native Firehose access-log delivery through its service owner.
		return "", &awswire.Error{Code: "NotImplementedException", Message: "Kinesis Data Firehose access log destinations are not implemented.", StatusCode: 501}
	}
	m := awsctx.FromContext(ctx)
	group := strings.TrimSuffix(strings.TrimPrefix(parsed.Resource, "log-group:"), ":*")
	if err != nil || parsed.Service != "logs" || parsed.Partition != m.Partition || parsed.AccountID != m.AccountID || parsed.Region != m.Region || !strings.HasPrefix(parsed.Resource, "log-group:") || len(group) == 0 || len(group) > 512 || strings.Trim(group, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.#/") != "" {
		return "", gatewayLogBadRequest("Invalid ARN specified in the request. The ARN must be a valid CloudWatch Logs log group or Kinesis Data Firehose delivery stream ARN.")
	}
	return group, nil
}

func gatewayLoggingRoleScope(ctx context.Context, roleARN string) error {
	m := awsctx.FromContext(ctx)
	role, err := arn.Parse(roleARN)
	if err != nil || role.Service != "iam" || role.Partition != m.Partition || role.Region != "" || role.AccountID != m.AccountID || !strings.HasPrefix(role.Resource, "role/") || len(role.Resource) <= len("role/") {
		return gatewayLoggingRoleError(err)
	}
	return nil
}

func gatewayLoggingRoleError(err error) error {
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.StatusCode >= 500 {
		return wire
	}
	return &awswire.Error{Code: "BadRequestException", Message: "The role ARN does not have required permissions configured. Please grant trust permission for API Gateway and add the required role policy.", StatusCode: 400, Cause: err}
}

func gatewayLogAdmissionError(ctx context.Context, protocol, group string, wire *awswire.Error) error {
	if wire.StatusCode >= 500 {
		return wire
	}
	if wire.Code == "ResourceNotFoundException" {
		message := "Cannot enable logging. LogDestination: " + group + " does not exist"
		if protocol == "HTTP" {
			message += " (Service: AWSIngestionHub; Status Code: 400; Error Code: LogDestinationNotFoundException; Request ID: " + awsctx.FromContext(ctx).RequestID + "; Proxy: null)"
		}
		return &awswire.Error{Code: "NotFoundException", Message: message, StatusCode: 404, Cause: wire}
	}
	return &awswire.Error{Code: "BadRequestException", Message: "Insufficient permissions to enable logging. " + wire.Message, StatusCode: 400, Cause: wire}
}

func gatewayLogBadRequest(message string) *awswire.Error {
	return &awswire.Error{Code: "BadRequestException", Message: message, StatusCode: 400}
}

func gatewayLogCommand(ctx context.Context) context.Context {
	m := awsctx.FromContext(ctx)
	m.RequestID = uuid.NewString()
	return awsctx.WithMetadata(ctx, m)
}

func gatewayLogParent(ctx context.Context) string {
	if parent := apievents.EventID(ctx); parent != "" {
		return parent
	}
	return awsctx.FromContext(ctx).ParentEventID
}
