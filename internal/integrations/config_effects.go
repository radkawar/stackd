package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
	lambdaapi "stackd/internal/awsapi/lambda"
	s3api "stackd/internal/awsapi/s3"
	snsapi "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/configservice"
)

// ConfigS3Commands keeps bucket policy, ACL, encryption and actual bytes in S3.
type ConfigS3Commands interface {
	S3LogCommands
	HeadBucket(context.Context, *s3api.HeadBucketInput) (*s3api.HeadBucketOutput, *awswire.Error)
}

// ConfigCapturePolicies supplies current owner policies and trusted resource
// conditions from the same typed snapshot, never from a Config JSON document.
type ConfigCapturePolicies interface {
	CapturePermission(context.Context, configservice.Item) (authorization.Request, error)
}

// ConfigEffects executes delivery and custom rules through the ordinary owners.
// Only AuthorizeCapture is permitted inside the Config/source transaction: it
// joins IAM without invoking a destination, runtime, or network operation.
type ConfigEffects struct {
	Roles     ServiceRoles
	S3        ConfigS3Commands
	SNS       SNSPublisher
	Functions FirehoseLambdaCommands
	Resources ConfigCapturePolicies
	sessions  serviceRoleSessions
}

var _ configservice.Effects = (*ConfigEffects)(nil)

func configEffectFailure(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}

func configEffectContext(ctx context.Context, scope configservice.Scope) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = scope.Partition, scope.AccountID, scope.Region
	return awsctx.WithMetadata(ctx, metadata)
}

func configDeliveryPrincipal(scope configservice.Scope) awsctx.ServicePrincipal {
	// Config documents a literal regional wildcard SourceArn for SNS/KMS
	// delivery: https://docs.aws.amazon.com/config/latest/developerguide/sns-topic-policy.html
	return awsctx.ServicePrincipal{Name: "config.amazonaws.com", SourceARN: "arn:" + scope.Partition + ":config:" + scope.Region + ":" + scope.AccountID + ":*", Type: "AWSService"}
}

func configRecorderPrincipal(recorder configservice.Recorder) awsctx.ServicePrincipal {
	return awsctx.ServicePrincipal{Name: "config.amazonaws.com", SourceARN: recorder.ARN, Type: "AWSService"}
}

func (a *ConfigEffects) ValidateRole(ctx context.Context, roleARN string) error {
	metadata := awsctx.FromContext(ctx)
	role, err := arn.Parse(roleARN)
	if err != nil || role.Partition != metadata.Partition || role.Service != "iam" || role.AccountID != metadata.AccountID || role.Region != "" || !strings.HasPrefix(role.Resource, "role/") || len(role.Resource) <= 5 {
		return configEffectFailure("InvalidRoleException", "The role is invalid. You must specify a role in this account that AWS Config can assume.")
	}
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil {
		return serviceRoleFailure(errors.New("config role authority is not configured"))
	}
	scope := configservice.Scope{Partition: metadata.Partition, AccountID: metadata.AccountID, Region: metadata.Region}
	return a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		snapshot, err := a.Roles.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			return configEffectFailure("InvalidRoleException", "The specified role does not exist or AWS Config cannot assume it.")
		}
		if rejected := a.Roles.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: roleARN, EvaluationTime: &now, Context: map[string][]string{"iam:PassedToService": {"config.amazonaws.com"}}}); rejected != nil {
			return rejected
		}
		service := awsctx.WithServicePrincipal(ctx, configDeliveryPrincipal(scope))
		if rejected := a.Roles.trust(service, snapshot, identity.RoleSessionSpec{SessionName: "AWSConfig"}, now, ""); rejected != nil {
			if rejected.StatusCode >= 500 {
				return rejected
			}
			return configEffectFailure("InvalidRoleException", "AWS Config cannot assume the specified role.")
		}
		return nil
	})
}

func (a *ConfigEffects) roleContext(ctx context.Context, recorder configservice.Recorder) (context.Context, error) {
	ctx = configEffectContext(ctx, recorder.Scope)
	return a.sessions.context(ctx, a.Roles, configRecorderPrincipal(recorder), recorder.RoleARN, "AWSConfig", "")
}

// AuthorizeCapture rechecks current trust and current role policies for the owner
// fields being observed. Repository snapshots never inherit the source caller's
// authority. IAM's transaction joins the source transaction and rolls back with it.
func (a *ConfigEffects) AuthorizeCapture(ctx context.Context, recorder configservice.Recorder, item configservice.Item) error {
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil || a.Resources == nil {
		return serviceRoleFailure(errors.New("config capture authority is not configured"))
	}
	ctx = configEffectContext(ctx, recorder.Scope)
	return a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.Roles.IAM.RoleForAssumption(ctx, recorder.RoleARN)
		if err != nil {
			return configEffectFailure("InvalidRoleException", "AWS Config cannot assume the specified role.")
		}
		if rejected := a.Roles.trust(awsctx.WithServicePrincipal(ctx, configRecorderPrincipal(recorder)), role, identity.RoleSessionSpec{SessionName: "AWSConfig"}, now, ""); rejected != nil {
			return rejected
		}
		// This is an authorization-only projection of the role resolved and
		// trust-checked above. It never issues credentials, leaves this IAM
		// transaction, or enters the external-effect session cache.
		origin := awsctx.FromContext(ctx)
		service := awsctx.WithMetadata(ctx, awsctx.Metadata{
			Partition: recorder.Partition, AccountID: recorder.AccountID, Region: recorder.Region,
			PrincipalARN: "arn:" + recorder.Partition + ":sts::" + recorder.AccountID + ":assumed-role/" + role.Name + "/AWSConfig",
			PrincipalID:  role.ID + ":AWSConfig", IssuerARN: role.ARN, IssuerID: role.ID,
			SessionType: string(identity.SessionTypeAssumeRole), TokenIssueTime: now,
			InvokedBy: "config.amazonaws.com", RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		})
		var actionBuffer [11]string
		actions := actionBuffer[:0]
		switch item.ResourceType {
		case "AWS::SQS::Queue":
			actions = append(actions, "sqs:GetQueueAttributes", "sqs:ListQueueTags")
		case "AWS::S3::Bucket":
			actions = append(actions, "s3:GetBucketLocation", "s3:GetBucketTagging")
			for _, permission := range []struct{ field, action string }{
				{"AccessControlList", "s3:GetBucketAcl"},
				{"AbacStatus", "s3:GetBucketAbac"},
				{"BucketVersioningConfiguration", "s3:GetBucketVersioning"},
				{"BucketLoggingConfiguration", "s3:GetBucketLogging"},
				{"BucketPolicy", "s3:GetBucketPolicy"},
				{"ServerSideEncryptionConfiguration", "s3:GetEncryptionConfiguration"},
				{"PublicAccessBlockConfiguration", "s3:GetBucketPublicAccessBlock"},
				{"IsRequesterPaysEnabled", "s3:GetBucketRequestPayment"},
				{"BucketAccelerateConfiguration", "s3:GetAccelerateConfiguration"},
			} {
				if _, present := item.Supplementary[permission.field]; present {
					actions = append(actions, permission.action)
				}
			}
		default:
			return configEffectFailure("ValidationException", "The resource type is not supported by the configuration recorder.")
		}
		permission, err := a.Resources.CapturePermission(service, item)
		if err != nil {
			return err
		}
		permission.EvaluationTime = &now
		for _, action := range actions {
			permission.Action = action
			if rejected := a.Roles.Authorizer.Authorize(service, permission); rejected != nil {
				return rejected
			}
		}
		return nil
	})
}

func configPermissionDenied(err *awswire.Error) bool {
	if err == nil {
		return false
	}
	switch err.Code {
	case "AccessDenied", "AccessDeniedException", "AuthorizationError", "AuthorizationErrorException", "KMS.AccessDeniedException":
		return true
	}
	return false
}

func (a *ConfigEffects) ValidateChannel(ctx context.Context, recorder configservice.Recorder, channel configservice.Channel) error {
	if a.S3 == nil {
		return serviceRoleFailure(errors.New("config S3 owner is not configured"))
	}
	if channel.TopicARN != "" {
		topic, err := arn.Parse(channel.TopicARN)
		if err != nil || topic.Partition != channel.Partition || topic.Service != "sns" || topic.Region != channel.Region || topic.AccountID == "" || topic.Resource == "" {
			return configEffectFailure("InvalidSNSTopicARNException", "The SNS topic ARN must identify a topic in the delivery channel Region.")
		}
	}
	service, err := a.roleContext(ctx, recorder)
	if err != nil {
		return err
	}
	_, headError := a.S3.HeadBucket(service, &s3api.HeadBucketInput{Bucket: new(s3api.BucketName(channel.Bucket))})
	// HeadBucket's ListBucket permission is advisory: AWS documents that a
	// delivery can succeed without it. Other failures still remain observable.
	if headError != nil && !configPermissionDenied(headError) {
		return configBucketError(headError, channel)
	}
	_, aclError := a.S3.GetBucketACL(service, &s3api.GetBucketAclInput{Bucket: new(s3api.BucketName(channel.Bucket))})
	if configPermissionDenied(aclError) {
		principal := awsctx.WithServicePrincipal(configEffectContext(ctx, channel.Scope), configDeliveryPrincipal(channel.Scope))
		_, aclError = a.S3.GetBucketACL(principal, &s3api.GetBucketAclInput{Bucket: new(s3api.BucketName(channel.Bucket))})
	}
	if aclError != nil {
		return configBucketError(aclError, channel)
	}
	prefix := channel.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	key := prefix + "AWSLogs/" + channel.AccountID + "/Config/ConfigWritabilityCheckFile"
	return a.Deliver(ctx, recorder, channel, key, nil)
}

func configBucketError(err *awswire.Error, channel configservice.Channel) *awswire.Error {
	if err.StatusCode >= 500 {
		return err
	}
	if err.Code == "NoSuchBucket" || err.Code == "NotFound" {
		return configEffectFailure("NoSuchBucketException", "The specified S3 bucket does not exist.")
	}
	return &awswire.Error{Code: "InsufficientDeliveryPolicyException", Message: "AWS Config does not have sufficient permissions to deliver to S3 bucket " + channel.Bucket + ".", StatusCode: 400, Cause: err}
}

func (a *ConfigEffects) Deliver(ctx context.Context, recorder configservice.Recorder, channel configservice.Channel, key string, body []byte) error {
	if a.S3 == nil {
		return serviceRoleFailure(errors.New("config S3 owner is not configured"))
	}
	service, err := a.roleContext(ctx, recorder)
	if err != nil {
		return err
	}
	in := &s3api.PutObjectInput{Bucket: new(s3api.BucketName(channel.Bucket)), Key: new(s3api.ObjectKey(key)), Body: body, ACL: new(s3api.ObjectCannedACL("bucket-owner-full-control")), ServerSideEncryption: new(s3api.ServerSideEncryption("AES256")), ContentType: new(s3api.ContentType("application/json")), ContentEncoding: new(s3api.ContentEncoding("gzip"))}
	if channel.KMSKeyARN != "" {
		in.ServerSideEncryption = new(s3api.ServerSideEncryption("aws:kms"))
		in.SSEKMSKeyId = new(s3api.SSEKMSKeyId(channel.KMSKeyARN))
	}
	_, rejected := a.S3.PutObject(service, in)
	// Config's documented fallback is a separately authorized owner command,
	// never a bypass of the current bucket policy or KMS policy.
	if configPermissionDenied(rejected) {
		principal := awsctx.WithServicePrincipal(configEffectContext(ctx, channel.Scope), configDeliveryPrincipal(channel.Scope))
		_, rejected = a.S3.PutObject(principal, in)
	}
	if rejected != nil {
		return configBucketError(rejected, channel)
	}
	return nil
}

func (a *ConfigEffects) Notify(ctx context.Context, recorder configservice.Recorder, channel configservice.Channel, body []byte) error {
	if channel.TopicARN == "" {
		return nil
	}
	if a.SNS == nil {
		return serviceRoleFailure(errors.New("config SNS owner is not configured"))
	}
	service, err := a.roleContext(ctx, recorder)
	if err != nil {
		return err
	}
	in := &snsapi.PublishInput{TopicArn: new(snsapi.TopicARN(channel.TopicARN)), Message: new(snsapi.Message(string(body)))}
	var notification struct {
		MessageType       string `json:"messageType"`
		ConfigurationItem struct {
			ResourceType string `json:"resourceType"`
			ResourceID   string `json:"resourceId"`
			ResourceName string `json:"resourceName"`
			Status       string `json:"configurationItemStatus"`
		} `json:"configurationItem"`
	}
	if err := json.Unmarshal(body, &notification); err != nil {
		return serviceRoleFailure(err)
	}
	subject := ""
	switch notification.MessageType {
	case "ConfigurationSnapshotDeliveryStarted":
		subject = "Configuration Snapshot Delivery Started for Account " + channel.AccountID
	case "ConfigurationSnapshotDeliveryCompleted":
		subject = "Configuration Snapshot Delivery Completed for Account " + channel.AccountID
	case "ConfigurationItemChangeNotification":
		item := notification.ConfigurationItem
		name := item.ResourceName
		if name == "" {
			name = item.ResourceID
		}
		change := "Updated"
		switch item.Status {
		case "ResourceDiscovered":
			change = "Discovered"
		case "ResourceDeleted":
			change = "Deleted"
		}
		subject = item.ResourceType + " " + name + " " + change + " in Account " + channel.AccountID
	}
	if subject != "" {
		subject = "[AWS Config:" + channel.Region + "] " + subject
		// Native subjects for the supported SQS/S3 resource names are ASCII
		// and end with an ellipsis when they exceed SNS's 100-byte limit.
		if len(subject) > 100 {
			subject = subject[:97] + "..."
		}
		in.Subject = new(snsapi.Subject(subject))
	}
	_, rejected := a.SNS.Publish(service, in)
	if configPermissionDenied(rejected) {
		principal := awsctx.WithServicePrincipal(configEffectContext(ctx, channel.Scope), configDeliveryPrincipal(channel.Scope))
		_, rejected = a.SNS.Publish(principal, in)
	}
	if rejected != nil {
		return rejected
	}
	return nil
}

func (a *ConfigEffects) InvokeRule(ctx context.Context, rule configservice.Rule, body []byte) error {
	if a.Functions == nil {
		return serviceRoleFailure(errors.New("config Lambda owner is not configured"))
	}
	ctx = awsctx.WithServicePrincipal(configEffectContext(ctx, rule.Scope), awsctx.ServicePrincipal{Name: "config.amazonaws.com", SourceARN: rule.ARN, Type: "AWSService"})
	out, _, rejected := a.Functions.Invoke(ctx, &lambdaapi.InvokeInput{FunctionName: new(lambdaapi.NamespacedFunctionName(rule.SourceIdentifier)), InvocationType: new(lambdaapi.InvocationType("RequestResponse")), Payload: body})
	if rejected != nil {
		return rejected
	}
	if out.FunctionError != nil {
		return configEffectFailure("LambdaFunctionError", "The custom Config rule function returned "+string(*out.FunctionError)+".")
	}
	return nil
}
