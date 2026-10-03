package integrations

import (
	"context"
	"errors"
	"fmt"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/ssmcommands"
)

// SSMNotifications uses the current IAM authority and SNS publication owner.
// No publisher credential or policy snapshot is retained in command state.
type SSMNotifications struct {
	Roles ServiceRoles
	SNS   SNSPublisher
}

func ssmNotificationSource(cmd ssmcommands.Command) awsctx.ServicePrincipal {
	return awsctx.ServicePrincipal{Name: "ssm.amazonaws.com", Type: "AWSService", SourceARN: fmt.Sprintf("arn:%s:ssm:%s:%s:command/%s", cmd.Key.Partition, cmd.Key.Region, cmd.Key.AccountID, cmd.Key.ID)}
}
func (a *SSMNotifications) Validate(ctx context.Context, cmd ssmcommands.Command) (string, error) {
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil {
		return "", errors.New("SSM notification IAM authority is not configured")
	}
	var roleID string
	err := a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.Roles.IAM.RoleForAssumption(ctx, cmd.ServiceRoleARN)
		if err != nil {
			return ssmNotificationRoleError()
		}
		source := ssmNotificationSource(cmd)
		if denied := a.Roles.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: role.ARN, ResourceAccountID: cmd.Key.AccountID, EvaluationTime: &now, Context: map[string][]string{"iam:PassedToService": {"ssm.amazonaws.com"}, "iam:AssociatedResourceArn": {source.SourceARN}}}); denied != nil {
			return denied
		}
		if denied := a.Roles.trust(awsctx.WithServicePrincipal(ctx, source), role, identity.RoleSessionSpec{SessionName: "SSM-RunCommand"}, now, ""); denied != nil {
			return ssmNotificationRoleError()
		}
		roleID = role.ID
		return nil
	})
	return roleID, err
}
func ssmNotificationRoleError() *awswire.Error {
	return &awswire.Error{Code: "InvalidRole", Message: "Systems Manager cannot assume the service role.", StatusCode: 400}
}
func (a *SSMNotifications) Publish(ctx context.Context, cmd ssmcommands.Command, body []byte) (string, error) {
	if a.SNS == nil {
		return "", errors.New("SSM notification SNS owner is not configured")
	}
	credential, denied := a.Roles.assume(ctx, ssmNotificationSource(cmd), cmd.ServiceRoleARN, identity.RoleSessionSpec{SessionName: "SSM-RunCommand", Role: identity.Principal{ID: cmd.ServiceRoleID}}, "")
	if denied != nil {
		return "", denied
	}
	ctx, denied = serviceRoleRequestContext(ctx, credential, cmd.Key.Region, "ssm.amazonaws.com")
	if denied != nil {
		return "", denied
	}
	out, denied := a.SNS.Publish(ctx, &api.PublishInput{TopicArn: new(api.TopicARN(cmd.NotificationARN)), Message: new(api.Message(body)), Subject: new(api.Subject("EC2 Run Command Notification " + cmd.Key.Region))})
	if denied != nil {
		return "", denied
	}
	if out == nil || out.MessageId == nil {
		return "", errors.New("SNS did not return publication acceptance")
	}
	return string(*out.MessageId), nil
}

var _ ssmcommands.Notifications = (*SSMNotifications)(nil)
