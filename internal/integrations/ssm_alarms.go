package integrations

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/ssmcommands"
)

// SSMAlarms monitors through the current Systems Manager service-linked role,
// never the sending user or the optional SNS notification role.
type SSMAlarms struct {
	CloudWatch  AppConfigAlarms
	Roles       ServiceRoles
	Provisioner interface {
		EnsureServiceLinkedRole(context.Context, string) error
	}
}

func ssmAlarmRoleARN(cmd ssmcommands.Command) string {
	return "arn:" + cmd.Key.Partition + ":iam::" + cmd.Key.AccountID + ":role/aws-service-role/ssm.amazonaws.com/AWSServiceRoleForAmazonSSM"
}

func (a *SSMAlarms) Prepare(ctx context.Context, cmd ssmcommands.Command) (string, error) {
	if a.Provisioner == nil || a.Roles.IAM == nil {
		return "", errors.New("SSM alarm IAM authority is not configured")
	}
	m := awsctx.FromContext(ctx)
	m.InvokedBy = "ssm.amazonaws.com"
	ctx = awsctx.WithMetadata(ctx, m)
	if err := a.Provisioner.EnsureServiceLinkedRole(ctx, "ssm.amazonaws.com"); err != nil {
		return "", err
	}
	role, err := a.Roles.IAM.RoleForAssumption(ctx, ssmAlarmRoleARN(cmd))
	if err != nil {
		return "", err
	}
	return role.ID, nil
}

func (a *SSMAlarms) State(ctx context.Context, cmd ssmcommands.Command) (string, error) {
	if a.CloudWatch == nil {
		return "", errors.New("SSM alarm CloudWatch owner is not configured")
	}
	credential, denied := a.Roles.assume(ctx, ssmNotificationSource(cmd), ssmAlarmRoleARN(cmd), identity.RoleSessionSpec{SessionName: "SSM-RunCommand", Role: identity.Principal{ID: cmd.AlarmPoll.RoleID}}, "")
	if denied != nil {
		return "", denied
	}
	ctx, denied = serviceRoleRequestContext(ctx, credential, cmd.Key.Region, "ssm.amazonaws.com")
	if denied != nil {
		return "", denied
	}
	out, denied := a.CloudWatch.DescribeAlarms(ctx, &api.DescribeAlarmsInput{AlarmNames: api.AlarmNames{api.AlarmName(cmd.Alarm.Name)}, AlarmTypes: api.AlarmTypes{"MetricAlarm", "CompositeAlarm"}})
	if denied != nil {
		return "", denied
	}
	for _, alarm := range out.MetricAlarms {
		if appConfigString(alarm.AlarmName) == cmd.Alarm.Name {
			return appConfigString(alarm.StateValue), nil
		}
	}
	for _, alarm := range out.CompositeAlarms {
		if appConfigString(alarm.AlarmName) == cmd.Alarm.Name {
			return appConfigString(alarm.StateValue), nil
		}
	}
	return "UNKNOWN", nil
}

var _ ssmcommands.Alarms = (*SSMAlarms)(nil)
