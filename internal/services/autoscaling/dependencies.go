package autoscaling

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/autoscaling"
	cwapi "stackd/internal/awsapi/cloudwatch"
	ec2api "stackd/internal/awsapi/ec2"
)

const ServicePrincipal = "autoscaling.amazonaws.com"

// ErrInstanceHibernationNotReady means EC2 rejected the stop before any power
// effect because the guest's hibernation agent is not ready yet.
var ErrInstanceHibernationNotReady = errors.New("autoscaling: instance hibernation is not ready")

// Instances enters EC2's current-authority commands; no EC2 repository is exposed.
// Template returns both native identifiers and the selected version. Placement
// resolves the actual scoped subnets rather than inventing zone metadata.
type Instances interface {
	Template(context.Context, api.LaunchTemplateSpecification) (api.LaunchTemplateSpecification, error)
	Placement(context.Context, []string, []string) ([]ec2api.Subnet, error)
	// Admit performs RunInstances DryRun as the original group caller.
	Admit(context.Context, GroupRecord) error
	ValidateWarmPool(context.Context, GroupRecord) error
	Launch(context.Context, GroupRecord, ActivityRecord) (ec2api.Instance, error)
	Observe(context.Context, []string) ([]InstanceObservation, error)
	Terminate(context.Context, string) error
	Start(context.Context, string) error
	Stop(context.Context, string, bool) error
	SetGroup(context.Context, string, string) error
}

type InstanceObservation struct {
	Instance ec2api.Instance
	Healthy  bool
}

// ExecutionIdentity uses the group's configured linked role, with the immutable
// group ARN as source. Cached credentials never bypass current role evaluation.
type ExecutionIdentity interface {
	Context(context.Context, GroupRecord) (context.Context, error)
}

type ServiceRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// TargetGroups owns ALB registration, health and drain. A stopped group must not
// release its EC2 instance before existing target traffic has drained.
// Membership methods take groupARN, targetGroupARN, and instanceID, in that order.
type TargetGroups interface {
	Validate(context.Context, []string, []ec2api.Subnet) error
	Register(context.Context, string, string, string) error
	Healthy(context.Context, string, string, string) (bool, error)
	Deregister(context.Context, string, string, string) error
	Drained(context.Context, string, string, string) (bool, error)
}

// Events publishes the documented service edge in the same transaction as the
// membership transition. Notification delivery remains owned by SNS/SQS adapters.
type Events interface {
	Publish(context.Context, GroupRecord, string, []byte) error
	Notify(context.Context, HookRecord, []byte) error
}

type MetricPublisher interface {
	Publish(context.Context, string, []cwapi.MetricDatum) error
}

// Alarms reuses CloudWatch admission, querying and current metric evaluation.
type Alarms interface {
	Put(context.Context, *cwapi.PutMetricAlarmInput) error
	Delete(context.Context, []string) error
	Query(context.Context, *cwapi.GetMetricDataInput) (*cwapi.GetMetricDataOutput, error)
	Describe(context.Context, *cwapi.DescribeAlarmsInput) (*cwapi.DescribeAlarmsOutput, error)
}
