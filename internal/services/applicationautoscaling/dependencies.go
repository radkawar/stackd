package applicationautoscaling

import (
	"context"

	api "stackd/internal/awsapi/cloudwatch"
)

const ECSServicePrincipal = "ecs.application-autoscaling.amazonaws.com"
const DynamoDBServicePrincipal = "dynamodb.application-autoscaling.amazonaws.com"

// Capacity distinguishes accepted intent from actual running resource capacity.
// DeploymentInProgress lets ECS retain its native scale-in exclusion during a
// deployment without exposing deployment internals to the scaling controller.
type Capacity struct {
	Desired, Running     int32
	DeploymentInProgress bool
}

// Resources enters the resource owner's audited commands. Admit performs the
// native forwarded permission probes and verifies access through the linked
// role; a denied forwarded probe is not itself a denied scaling registration.
type Resources interface {
	Admit(context.Context, TargetKey) (Capacity, error)
	Capacity(context.Context, TargetKey) (Capacity, error)
	HighResolutionReady(context.Context, TargetKey, string) (bool, error)
	ALBTargetGroupAttached(context.Context, TargetKey, string) (bool, error)
	SetCapacity(context.Context, TargetKey, int32) error
}

// ExecutionIdentity supplies the linked identity for runtime changes and the
// native admission fallback, retaining the observed operation-specific session.
type ExecutionIdentity interface {
	Context(context.Context, TargetKey, string) (context.Context, error)
}

// ServiceRoles owns linked-role creation and the original caller's IAM check.
type ServiceRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// Alarms uses CloudWatch's existing command/query engine under the supplied
// authority. Calls join a supplied shared storage transaction.
type Alarms interface {
	Put(context.Context, *api.PutMetricAlarmInput) error
	Delete(context.Context, []string) error
	Query(context.Context, *api.GetMetricDataInput) (*api.GetMetricDataOutput, error)
	Describe(context.Context, *api.DescribeAlarmsInput) (*api.DescribeAlarmsOutput, error)
}
