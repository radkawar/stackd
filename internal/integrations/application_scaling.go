package integrations

import (
	"context"
	"strings"

	"stackd/internal/apievents"
	cwapi "stackd/internal/awsapi/cloudwatch"
	ecsapi "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	aas "stackd/internal/services/applicationautoscaling"
	"stackd/internal/services/cloudwatch"
	"stackd/internal/services/ecs"
)

// ApplicationScaling joins accepted scaling changes to the owning service
// transactions. Resource owners remain the sole authority for actual capacity.
type ApplicationScaling struct {
	ECS        *ecs.Service
	DynamoDB   DynamoDBScaling
	CloudWatch *cloudwatch.Service
	Scaling    *aas.Service
	Roles      ServiceRoles
	sessions   serviceRoleSessions
}

var _ aas.Resources = (*ApplicationScaling)(nil)
var _ aas.ExecutionIdentity = (*ApplicationScaling)(nil)
var _ aas.Alarms = (*ApplicationScaling)(nil)

func (a *ApplicationScaling) Context(ctx context.Context, key aas.TargetKey, sessionName string) (context.Context, error) {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = key.Partition, key.AccountID, key.Region
	if eventID := apievents.EventID(ctx); eventID != "" {
		metadata.ParentEventID = eventID
	}
	ctx = awsctx.WithMetadata(ctx, metadata)
	principal, roleARN := aas.LinkedRole(key)
	source := awsctx.ServicePrincipal{Name: principal, SourceARN: aas.ResourceARN(key), Type: "AWSService"}
	return a.sessions.context(ctx, a.Roles, source, roleARN, sessionName, "")
}

func scalingServiceInput(key aas.TargetKey) *ecsapi.DescribeServicesInput {
	parts := strings.SplitN(key.ResourceID, "/", 3)
	return &ecsapi.DescribeServicesInput{Cluster: new(ecsapi.String(parts[1])), Services: ecsapi.StringList{ecsapi.String(parts[2])}}
}

func (a *ApplicationScaling) Admit(ctx context.Context, key aas.TargetKey) (aas.Capacity, error) {
	if key.Namespace == "dynamodb" {
		service, err := a.Context(ctx, key, "AutoScaling-VerifyServiceLinkedRole")
		if err != nil {
			return aas.Capacity{}, err
		}
		return a.Capacity(service, key)
	}
	input := scalingServiceInput(key)
	// These are real native forwarded permission probes, including the rejected
	// negative UpdateService request. Neither denial grants caller ECS authority
	// nor prevents the independent linked-role verification from succeeding.
	if _, rejected := a.ECS.DescribeServices(ctx, input); rejected != nil && rejected.StatusCode >= 500 {
		return aas.Capacity{}, rejected
	}
	if _, rejected := a.ECS.UpdateService(ctx, &ecsapi.UpdateServiceInput{Cluster: input.Cluster, Service: new(input.Services[0]), DesiredCount: new(ecsapi.BoxedInteger(-1))}); rejected != nil && rejected.StatusCode >= 500 {
		return aas.Capacity{}, rejected
	}
	service, err := a.Context(ctx, key, "AutoScaling-VerifyServiceLinkedRole")
	if err != nil {
		return aas.Capacity{}, err
	}
	return a.Capacity(service, key)
}

func (a *ApplicationScaling) Capacity(ctx context.Context, key aas.TargetKey) (aas.Capacity, error) {
	if key.Namespace == "dynamodb" {
		throughput, err := a.dynamoDBThroughput(ctx, key)
		if err != nil {
			return aas.Capacity{}, err
		}
		units := throughput.WriteCapacityUnits
		if strings.HasSuffix(key.Dimension, ":ReadCapacityUnits") {
			units = throughput.ReadCapacityUnits
		}
		count, err := dynamoDBCapacityUnits(units)
		return aas.Capacity{Desired: count, Running: count}, err
	}
	out, rejected := a.ECS.DescribeServices(ctx, scalingServiceInput(key))
	if rejected != nil {
		if rejected.Code == "ClusterNotFoundException" || rejected.Code == "ServiceNotFoundException" {
			return aas.Capacity{}, aas.ErrNotFound
		}
		return aas.Capacity{}, rejected
	}
	if len(out.Services) == 0 || out.Services[0].Status != nil && *out.Services[0].Status == "INACTIVE" {
		return aas.Capacity{}, aas.ErrNotFound
	}
	return scalingCapacity(&out.Services[0]), nil
}

func scalingCapacity(service *ecsapi.Service) aas.Capacity {
	capacity := aas.Capacity{Desired: int32(*service.DesiredCount), Running: int32(*service.RunningCount)}
	for _, deployment := range service.Deployments {
		if deployment.RolloutState != nil && *deployment.RolloutState == "IN_PROGRESS" {
			capacity.DeploymentInProgress = true
			break
		}
	}
	return capacity
}

func (a *ApplicationScaling) HighResolutionReady(ctx context.Context, key aas.TargetKey, metricName string) (bool, error) {
	if key.Namespace == "dynamodb" {
		return false, nil
	}
	ready, rejected := a.ECS.HighResolutionReady(ctx, scalingServiceInput(key), metricName)
	if rejected != nil {
		return false, rejected
	}
	return ready, nil
}

func (a *ApplicationScaling) ALBTargetGroupAttached(ctx context.Context, key aas.TargetKey, group string) (bool, error) {
	out, rejected := a.ECS.DescribeServices(ctx, scalingServiceInput(key))
	if rejected != nil {
		return false, rejected
	}
	arn := "arn:" + key.Partition + ":elasticloadbalancing:" + key.Region + ":" + key.AccountID + ":" + group
	for _, service := range out.Services {
		for _, binding := range service.LoadBalancers {
			if binding.TargetGroupArn != nil && string(*binding.TargetGroupArn) == arn {
				return true, nil
			}
		}
	}
	return false, nil
}

func (a *ApplicationScaling) SetCapacity(ctx context.Context, key aas.TargetKey, count int32) error {
	if key.Namespace == "dynamodb" {
		return a.setDynamoDBCapacity(ctx, key, count)
	}
	input := scalingServiceInput(key)
	_, rejected := a.ECS.UpdateService(ctx, &ecsapi.UpdateServiceInput{Cluster: input.Cluster, Service: new(input.Services[0]), DesiredCount: new(ecsapi.BoxedInteger(count))})
	if rejected != nil {
		return rejected
	}
	return nil
}

func (a *ApplicationScaling) Put(ctx context.Context, in *cwapi.PutMetricAlarmInput) error {
	_, rejected := a.CloudWatch.PutMetricAlarm(ctx, in)
	if rejected != nil {
		return rejected
	}
	return nil
}

func (a *ApplicationScaling) Delete(ctx context.Context, names []string) error {
	input := &cwapi.DeleteAlarmsInput{AlarmNames: make(cwapi.AlarmNames, 0, len(names))}
	for _, name := range names {
		input.AlarmNames = append(input.AlarmNames, cwapi.AlarmName(name))
	}
	_, rejected := a.CloudWatch.DeleteAlarms(ctx, input)
	if rejected != nil {
		return rejected
	}
	return nil
}

func (a *ApplicationScaling) Query(ctx context.Context, in *cwapi.GetMetricDataInput) (*cwapi.GetMetricDataOutput, error) {
	out, rejected := a.CloudWatch.GetMetricData(ctx, in)
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}

func (a *ApplicationScaling) Describe(ctx context.Context, in *cwapi.DescribeAlarmsInput) (*cwapi.DescribeAlarmsOutput, error) {
	out, rejected := a.CloudWatch.DescribeAlarms(ctx, in)
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}

func (a *ApplicationScaling) ObserveService(ctx context.Context, key ecs.ServiceKey, service *ecsapi.Service) error {
	target := aas.TargetKey{Scope: aas.Scope{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region}, Namespace: "ecs", ResourceID: "service/" + key.Name + "/" + key.ServiceName, Dimension: "ecs:service:DesiredCount"}
	if service.Status != nil && *service.Status == "INACTIVE" {
		return a.Scaling.RemoveResource(ctx, target)
	}
	return a.Scaling.ObserveCapacity(ctx, target, int32(*service.DesiredCount), int32(*service.RunningCount))
}

// ApplyAlarm accepts only CloudWatch's authenticated internal delivery context.
func (a *ApplicationScaling) ApplyAlarm(ctx context.Context, policyARN string, signal cloudwatch.ScalingAlarmSignal) *awswire.Error {
	return a.Scaling.ApplyAlarm(ctx, policyARN, signal)
}
