package ecs

import (
	"context"
	"errors"
	"net/netip"
	"time"

	api "stackd/internal/awsapi/ecs"
)

// ServiceTarget identifies one task incarnation, never just a reusable IP address.
// Adapters must fence registration and every delivery by current ENI ownership.
type ServiceTarget struct {
	TargetGroupARN, TaskARN, AttachmentARN, NetworkInterfaceID, PrivateIP string
	Port                                                                  int32
}

type ServiceTargetHealth string

const (
	ServiceTargetInitial   ServiceTargetHealth = "initial"
	ServiceTargetHealthy   ServiceTargetHealth = "healthy"
	ServiceTargetUnhealthy ServiceTargetHealth = "unhealthy"
)

// ServiceLoadBalancers owns no ELB state. Every operation uses the current ECS
// service-linked role; registration and drain effects run outside ECS transactions.
// Register is idempotent without resetting health; deregistration cannot remove a
// different incarnation. Drained becomes true only after old traffic has finished.
type ServiceLoadBalancers interface {
	Validate(context.Context, string, api.AwsVpcConfiguration, api.LoadBalancers) error
	Register(context.Context, ServiceTarget) error
	Health(context.Context, ServiceTarget) (ServiceTargetHealth, error)
	Deregister(context.Context, ServiceTarget) error
	Drained(context.Context, ServiceTarget) (bool, error)
}

func (s *Service) validateServiceLoadBalancers(ctx context.Context, record ServiceRecord, definition api.TaskDefinition) error {
	bindings := record.Data.LoadBalancers
	if len(bindings) == 0 {
		return nil
	}
	if len(bindings) > 5 {
		return failure("InvalidParameterException", "A service can have at most five target groups.")
	}
	if value(definition.NetworkMode) != "awsvpc" {
		return unsupported("Service load balancing requires awsvpc networking and ALB IP target groups.")
	}
	seen := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		if value(binding.LoadBalancerName) != "" || binding.AdvancedConfiguration != nil {
			return unsupported("Classic load balancers and advanced load balancer deployments are not supported.")
		}
		arn := value(binding.TargetGroupArn)
		if arn == "" || seen[arn] {
			return failure("InvalidParameterException", "Each load balancer must specify a distinct target group ARN.")
		}
		seen[arn] = true
		if binding.ContainerPort == nil || *binding.ContainerPort < 1 || *binding.ContainerPort > 65535 {
			return failure("InvalidParameterException", "The load balancer container port must be between 1 and 65535.")
		}
		found := false
		for _, container := range definition.ContainerDefinitions {
			if value(container.Name) != value(binding.ContainerName) {
				continue
			}
			for _, port := range container.PortMappings {
				if port.ContainerPort != nil && *port.ContainerPort == *binding.ContainerPort && (value(port.Protocol) == "" || value(port.Protocol) == "tcp") {
					found = true
				}
			}
		}
		if !found {
			return failure("InvalidParameterException", "The load balancer container name and TCP port must match a port mapping in the task definition.")
		}
	}
	if s.loadBalancers == nil {
		return unsupported("Service load balancer lifecycle is not configured.")
	}
	if record.Data.NetworkConfiguration == nil || record.Data.NetworkConfiguration.AwsvpcConfiguration == nil {
		return failure("InvalidParameterException", "Load balanced services require an awsvpc network configuration.")
	}
	return s.loadBalancers.Validate(serviceOwnerContext(ctx, record), record.Key.ARN(), *record.Data.NetworkConfiguration.AwsvpcConfiguration, bindings)
}

func taskServiceTargets(task TaskRecord, bindings api.LoadBalancers) ([]ServiceTarget, error) {
	if len(bindings) == 0 {
		return nil, nil
	}
	var attachment *api.Attachment
	for i := range task.Data.Attachments {
		if value(task.Data.Attachments[i].Type) == "ElasticNetworkInterface" {
			attachment = &task.Data.Attachments[i]
			break
		}
	}
	if attachment == nil {
		return nil, errors.New("ECS load balanced task has no network attachment")
	}
	if value(attachment.Status) == "PRECREATED" {
		return nil, nil
	}
	identity := ServiceTarget{TaskARN: task.Key.ARN(), AttachmentARN: "arn:" + task.Key.Partition + ":ecs:" + task.Key.Region + ":" + task.Key.AccountID + ":attachment/" + value(attachment.Id)}
	for _, detail := range attachment.Details {
		switch value(detail.Name) {
		case "networkInterfaceId":
			identity.NetworkInterfaceID = value(detail.Value)
		case "privateIPv4Address":
			identity.PrivateIP = value(detail.Value)
		}
	}
	ip, err := netip.ParseAddr(identity.PrivateIP)
	if err != nil || !ip.Is4() || identity.NetworkInterfaceID == "" || value(attachment.Id) == "" {
		return nil, errors.New("ECS load balanced task has an incomplete ENI identity")
	}
	out := make([]ServiceTarget, len(bindings))
	for i, binding := range bindings {
		if binding.ContainerPort == nil {
			return nil, errors.New("ECS deployment has no target container port")
		}
		out[i] = identity
		out[i].TargetGroupARN = value(binding.TargetGroupArn)
		out[i].Port = int32(*binding.ContainerPort)
	}
	return out, nil
}

func (s *Service) taskLoadBalancerBindings(ctx context.Context, task TaskRecord) (api.LoadBalancers, error) {
	if task.ServiceName == "" {
		return nil, nil
	}
	var bindings api.LoadBalancers
	err := s.repository.View(ctx, func(r Reader) error {
		service, err := r.Service(ServiceKey{ClusterKey: task.Key.ClusterKey, ServiceName: task.ServiceName})
		if err != nil {
			return err
		}
		for _, deployment := range service.Deployments {
			if value(deployment.Data.Id) == task.ServiceDeploymentID {
				bindings = deployment.LoadBalancers
				return nil
			}
		}
		return errors.New("ECS task deployment ownership is missing")
	})
	return bindings, err
}

func (e *taskExecution) registerTargets(task TaskRecord) error {
	if value(task.Data.LastStatus) != "RUNNING" || value(task.Data.DesiredStatus) != "RUNNING" {
		return nil
	}
	bindings, err := e.service.taskLoadBalancerBindings(e.ctx, task)
	if err != nil || len(bindings) == 0 {
		return err
	}
	if e.service.loadBalancers == nil {
		return errors.New("ECS target lifecycle is not configured")
	}
	targets, err := taskServiceTargets(task, bindings)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := e.service.loadBalancers.Register(taskOwnerContext(e.ctx, task), target); err != nil {
			return err
		}
	}
	return nil
}

func (e *taskExecution) drainTargets(task TaskRecord) (bool, error) {
	bindings, err := e.service.taskLoadBalancerBindings(e.ctx, task)
	if err != nil || len(bindings) == 0 {
		return err == nil, err
	}
	targets, err := taskServiceTargets(task, bindings)
	if err != nil || len(targets) == 0 {
		return err == nil, err
	}
	if e.service.loadBalancers == nil {
		return false, errors.New("ECS target lifecycle is not configured")
	}
	drained := true
	ctx := taskOwnerContext(e.ctx, task)
	for _, target := range targets {
		if err := e.service.loadBalancers.Deregister(ctx, target); err != nil {
			return false, err
		}
		done, err := e.service.loadBalancers.Drained(ctx, target)
		if err != nil {
			return false, err
		}
		drained = drained && done
	}
	return drained, nil
}

// Health is sampled before entering the scheduler transaction. Comparable exact
// identities prevent an observation from authorizing a changed task/ENI binding.
func (s *Service) serviceTargetHealth(ctx context.Context, key ServiceKey) (map[ServiceTarget]ServiceTargetHealth, error) {
	var service ServiceRecord
	var tasks []TaskRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		service, err = r.Service(key)
		if err != nil {
			return err
		}
		tasks, err = r.Tasks(TaskQuery{ClusterKey: key.ClusterKey, ServiceName: key.ServiceName, ActiveOnly: true})
		return err
	})
	if err != nil || value(service.Data.Status) != "ACTIVE" {
		return nil, err
	}
	var out map[ServiceTarget]ServiceTargetHealth
	for _, task := range tasks {
		if value(task.Data.LastStatus) != "RUNNING" || value(task.Data.DesiredStatus) != "RUNNING" {
			continue
		}
		for _, deployment := range service.Deployments {
			if value(deployment.Data.Id) != task.ServiceDeploymentID || len(deployment.LoadBalancers) == 0 {
				continue
			}
			targets, err := taskServiceTargets(task, deployment.LoadBalancers)
			if err != nil {
				return nil, err
			}
			if s.loadBalancers == nil {
				return nil, errors.New("ECS target lifecycle is not configured")
			}
			if out == nil {
				out = make(map[ServiceTarget]ServiceTargetHealth)
			}
			for _, target := range targets {
				health, err := s.loadBalancers.Health(taskOwnerContext(ctx, task), target)
				if err != nil {
					return nil, err
				}
				out[target] = health
			}
		}
	}
	return out, nil
}

func replicaTargetHealth(task TaskRecord, bindings api.LoadBalancers, observed map[ServiceTarget]ServiceTargetHealth, grace time.Duration, now time.Time) (bool, bool) {
	targets, err := taskServiceTargets(task, bindings)
	if err != nil || len(targets) != len(bindings) {
		return false, false
	}
	healthy, unhealthy := true, false
	for _, target := range targets {
		state := observed[target]
		healthy = healthy && state == ServiceTargetHealthy
		unhealthy = unhealthy || state == ServiceTargetUnhealthy
	}
	return healthy, unhealthy && task.Data.StartedAt != nil && !now.Before(task.Data.StartedAt.Add(grace))
}
