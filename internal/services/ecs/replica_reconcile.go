package ecs

import (
	"context"
	"reflect"
	"slices"
	api "stackd/internal/awsapi/ecs"
	"strings"
	"time"
)

type replicaTask struct {
	record             TaskRecord
	deployment         int
	healthy, unhealthy bool
}

func (s *Service) reconcileService(ctx context.Context, tx Transaction, r *ServiceRecord, targetHealth map[ServiceTarget]ServiceTargetHealth) (bool, error) {
	before := cloneServiceRecord(*r)
	tasks, err := tx.Tasks(TaskQuery{ClusterKey: r.Key.ClusterKey, ServiceName: r.Key.ServiceName})
	if err != nil {
		return false, err
	}
	now := s.clock.Now().Truncate(time.Millisecond)
	desired := int(*r.Data.DesiredCount)
	primary := -1
	byID := make(map[string]int, len(r.Deployments))
	for i := range r.Deployments {
		d := &r.Deployments[i]
		byID[value(d.Data.Id)] = i
		d.Data.RunningCount = new(api.Integer(0))
		d.Data.PendingCount = new(api.Integer(0))
		d.Deadline = time.Time{}
		if value(d.Data.Status) == "PRIMARY" {
			primary = i
			d.Data.DesiredCount = new(api.Integer(desired))
		}
		if d.ObservedTasks == nil {
			d.ObservedTasks = map[string]string{}
		}
	}
	if primary < 0 {
		return false, failure("ServerException", "Service has no primary deployment.", 500)
	}
	var live []replicaTask
	healthyTotal := 0
	changedTasks := false
	r.Data.RunningCount = new(api.Integer(0))
	r.Data.PendingCount = new(api.Integer(0))
	// Replay newly observed transitions chronologically after recovery. Random
	// task IDs must not determine whether a later healthy task resets failures.
	tasks = slices.DeleteFunc(tasks, func(t TaskRecord) bool {
		_, owned := byID[t.ServiceDeploymentID]
		return !owned
	})
	slices.SortStableFunc(tasks, func(a, b TaskRecord) int {
		return replicaObservationTime(a, r.Deployments[byID[a.ServiceDeploymentID]].LoadBalancers, now).Compare(replicaObservationTime(b, r.Deployments[byID[b.ServiceDeploymentID]].LoadBalancers, now))
	})
	for _, task := range tasks {
		at := byID[task.ServiceDeploymentID]
		d := &r.Deployments[at]
		healthy, unhealthy := replicaHealth(task, r.Data, d.LoadBalancers, targetHealth, now)
		deadline := replicaReadinessDeadline(task, r.Data, d.LoadBalancers)
		if deadline.After(now) && (d.Deadline.IsZero() || deadline.Before(d.Deadline)) {
			d.Deadline = deadline
		}
		observation := d.ObservedTasks[task.Key.ID]
		failed := value(task.Data.StopCode) == "TaskFailedToStart" || value(task.Data.StopCode) == "EssentialContainerExited" || unhealthy
		if failed && observation != "failed" && value(task.Data.StopCode) != "UserInitiated" {
			if !d.Completed {
				d.Failures++
			}
			d.ObservedTasks[task.Key.ID] = "failed"
			d.RetryAfter = now.Add(time.Second)
		} else if healthy && observation != "healthy" {
			d.ObservedTasks[task.Key.ID] = "healthy"
			breaker := r.Data.DeploymentConfiguration.DeploymentCircuitBreaker
			if breaker == nil || breaker.ResetOnHealthyTask == nil || bool(*breaker.ResetOnHealthyTask) {
				d.Failures = 0
			}
		}
		d.Data.FailedTasks = new(api.Integer(d.Failures))
		if value(task.Data.LastStatus) == "STOPPED" {
			continue
		}
		if value(task.Data.LastStatus) == "RUNNING" {
			*d.Data.RunningCount++
			*r.Data.RunningCount++
		} else if value(task.Data.DesiredStatus) == "RUNNING" {
			*d.Data.PendingCount++
			*r.Data.PendingCount++
		}
		live = append(live, replicaTask{task, at, healthy, unhealthy})
		if healthy && value(task.Data.DesiredStatus) == "RUNNING" {
			healthyTotal++
		}
	}
	stop := func(at int, reason string, replacing bool) error {
		t := &live[at]
		if value(t.record.Data.DesiredStatus) == "STOPPED" {
			return nil
		}
		if t.healthy {
			healthyTotal--
		}
		if !replacing && t.deployment != primary {
			dep := &r.Deployments[t.deployment]
			dep.Data.DesiredCount = new(api.Integer(max(0, int(*dep.Data.DesiredCount)-1)))
		}
		t.record.AcceptedEventID = r.AcceptedEventID
		t.record.Data.DesiredStatus = new(api.String("STOPPED"))
		t.record.Data.StopCode = new(api.TaskStopCode("ServiceSchedulerInitiated"))
		t.record.Data.StoppedReason = new(api.String(reason))
		t.record.Data.StoppingAt = new(now)
		changedTasks = true
		return s.putTaskTransition(ctx, tx, &t.record)
	}
	if value(r.Data.Status) == "DRAINING" {
		for i := range live {
			if err := stop(i, "Service was deleted", false); err != nil {
				return false, err
			}
		}
		if len(live) == 0 && !now.Before(r.DrainAfter) {
			r.Data.Status = new(api.String("INACTIVE"))
			r.Deployments = nil
			r.Data.Deployments = api.Deployments{}
		}
		return s.persistReplica(ctx, tx, r, before, changedTasks)
	}
	d := &r.Deployments[primary]
	breaker := r.Data.DeploymentConfiguration.DeploymentCircuitBreaker
	if !d.Completed && value(d.Data.RolloutState) != "FAILED" && breaker != nil && breaker.Enable != nil && bool(*breaker.Enable) && d.Failures >= replicaFailureThreshold(breaker, desired) {
		d.Data.RolloutState = new(api.DeploymentRolloutState("FAILED"))
		d.Data.RolloutStateReason = new(api.String("ECS deployment circuit breaker: tasks failed to start or remain healthy."))
		d.Data.UpdatedAt = new(now)
		if err := s.publishServiceEvent(ctx, r, "SERVICE_DEPLOYMENT_FAILED", value(d.Data.Id), value(d.Data.RolloutStateReason)); err != nil {
			return false, err
		}
		if breaker.Rollback != nil && bool(*breaker.Rollback) {
			rollback := -1
			for i := range r.Deployments {
				candidate := &r.Deployments[i]
				if i != primary && candidate.Completed && value(candidate.Data.RolloutState) == "COMPLETED" && (rollback < 0 || candidate.Data.CreatedAt.After(*r.Deployments[rollback].Data.CreatedAt)) {
					rollback = i
				}
			}
			if rollback >= 0 {
				d.Data.Status = new(api.String("ACTIVE"))
				primary = rollback
				d = &r.Deployments[primary]
				d.Completed = false
				d.Failures = 0
				d.RetryAfter = time.Time{}
				d.Data.Status = new(api.String("PRIMARY"))
				d.Data.RolloutState = new(api.DeploymentRolloutState("IN_PROGRESS"))
				d.Data.RolloutStateReason = new(api.String("Rolling back to the last completed deployment."))
				d.Data.UpdatedAt = new(now)
				d.Data.DesiredCount = new(api.Integer(desired))
				r.Data.TaskDefinition = d.Definition.TaskDefinitionArn
				r.Data.NetworkConfiguration = d.Input.NetworkConfiguration
				r.Data.PlatformVersion = d.Input.PlatformVersion
				r.Data.LaunchType = d.Input.LaunchType
				r.Data.CapacityProviderStrategy = d.Input.CapacityProviderStrategy
				r.Data.LoadBalancers = api.CloneLoadBalancers(d.LoadBalancers)
				if err := s.publishServiceEvent(ctx, r, "SERVICE_DEPLOYMENT_IN_PROGRESS", value(d.Data.Id), value(d.Data.RolloutStateReason)); err != nil {
					return false, err
				}
			}
		}
	}
	maximum := desired * int(*r.Data.DeploymentConfiguration.MaximumPercent) / 100
	minimum := (desired*int(*r.Data.DeploymentConfiguration.MinimumHealthyPercent) + 99) / 100
	liveDesired := 0
	primaryDesired := 0
	primaryHealthy := 0
	for _, t := range live {
		if value(t.record.Data.DesiredStatus) == "RUNNING" {
			liveDesired++
			if t.deployment == primary {
				primaryDesired++
				if t.healthy {
					primaryHealthy++
				}
			}
		}
	}
	zoneCounts := map[string]int{}
	for _, t := range live {
		zoneCounts[value(t.record.Data.AvailabilityZone)]++
	}
	slices.SortStableFunc(live, func(a, b replicaTask) int {
		return zoneCounts[value(a.record.Data.AvailabilityZone)] - zoneCounts[value(b.record.Data.AvailabilityZone)]
	})
	// Scale-down does not wait for a new revision. Retire old deployment tasks
	// first, then excess primary tasks, without touching stopped task history.
	for pass := range 2 {
		for i := len(live) - 1; i >= 0 && liveDesired > desired; i-- {
			t := &live[i]
			if value(t.record.Data.DesiredStatus) != "RUNNING" || (pass == 0) == (t.deployment == primary) {
				continue
			}
			if t.deployment == primary && (primaryDesired <= desired || healthyTotal < desired) {
				continue
			}
			if t.healthy && healthyTotal-1 < minimum {
				continue
			}
			if desired > 0 && !t.healthy && !t.unhealthy && healthyTotal <= desired {
				continue
			}
			if err := stop(i, "Scaling activity initiated by the ECS service scheduler", false); err != nil {
				return false, err
			}
			liveDesired--
			if t.deployment == primary {
				primaryDesired--
			}
		}
	}
	// Unhealthy source tasks retain source revision ownership. Prefer creating a
	// replacement within surge capacity before stopping the unhealthy process.
	for i := range live {
		t := &live[i]
		if !t.unhealthy || value(t.record.Data.DesiredStatus) != "RUNNING" {
			continue
		}
		target := int(*r.Deployments[t.deployment].Data.DesiredCount)
		ready, pending := 0, 0
		for _, other := range live {
			if other.deployment == t.deployment && other.record.Key != t.record.Key && value(other.record.Data.DesiredStatus) == "RUNNING" {
				if other.healthy {
					ready++
				} else if !other.unhealthy {
					pending++
				}
			}
		}
		replacementReady, replacementPending := ready >= target, ready+pending >= target
		if len(live) < maximum && !replacementReady && !replacementPending && value(r.Deployments[t.deployment].Data.RolloutState) != "FAILED" {
			launched, err := s.launchReplicaTask(ctx, tx, r, t.deployment, &live, now)
			if err != nil {
				return false, err
			}
			if launched {
				changedTasks = true
				liveDesired++
				replacementPending = true
				if t.deployment == primary {
					primaryDesired++
				}
			}
		}
		if replacementReady || !replacementPending && len(live) >= maximum || maximum == 0 || value(r.Deployments[t.deployment].Data.RolloutState) == "FAILED" {
			if err := stop(i, "Task failed container or load balancer health checks", true); err != nil {
				return false, err
			}
			liveDesired--
			if t.deployment == primary {
				primaryDesired--
			}
		}
	}
	// A max=100 rollout frees capacity only as permitted by the rounded-up
	// minimum healthy limit. STOPPING tasks occupy surge slots until released.
	if primaryDesired < desired && len(live) >= maximum {
		for i := range live {
			t := &live[i]
			if t.deployment == primary || value(t.record.Data.DesiredStatus) != "RUNNING" {
				continue
			}
			if t.healthy && healthyTotal-1 < minimum {
				continue
			}
			if err := stop(i, "Deployment replaced by the ECS service scheduler", false); err != nil {
				return false, err
			}
			liveDesired--
			break
		}
		if !changedTasks && primaryDesired == primaryHealthy && healthyTotal == liveDesired && liveDesired == len(live) {
			reason := "Service was unable to stop or start tasks during a deployment because of the service deployment configuration. Update minimumHealthyPercent or maximumPercent."
			deployment := &r.Deployments[primary]
			if value(deployment.Data.RolloutStateReason) != reason && value(deployment.Data.RolloutState) != "FAILED" {
				deployment.Data.RolloutStateReason = new(api.String(reason))
				if err := s.publishServiceEvent(ctx, r, "SERVICE_TASK_CONFIGURATION_FAILURE", value(deployment.Data.Id), reason); err != nil {
					return false, err
				}
			}
		}
	}
	if value(r.Deployments[primary].Data.RolloutState) != "FAILED" {
		slots := max(0, maximum-len(live))
		// A stable service at maximumPercent=100 must still replace stopped tasks.
		for primaryDesired < desired && slots > 0 {
			launched, err := s.launchReplicaTask(ctx, tx, r, primary, &live, now)
			if err != nil {
				return false, err
			}
			if !launched {
				break
			}
			changedTasks = true
			primaryDesired++
			liveDesired++
			slots--
		}
	}
	if value(r.Data.AvailabilityZoneRebalancing) == "ENABLED" && primaryHealthy == desired && primaryDesired == desired && desired > 0 && len(live) == desired && len(live) < maximum {
		cluster, err := tx.Cluster(r.Key.ClusterKey)
		if err != nil {
			return false, err
		}
		_, unbalanced, err := s.replicaPlacement(ctx, cluster, r.Deployments[primary].Input, live)
		if err != nil {
			return false, err
		}
		if unbalanced {
			launched, err := s.launchReplicaTask(ctx, tx, r, primary, &live, now)
			if err != nil {
				return false, err
			}
			if launched {
				changedTasks = true
				primaryDesired++
			}
		}
	}
	// Complete only after old processes are fully gone and all desired primary
	// tasks satisfy their immutable container and target-group health contract.
	oldLive := false
	for _, t := range live {
		if t.deployment != primary {
			oldLive = true
		}
	}
	d = &r.Deployments[primary]
	if primaryHealthy == desired && primaryDesired == desired && !oldLive && !changedTasks && value(d.Data.RolloutState) != "FAILED" && !d.Completed {
		d.Completed = true
		d.Data.RolloutState = new(api.DeploymentRolloutState("COMPLETED"))
		d.Data.RolloutStateReason = new(api.String("ECS deployment completed."))
		d.Data.UpdatedAt = new(now)
		if err := s.publishServiceEvent(ctx, r, "SERVICE_DEPLOYMENT_COMPLETED", value(d.Data.Id), ""); err != nil {
			return false, err
		}
		if err := s.publishServiceEvent(ctx, r, "SERVICE_STEADY_STATE", value(d.Data.Id), ""); err != nil {
			return false, err
		}
	}
	// Retain one execution baseline for rollback plus deployments owning live
	// tasks. Archive other revisions before releasing their definition ownership.
	baseline := -1
	for i := range r.Deployments {
		x := &r.Deployments[i]
		if i != primary && x.Completed && (baseline < 0 || x.Data.CreatedAt.After(*r.Deployments[baseline].Data.CreatedAt)) {
			baseline = i
		}
	}
	retained := r.Deployments[:0]
	for i, dep := range r.Deployments {
		owns := slices.ContainsFunc(live, func(t replicaTask) bool { return t.deployment == i })
		if i != primary && !owns && i != baseline {
			if err := tx.PutServiceRevision(serviceRevision(*r, dep)); err != nil {
				return false, err
			}
			continue
		}
		if i != primary && !owns {
			dep.Data.Status = new(api.String("INACTIVE"))
		}
		retained = append(retained, dep)
	}
	r.Deployments = retained
	return s.persistReplica(ctx, tx, r, before, changedTasks)
}

func (s *Service) persistReplica(ctx context.Context, tx Transaction, r *ServiceRecord, before ServiceRecord, tasksChanged bool) (bool, error) {
	if reflect.DeepEqual(before, *r) {
		return tasksChanged, nil
	}
	if err := s.putService(tx, *r); err != nil {
		return false, err
	}
	if err := s.reapTaskDefinitions(tx, r.Key.Scope); err != nil {
		return false, err
	}
	return tasksChanged, nil
}

func replicaHealth(t TaskRecord, service api.Service, bindings api.LoadBalancers, targetHealth map[ServiceTarget]ServiceTargetHealth, now time.Time) (healthy, unhealthy bool) {
	if value(t.Data.LastStatus) != "RUNNING" || value(t.Data.DesiredStatus) != "RUNNING" || t.Data.StartedAt == nil {
		return false, false
	}
	grace := time.Duration(0)
	if service.HealthCheckGracePeriodSeconds != nil {
		grace = time.Duration(*service.HealthCheckGracePeriodSeconds) * time.Second
	}
	hasHealth := false
	for _, c := range t.Definition.ContainerDefinitions {
		if (c.Essential == nil || bool(*c.Essential)) && c.HealthCheck != nil {
			hasHealth = true
			break
		}
	}
	healthy, unhealthy = true, false
	if hasHealth {
		healthy = value(t.Data.HealthStatus) == "HEALTHY"
		unhealthy = value(t.Data.HealthStatus) == "UNHEALTHY" && !now.Before(t.Data.StartedAt.Add(grace))
	}
	if len(bindings) > 0 {
		targetHealthy, targetUnhealthy := replicaTargetHealth(t, bindings, targetHealth, grace, now)
		return healthy && targetHealthy, unhealthy || targetUnhealthy
	}
	if !hasHealth {
		return !now.Before(t.Data.StartedAt.Add(40 * time.Second)), false
	}
	return healthy, unhealthy
}
func replicaFailureThreshold(b *api.DeploymentCircuitBreaker, desired int) int32 {
	kind, amount := "BOUNDED_PERCENT", 50
	if b.ThresholdConfiguration != nil {
		kind = value(b.ThresholdConfiguration.Type)
		if b.ThresholdConfiguration.Value != nil {
			amount = int(*b.ThresholdConfiguration.Value)
		}
	}
	if kind == "COUNT" {
		return int32(amount)
	}
	n := (desired*amount + 99) / 100
	if kind == "BOUNDED_PERCENT" {
		n = min(200, max(3, n))
	}
	return int32(n)
}

func (s *Service) launchReplicaTask(ctx context.Context, tx Transaction, r *ServiceRecord, index int, live *[]replicaTask, now time.Time) (bool, error) {
	d := &r.Deployments[index]
	for _, container := range d.Definition.ContainerDefinitions {
		if value(container.VersionConsistency) == "disabled" || strings.Contains(value(container.Image), "@") || d.ResolvedImages[value(container.Name)] != "" {
			continue
		}
		for _, existing := range *live {
			if existing.deployment == index && value(existing.record.Data.DesiredStatus) == "RUNNING" && value(existing.record.Data.LastStatus) != "RUNNING" {
				return false, nil
			}
		}
	}
	if now.Before(d.RetryAfter) {
		return false, nil
	}
	cluster, err := tx.Cluster(r.Key.ClusterKey)
	if err != nil {
		return false, err
	}
	input := api.CloneRunTaskRequest(d.Input)
	input.Group = new(api.String("service:" + r.Key.ServiceName))
	input.StartedBy = d.Data.Id
	key, rejected := definitionKey(ctx, value(d.Definition.TaskDefinitionArn), false)
	if rejected != nil {
		return false, rejected
	}
	selected, _, err := s.replicaPlacement(ctx, cluster, input, *live)
	if err != nil {
		return s.replicaLaunchFailure(ctx, r, index, now, err)
	}
	input.NetworkConfiguration.AwsvpcConfiguration.Subnets = api.StringList{api.String(selected.SubnetID)}
	plan, err := s.prepareTask(ctx, &input, cluster, TaskDefinitionRecord{Key: key, Data: d.Definition})
	if err != nil {
		return s.replicaLaunchFailure(ctx, r, index, now, err)
	}
	tags := api.Tags{}
	switch value(r.Data.PropagateTags) {
	case "SERVICE":
		tags, err = tagsFor(tx, r.Key.Scope, r.Key.ARN())
	case "TASK_DEFINITION":
		tags, err = tagsFor(tx, r.Key.Scope, value(d.Definition.TaskDefinitionArn))
	}
	if err != nil {
		return false, err
	}
	task := s.buildTask(plan, d.AcceptedEventID)
	task.ServiceName = r.Key.ServiceName
	task.ServiceDeploymentID = value(d.Data.Id)
	managed := r.Data.EnableECSManagedTags != nil && bool(*r.Data.EnableECSManagedTags)
	if err := s.acceptTask(ctx, tx, task, tags, managed, r.Key.ServiceName); err != nil {
		return false, err
	}
	*live = append(*live, replicaTask{record: task, deployment: index})
	return true, nil
}
func (s *Service) replicaLaunchFailure(ctx context.Context, r *ServiceRecord, index int, now time.Time, cause error) (bool, error) {
	d := &r.Deployments[index]
	d.Failures++
	d.Data.FailedTasks = new(api.Integer(d.Failures))
	d.RetryAfter = now.Add(time.Duration(min(30, max(1, int(d.Failures)))) * time.Second)
	return false, s.publishServiceEvent(ctx, r, "SERVICE_TASK_PLACEMENT_FAILURE", value(d.Data.Id), cause.Error())
}

// Spread admission and steady-state rebalance share the same real subnet/AZ
// inventory. Multiple subnets in one zone do not count as additional zones.
func (s *Service) replicaPlacement(ctx context.Context, cluster ClusterRecord, input api.RunTaskInput, live []replicaTask) (TaskPlacement, bool, error) {
	counts := map[string]int{}
	largest := 0
	for _, t := range live {
		zone := value(t.record.Data.AvailabilityZone)
		counts[zone]++
		largest = max(largest, counts[zone])
	}
	var selected TaskPlacement
	for _, subnet := range input.NetworkConfiguration.AwsvpcConfiguration.Subnets {
		cfg := api.CloneAwsVpcConfiguration(*input.NetworkConfiguration.AwsvpcConfiguration)
		cfg.Subnets = api.StringList{subnet}
		placement, err := s.networks.Select(ctx, cluster.Key.ARN(), cfg)
		if err != nil {
			return TaskPlacement{}, false, err
		}
		if selected.SubnetID == "" || counts[placement.AvailabilityZone] < counts[selected.AvailabilityZone] {
			selected = placement
		}
	}
	if selected.SubnetID == "" {
		return selected, false, failure("InvalidParameterException", "At least one subnet is required.")
	}
	return selected, largest-counts[selected.AvailabilityZone] > 1, nil
}

func replicaReadinessDeadline(task TaskRecord, service api.Service, bindings api.LoadBalancers) time.Time {
	if task.Data.StartedAt == nil || value(task.Data.DesiredStatus) != "RUNNING" {
		return time.Time{}
	}
	if len(bindings) > 0 {
		if service.HealthCheckGracePeriodSeconds != nil {
			return task.Data.StartedAt.Add(time.Duration(*service.HealthCheckGracePeriodSeconds) * time.Second)
		}
		return time.Time{}
	}
	for _, container := range task.Definition.ContainerDefinitions {
		if (container.Essential == nil || bool(*container.Essential)) && container.HealthCheck != nil {
			if service.HealthCheckGracePeriodSeconds != nil {
				return task.Data.StartedAt.Add(time.Duration(*service.HealthCheckGracePeriodSeconds) * time.Second)
			}
			return time.Time{}
		}
	}
	return task.Data.StartedAt.Add(40 * time.Second)
}

func replicaObservationTime(task TaskRecord, bindings api.LoadBalancers, now time.Time) time.Time {
	if task.Data.StoppingAt != nil {
		return *task.Data.StoppingAt
	}
	if task.Data.StartedAt != nil {
		if len(bindings) > 0 {
			return now
		}
		for _, container := range task.Definition.ContainerDefinitions {
			if (container.Essential == nil || bool(*container.Essential)) && container.HealthCheck != nil {
				return now
			}
		}
		return task.Data.StartedAt.Add(40 * time.Second)
	}
	return now
}
