package ecs

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	runtime "stackd/compute/ecs"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
)

func targetFixtureTask(now time.Time) (TaskRecord, api.LoadBalancers) {
	key := TaskKey{ClusterKey: ClusterKey{Scope: Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, Name: "targets"}, ID: "task-a"}
	task := TaskRecord{Key: key, ServiceName: "web", ServiceDeploymentID: "ecs-svc/1", Data: api.Task{
		LastStatus: new(api.String("RUNNING")), DesiredStatus: new(api.String("RUNNING")), StartedAt: new(now), Version: new(api.Long(1)),
		Attachments: api.Attachments{{Id: new(api.String("attachment-a")), Type: new(api.String("ElasticNetworkInterface")), Status: new(api.String("ATTACHED")), Details: api.AttachmentDetails{
			{Name: new(api.String("networkInterfaceId")), Value: new(api.String("eni-a"))},
			{Name: new(api.String("privateIPv4Address")), Value: new(api.String("10.0.0.7"))},
		}}},
	}, Definition: api.TaskDefinition{NetworkMode: new(api.NetworkMode("awsvpc")), ContainerDefinitions: api.ContainerDefinitions{{Name: new(api.String("web")), PortMappings: api.PortMappingList{{ContainerPort: new(api.BoxedInteger(8080))}}}}}}
	return task, api.LoadBalancers{{TargetGroupArn: new(api.String("arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/web/1234")), ContainerName: new(api.String("web")), ContainerPort: new(api.BoxedInteger(8080))}}
}

func TestReplicaTargetHealthGatesReadinessAndFencesIncarnation(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	task, bindings := targetFixtureTask(now)
	service := api.Service{HealthCheckGracePeriodSeconds: new(api.BoxedInteger(30))}
	targets, err := taskServiceTargets(task, bindings)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[ServiceTarget]ServiceTargetHealth{targets[0]: ServiceTargetInitial}
	if healthy, unhealthy := replicaHealth(task, service, bindings, observed, now.Add(time.Minute)); healthy || unhealthy {
		t.Fatalf("elapsed time manufactured target health: healthy=%v unhealthy=%v", healthy, unhealthy)
	}
	observed[targets[0]] = ServiceTargetHealthy
	if healthy, unhealthy := replicaHealth(task, service, bindings, observed, now); !healthy || unhealthy {
		t.Fatalf("observed healthy target did not admit readiness: healthy=%v unhealthy=%v", healthy, unhealthy)
	}
	task.Definition.ContainerDefinitions[0].HealthCheck = &api.HealthCheck{}
	task.Data.HealthStatus = new(api.HealthStatus("UNKNOWN"))
	if healthy, _ := replicaHealth(task, service, bindings, observed, now); healthy {
		t.Fatal("target health bypassed required container health")
	}
	task.Data.HealthStatus = new(api.HealthStatus("HEALTHY"))
	observed[targets[0]] = ServiceTargetUnhealthy
	if _, unhealthy := replicaHealth(task, service, bindings, observed, now.Add(29*time.Second)); unhealthy {
		t.Fatal("target failure ignored health-check grace period")
	}
	if healthy, unhealthy := replicaHealth(task, service, bindings, observed, now.Add(30*time.Second)); healthy || !unhealthy {
		t.Fatal("target failure was not exposed at grace boundary")
	}
	observed[targets[0]] = ServiceTargetHealthy
	task.Data.Attachments[0].Details[0].Value = new(api.String("eni-replacement"))
	if healthy, _ := replicaHealth(task, service, bindings, observed, now.Add(time.Minute)); healthy {
		t.Fatal("health from a reused address admitted a different ENI incarnation")
	}
}

func TestReplicaTargetFailureRollsBackImmutableBindings(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	source := clock.NewManual(now)
	s := New(Config{Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	oldTask, oldBindings := targetFixtureTask(now.Add(-time.Minute))
	newTask := oldTask
	newTask.Key.ID, newTask.ServiceDeploymentID = "task-b", "ecs-svc/2"
	newTask.Data = api.CloneTask(oldTask.Data)
	newTask.Data.Attachments[0].Id = new(api.String("attachment-b"))
	newTask.Data.Attachments[0].Details[0].Value = new(api.String("eni-b"))
	newTask.Data.Attachments[0].Details[1].Value = new(api.String("10.0.0.8"))
	newBindings := api.CloneLoadBalancers(oldBindings)
	newBindings[0].TargetGroupArn = new(api.String("arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/new/5678"))
	record := ServiceRecord{Key: ServiceKey{ClusterKey: oldTask.Key.ClusterKey, ServiceName: "web"}, Data: api.Service{
		Status: new(api.String("ACTIVE")), DesiredCount: new(api.Integer(1)), LoadBalancers: newBindings,
		DeploymentConfiguration: &api.DeploymentConfiguration{MaximumPercent: new(api.BoxedInteger(200)), MinimumHealthyPercent: new(api.BoxedInteger(100)), DeploymentCircuitBreaker: &api.DeploymentCircuitBreaker{Enable: new(api.Boolean(true)), Rollback: new(api.Boolean(true)), ResetOnHealthyTask: new(api.BoxedBoolean(false)), ThresholdConfiguration: &api.ThresholdConfiguration{Type: new(api.ThresholdType("COUNT")), Value: new(api.Integer(1))}}},
	},
		Deployments: []ServiceDeployment{
			{Data: api.Deployment{Id: new(api.String("ecs-svc/2")), Status: new(api.String("PRIMARY")), RolloutState: new(api.DeploymentRolloutState("IN_PROGRESS")), DesiredCount: new(api.Integer(1)), CreatedAt: new(now)}, LoadBalancers: newBindings},
			{Data: api.Deployment{Id: new(api.String("ecs-svc/1")), Status: new(api.String("ACTIVE")), RolloutState: new(api.DeploymentRolloutState("COMPLETED")), DesiredCount: new(api.Integer(1)), CreatedAt: new(now.Add(-time.Minute))}, LoadBalancers: oldBindings, Completed: true},
		},
	}
	oldTargets, _ := taskServiceTargets(oldTask, oldBindings)
	newTargets, _ := taskServiceTargets(newTask, newBindings)
	health := map[ServiceTarget]ServiceTargetHealth{oldTargets[0]: ServiceTargetHealthy, newTargets[0]: ServiceTargetUnhealthy}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutTask(oldTask); err != nil {
			return err
		}
		if err := tx.PutTask(newTask); err != nil {
			return err
		}
		if err := tx.PutService(record); err != nil {
			return err
		}
		_, err := s.reconcileService(tx.Context(), tx, &record, health)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if value(record.Data.LoadBalancers[0].TargetGroupArn) != value(oldBindings[0].TargetGroupArn) || value(record.Deployments[1].Data.Status) != "PRIMARY" || value(record.Deployments[0].Data.RolloutState) != "FAILED" {
		t.Fatal("target health failure did not restore the immutable baseline bindings")
	}
	if err := s.repository.View(t.Context(), func(r Reader) error {
		failed, err := r.Task(newTask.Key)
		if err == nil && value(failed.Data.DesiredStatus) != "STOPPED" {
			t.Fatal("failed revision task was not retired")
		}
		baseline, err := r.Task(oldTask.Key)
		if err == nil && value(baseline.Data.DesiredStatus) != "RUNNING" {
			t.Fatal("healthy rollback baseline was stopped")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type targetDrainFixture struct {
	ServiceLoadBalancers
	cancel       context.CancelFunc
	drained      bool
	deregistered []ServiceTarget
}

func (f *targetDrainFixture) Deregister(_ context.Context, target ServiceTarget) error {
	f.deregistered = append(f.deregistered, target)
	return nil
}
func (f *targetDrainFixture) Drained(context.Context, ServiceTarget) (bool, error) {
	if f.cancel != nil {
		f.cancel()
	}
	return f.drained, nil
}

func TestTaskStopWaitsForTargetDrainAndRetainsOldBinding(t *testing.T) {
	task, bindings := targetFixtureTask(time.Now())
	task.Data.DesiredStatus = new(api.String("STOPPED"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	owner := &targetDrainFixture{cancel: cancel}
	s := New(Config{LoadBalancers: owner, Networks: &stoppingPolicyNetwork{}})
	t.Cleanup(func() { _ = s.Close() })
	record := ServiceRecord{Key: ServiceKey{ClusterKey: task.Key.ClusterKey, ServiceName: task.ServiceName}, Data: api.Service{LoadBalancers: api.LoadBalancers{}}, Deployments: []ServiceDeployment{{Data: api.Deployment{Id: new(api.String(task.ServiceDeploymentID))}, LoadBalancers: bindings}}}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutService(record); err != nil {
			return err
		}
		return tx.PutTask(task)
	}); err != nil {
		t.Fatal(err)
	}
	native := &stoppingPolicyRuntime{running: true}
	e := &taskExecution{service: s, key: task.Key, ctx: ctx, environment: native}
	// Native removal and network release are deliberately unconfigured: invoking
	// either before confirmed drain fails rather than returning fake success.
	if err := e.stop(task); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop passed the unfinished drain: %v", err)
	}
	if len(owner.deregistered) != 1 || owner.deregistered[0].TaskARN != task.Key.ARN() || owner.deregistered[0].NetworkInterfaceID != "eni-a" || owner.deregistered[0].TargetGroupARN != value(bindings[0].TargetGroupArn) {
		t.Fatal("service binding removal lost the retiring task's exact target identity")
	}
	if !native.running {
		t.Fatal("healthy-policy process stopped before graceful drain completed")
	}
	if err := s.repository.View(t.Context(), func(r Reader) error {
		current, err := r.Task(task.Key)
		if err == nil && (value(current.Data.LastStatus) != "RUNNING" || value(current.Data.Attachments[0].Status) != "ATTACHED") {
			t.Fatal("draining task lost its process or ENI")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	owner.cancel, owner.drained = nil, true
	e.ctx = t.Context()
	if drained, err := e.drainTargets(task); err != nil || !drained {
		t.Fatalf("completed drain did not release stop gate: %v %v", drained, err)
	}
}

type targetAdmissionDependencies struct {
	runtime.Executor
	TaskNetworks
	TaskRoles
}

func (targetAdmissionDependencies) Select(context.Context, string, api.AwsVpcConfiguration) (TaskPlacement, error) {
	return TaskPlacement{SubnetID: "subnet-a", AvailabilityZone: "us-east-1a"}, nil
}
func (targetAdmissionDependencies) EnsureServiceLinkedRole(context.Context, string) error { return nil }

func TestServiceLoadBalancerRemovalCreatesImmutableDeployment(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	task, bindings := targetFixtureTask(now)
	dependencies := targetAdmissionDependencies{}
	s := New(Config{Clock: clock.NewManual(now), Executor: dependencies, Networks: dependencies, TaskRoles: dependencies, Roles: dependencies})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: task.Key.Partition, AccountID: task.Key.AccountID, Region: task.Key.Region, PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: task.Key.AccountID})
	key := ServiceKey{ClusterKey: task.Key.ClusterKey, ServiceName: task.ServiceName}
	definition := task.Definition
	definition.TaskDefinitionArn = new(api.String("arn:aws:ecs:us-east-1:111122223333:task-definition/web:1"))
	definition.Cpu, definition.Memory = new(api.String("256")), new(api.String("512"))
	record := ServiceRecord{Key: key, Data: api.Service{Status: new(api.String("ACTIVE")), ClusterArn: new(api.String(key.ClusterKey.ARN())), TaskDefinition: definition.TaskDefinitionArn, DesiredCount: new(api.Integer(0)), LaunchType: new(api.LaunchType("FARGATE")), LoadBalancers: bindings, SchedulingStrategy: new(api.SchedulingStrategy("REPLICA")), NetworkConfiguration: &api.NetworkConfiguration{AwsvpcConfiguration: &api.AwsVpcConfiguration{Subnets: api.StringList{"subnet-a"}}}}}
	record.Data.DeploymentController = &api.DeploymentController{Type: new(api.DeploymentControllerType("ECS"))}
	record.Data.PropagateTags = new(api.PropagateTags("NONE"))
	record.Data.AvailabilityZoneRebalancing = new(api.AvailabilityZoneRebalancing("DISABLED"))
	record.Deployments = []ServiceDeployment{s.newServiceDeployment(ctx, record, TaskDefinitionRecord{Data: definition}, nil)}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutCluster(ClusterRecord{Key: key.ClusterKey, Data: api.Cluster{Status: new(api.String("ACTIVE"))}}); err != nil {
			return err
		}
		return tx.PutService(record)
	}); err != nil {
		t.Fatal(err)
	}
	out, rejected := runCommand(s, ctx, "UpdateService", &api.UpdateServiceInput{Cluster: new(api.String(key.Name)), Service: new(api.String(key.ServiceName)), LoadBalancers: api.LoadBalancers{}}, s.updateService)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if len(out.Service.LoadBalancers) != 0 {
		t.Fatal("empty list did not remove service bindings")
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		current, err := r.Service(key)
		if err != nil {
			return err
		}
		if len(current.Deployments) != 2 || len(current.Deployments[0].LoadBalancers) != 0 || value(current.Deployments[1].LoadBalancers[0].TargetGroupArn) != value(bindings[0].TargetGroupArn) {
			t.Fatal("binding removal changed the old execution snapshot")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, binding := range []api.LoadBalancer{
		{TargetGroupArn: bindings[0].TargetGroupArn, ContainerName: new(api.String("missing")), ContainerPort: bindings[0].ContainerPort},
		{TargetGroupArn: bindings[0].TargetGroupArn, ContainerName: bindings[0].ContainerName, ContainerPort: new(api.BoxedInteger(8081))},
	} {
		record.Data.LoadBalancers = api.LoadBalancers{binding}
		if rejected := wireError(s.validateServiceLoadBalancers(ctx, record, definition)); rejected == nil || rejected.Code != "InvalidParameterException" {
			t.Fatalf("invalid container/port binding admitted: %v", rejected)
		}
	}
}
