package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"stackd/compute/docker"
	computeecs "stackd/compute/ecs"
	"stackd/compute/network"
	"stackd/internal/awsapi"
	aasapi "stackd/internal/awsapi/applicationautoscaling"
	asgapi "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
	ecsapi "stackd/internal/awsapi/ecs"
	elbapi "stackd/internal/awsapi/elbv2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	aas "stackd/internal/services/applicationautoscaling"
	asg "stackd/internal/services/autoscaling"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ecs"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
	"stackd/storage/sqlite"
	aasstore "stackd/storage/sqlite/applicationautoscaling"
	asgstore "stackd/storage/sqlite/autoscaling"
	ecsstore "stackd/storage/sqlite/ecs"
	elbstore "stackd/storage/sqlite/elbv2"
)

type cfnComputeOwnerFixture struct {
	base      *autoScalingFixture
	db        *sql.DB
	path      string
	aasRepo   aas.Repository
	asgRepo   asg.Repository
	ecsRepo   ecs.Repository
	elbRepo   elbv2.Repository
	scaling   *aas.Service
	groups    *asg.Service
	replicas  *ecs.Service
	balancers *elbv2.Service
	executor  computeecs.Executor
	identity  *iam.Service
	commands  StepFunctionsCommands
	handlers  map[string]cloudformation.ResourceHandler
}

func newCFNComputeOwnerFixture(t *testing.T, backend string, executor computeecs.Executor) *cfnComputeOwnerFixture {
	t.Helper()
	f := &cfnComputeOwnerFixture{base: newAutoScalingFixture(t), executor: executor}
	f.identity = f.base.roles.IAM.(*iam.Service)
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "compute.sqlite")
		f.open(t)
	} else {
		f.aasRepo = aas.NewMemoryRepository(f.base.domain)
		f.asgRepo = asg.NewMemoryRepository(f.base.domain)
		f.ecsRepo = ecs.NewMemoryRepository(f.base.domain)
		f.elbRepo = elbv2.NewMemoryRepository(f.base.domain)
	}
	f.start()
	// Replace the isolated autoscaling execution-role seed with the actual
	// service-linked owner; names alone must never confer service authority.
	if err := f.base.iam.Update(f.base.root, func(tx iam.WriteTx) error {
		return tx.DeleteRole(iam.Scope{Partition: "aws", AccountID: "123456789012"}, "AWSServiceRoleForAutoScaling")
	}); err != nil {
		t.Fatal(err)
	}
	for _, template := range f.identity.ServiceLinkedRoleTemplates() {
		switch template.ServiceName {
		case ecs.ServicePrincipal, asg.ServicePrincipal, aas.ECSServicePrincipal, aas.DynamoDBServicePrincipal:
			if err := f.identity.RegisterServiceLinkedRole(template, f); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.identity.EnsureServiceLinkedRole(f.base.root, asg.ServicePrincipal); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.identity.Close() })
	t.Cleanup(func() {
		f.closeOwners()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}
func (f *cfnComputeOwnerFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.db, err = sqlite.Open(f.base.root, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.aasRepo = aasstore.New(f.db)
	f.asgRepo = asgstore.New(f.db)
	f.ecsRepo = ecsstore.New(f.db)
	f.elbRepo = elbstore.New(f.db)
}
func (f *cfnComputeOwnerFixture) start() {
	b := f.base
	f.balancers = elbv2.New(elbv2.Config{Repository: f.elbRepo, Clock: b.clock, Authorizer: b.roles.Authorizer})
	f.replicas = ecs.New(ecs.Config{Repository: f.ecsRepo, Clock: b.clock, Authorizer: b.roles.Authorizer, Roles: f.identity, Executor: f.executor, Networks: &ECSTaskNetworks{EC2: b.ec2, Roles: b.roles}, TaskRoles: ECSTaskRoles{ServiceRoles: b.roles}, LoadBalancers: &ECSLoadBalancers{ELBv2: f.balancers, EC2: b.ec2, Roles: b.roles}})
	f.groups = asg.New(asg.Config{Repository: f.asgRepo, Clock: b.clock, Authorizer: b.roles.Authorizer, Roles: f.identity, Instances: b.adapter, Identity: b.adapter})
	resources := &ApplicationScaling{ECS: f.replicas, Roles: b.roles}
	f.scaling = aas.New(aas.Config{Repository: f.aasRepo, Clock: b.clock, Authorizer: b.roles.Authorizer, Roles: f.identity, Resources: resources, Identity: resources})
	resources.Scaling = f.scaling
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"applicationautoscaling": f.scaling, "autoscaling": f.groups, "ecs": f.replicas, "elbv2": f.balancers})
	f.handlers = CloudFormationComputeServiceHandlers(f.commands)
}

// Registration retains the fixture, not a closed owner from before SQLite
// reopen. Every role-deletion inspection forwards to the current real service.
func (f *cfnComputeOwnerFixture) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	switch ref.ServiceName {
	case ecs.ServicePrincipal:
		return (ECSRoleUsage{Clusters: f.replicas}).WithServiceLinkedRoleUsage(ctx, ref, fn)
	case asg.ServicePrincipal:
		return (AutoScalingRoleUsage{Groups: f.groups}).WithServiceLinkedRoleUsage(ctx, ref, fn)
	case aas.ECSServicePrincipal, aas.DynamoDBServicePrincipal:
		return (ApplicationScalingRoleUsage{Targets: f.scaling}).WithServiceLinkedRoleUsage(ctx, ref, fn)
	default:
		return fmt.Errorf("unsupported compute service-linked role usage %s", ref.ServiceName)
	}
}
func (f *cfnComputeOwnerFixture) closeOwners() {
	_ = f.scaling.Close()
	_ = f.groups.Close()
	_ = f.replicas.Close()
	_ = f.balancers.Close()
}
func (f *cfnComputeOwnerFixture) reopen(t *testing.T) {
	t.Helper()
	if f.path == "" {
		return
	}
	f.closeOwners()
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	f.start()
}
func (f *cfnComputeOwnerFixture) request(kind, logical string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: kind, StackID: "compute-stack", StackName: "compute", LogicalID: logical, Token: logical + "-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: p}
}
func (f *cfnComputeOwnerFixture) create(t *testing.T, r *cloudformation.ResourceRequest) cloudformation.ResourceResult {
	t.Helper()
	out, err := f.handlers[r.Type].Create(f.base.root, *r)
	if err != nil {
		t.Fatalf("create %s: %v", r.Type, err)
	}
	r.PhysicalID = out.PhysicalID
	return out
}
func (f *cfnComputeOwnerFixture) native(t *testing.T, service, operation string, input map[string]any) any {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	out, rejected := f.commands.Call(f.base.root, service, operation, body)
	if rejected != nil {
		t.Fatalf("%s.%s: %v", service, operation, rejected)
	}
	return out.Output
}
func (f *cfnComputeOwnerFixture) loadBalancer(t *testing.T, vpc string) string {
	t.Helper()
	scope := elbv2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dependency/0000000000000001"
	if err := f.elbRepo.Update(f.base.root, func(tx elbv2.Transaction) error {
		return tx.PutLoadBalancer(elbv2.LoadBalancerRecord{Scope: scope, Data: elbapi.LoadBalancer{LoadBalancerArn: new(elbapi.LoadBalancerArn(arn)), LoadBalancerName: new(elbapi.LoadBalancerName("dependency")), Type: new(elbapi.LoadBalancerTypeEnum("application")), VpcId: new(elbapi.VpcId(vpc))}})
	}); err != nil {
		t.Fatal(err)
	}
	return arn
}

// Public tags are forgeable metadata, never the authority for an incarnation.
// The listener dependency is a native ALB fixture; all listener CRUD is real.
func TestComputeListenerCloudControlCreateCannotAdoptForeignListener(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			lb := f.loadBalancer(t, "vpc-dependency")
			p := cloudformation.Properties{"LoadBalancerArn": lb, "Port": 80, "Protocol": "HTTP", "DefaultActions": []any{map[string]any{"Type": "fixed-response", "FixedResponseConfig": map[string]any{"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "foreign"}}}}
			r := f.request("AWS::ElasticLoadBalancingV2::Listener", "Listener", p)
			r.CloudControl = true
			in := cfnComputeCopy(p, "LoadBalancerArn", "Port", "Protocol", "DefaultActions")
			in["Tags"] = cfnELBTagList(cfnComputeOwnedTags(r))
			foreign := f.native(t, "elbv2", "CreateListener", in).(*elbapi.CreateListenerOutput).Listeners[0]
			f.reopen(t)
			out, err := f.handlers[r.Type].Create(f.base.root, r)
			var rejection *awswire.Error
			if out.PhysicalID != "" || !errors.As(err, &rejection) {
				t.Fatalf("adopted foreign native listener: %+v %v", out, err)
			}
			r.PhysicalID = string(*foreign.ListenerArn)
			r.CloudControl = false
			if err := f.handlers[r.Type].Delete(f.base.root, r); err == nil {
				t.Fatal("forged public tags granted delete authority")
			}
			described := f.native(t, "elbv2", "DescribeListeners", map[string]any{"ListenerArns": []string{r.PhysicalID}}).(*elbapi.DescribeListenersOutput)
			if len(described.Listeners) != 1 || string(*described.Listeners[0].ListenerArn) != r.PhysicalID {
				t.Fatalf("rejection removed foreign listener: %+v", described)
			}
			// Direct CloudControl mutations remain native-authoritative, without adopting
			// the resource into a Create operation's private incarnation.
			r.CloudControl = true
			if err := f.handlers[r.Type].Delete(f.base.root, r); err != nil {
				t.Fatalf("direct delete rejected: %v", err)
			}
			r.PhysicalID = ""
			boundary := &cfnComputeLostCreateReply{owner: f.balancers, operation: "CreateListener", lose: true}
			handlers := CloudFormationComputeServiceHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"elbv2": boundary}))
			owned, err := handlers[r.Type].Create(f.base.root, r)
			var timeout *awswire.Error
			if owned.PhysicalID == "" || !errors.As(err, &timeout) || timeout.Code != "RequestTimeout" {
				t.Fatalf("lost admitted listener after native timeout: %+v %v", owned, err)
			}
			r.PhysicalID = owned.PhysicalID
			f.reopen(t)
			replay := r
			replay.PhysicalID = ""
			if got, err := f.handlers[r.Type].Create(f.base.root, replay); err != nil || got.PhysicalID != owned.PhysicalID {
				t.Fatalf("lost own listener on replay: %+v %v", got, err)
			}
			wrong := r
			wrong.CloudControl = false
			wrong.Token = "replacement-incarnation"
			if err := f.handlers[r.Type].Delete(f.base.root, wrong); err == nil {
				t.Fatal("stale incarnation deleted current listener")
			}
			if err := f.handlers[r.Type].Delete(f.base.root, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestComputeScalableTargetReplayResumesSchedules(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			// A zero-capacity native service snapshot supplies the real ECS permission
			// probes and linked-role capacity read used by ApplicationScaling.Admit.
			cluster := ecs.ClusterKey{Scope: ecs.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "scaling"}
			service := ecs.ServiceKey{ClusterKey: cluster, ServiceName: "workers"}
			if err := f.ecsRepo.Update(f.base.root, func(tx ecs.Transaction) error {
				if err := tx.PutCluster(ecs.ClusterRecord{Key: cluster, Data: ecsapi.Cluster{ClusterArn: new(ecsapi.String(cluster.ARN())), ClusterName: new(ecsapi.String(cluster.Name)), Status: new(ecsapi.String("ACTIVE"))}}); err != nil {
					return err
				}
				return tx.PutService(ecs.ServiceRecord{Key: service, Data: ecsapi.Service{ServiceArn: new(ecsapi.String(service.ARN())), ServiceName: new(ecsapi.String(service.ServiceName)), ClusterArn: new(ecsapi.String(cluster.ARN())), Status: new(ecsapi.String("ACTIVE")), DesiredCount: new(ecsapi.Integer(0)), RunningCount: new(ecsapi.Integer(0)), PendingCount: new(ecsapi.Integer(0))}})
			}); err != nil {
				t.Fatal(err)
			}
			p := cloudformation.Properties{"ServiceNamespace": "ecs", "ResourceId": "service/scaling/workers", "ScalableDimension": "ecs:service:DesiredCount", "MinCapacity": 0, "MaxCapacity": 2, "ScheduledActions": []any{map[string]any{"ScheduledActionName": "later", "Schedule": "invalid-schedule", "ScalableTargetAction": map[string]any{"MinCapacity": 0, "MaxCapacity": 2}}}}
			r := f.request(cfnAASTargetType, "Target", p)
			admitted, err := f.handlers[r.Type].Create(f.base.root, r)
			if err == nil || admitted.PhysicalID != "service/scaling/workers|ecs:service:DesiredCount|ecs" {
				t.Fatalf("lost admitted target after schedule rejection: %+v %v", admitted, err)
			}
			f.reopen(t)
			again, err := f.handlers[r.Type].Create(f.base.root, r)
			if err == nil || again.PhysicalID != admitted.PhysicalID {
				t.Fatalf("lost admitted target during rejected replay: %+v %v", again, err)
			}
			p["ScheduledActions"] = []any{map[string]any{"ScheduledActionName": "later", "Schedule": "at(2035-01-03T00:00:00)", "ScalableTargetAction": map[string]any{"MinCapacity": 0, "MaxCapacity": 2}}}
			accepted := f.create(t, &r)
			if accepted.PhysicalID != admitted.PhysicalID {
				t.Fatal("replay created another target")
			}
			key := cfnAASTargetFrom(p)
			target, _, err := cfnAASGetTarget(f.base.root, f.commands, key)
			if err != nil {
				t.Fatal(err)
			}
			f.native(t, "applicationautoscaling", "TagResource", map[string]any{"ResourceARN": string(*target.ScalableTargetARN), "Tags": map[string]string{cfnComputeTagPrefix + "stack-id": "forged", cfnComputeTagPrefix + "logical-id": "forged", cfnComputeTagPrefix + "incarnation": "forged"}})
			replay := r
			replay.PhysicalID = ""
			if got, err := f.handlers[r.Type].Create(f.base.root, replay); err != nil || got.PhysicalID != r.PhysicalID {
				t.Fatalf("public retagging erased private target owner: %+v %v", got, err)
			}
			removed := cfnComputeCopy(p, "ServiceNamespace", "ResourceId", "ScalableDimension", "MinCapacity", "MaxCapacity")
			update := r
			update.Previous = p
			update.Properties = removed
			if _, err := f.handlers[r.Type].Update(f.base.root, update); err != nil {
				t.Fatal(err)
			}
			schedules := f.native(t, "applicationautoscaling", "DescribeScheduledActions", key.input()).(*aasapi.DescribeScheduledActionsOutput)
			if len(schedules.ScheduledActions) != 0 {
				t.Fatalf("removed schedule survived: %+v", schedules)
			}
			update.Previous = removed
			update.Properties = p
			if _, err := f.handlers[r.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("schedule rollback: %v", err)
			}
			schedules = f.native(t, "applicationautoscaling", "DescribeScheduledActions", key.input()).(*aasapi.DescribeScheduledActionsOutput)
			if len(schedules.ScheduledActions) != 1 {
				t.Fatalf("rollback did not restore schedule: %+v", schedules)
			}
			if err := f.handlers[r.Type].Delete(f.base.root, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestComputeGroupInlineHooksFenceStandaloneOwnerBeforeMutation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			p := cloudformation.Properties{"AutoScalingGroupName": "workers", "MinSize": 0, "MaxSize": 2, "DesiredCapacity": 0}
			group := f.request(cfnASGGroupType, "Group", p)
			group.PhysicalID = "workers"
			record := f.base.group
			record.Ownership = cfnNativeComputeClaim(group)
			record.Data.AutoScalingGroupName = new(asgapi.XmlStringMaxLen255("workers"))
			record.Data.MinSize = new(asgapi.AutoScalingGroupMinSize(0))
			record.Data.MaxSize = new(asgapi.AutoScalingGroupMaxSize(2))
			record.Data.DesiredCapacity = new(asgapi.AutoScalingGroupDesiredCapacity(0))
			if err := f.asgRepo.Update(f.base.root, func(tx asg.Transaction) error { return tx.PutGroup(record) }); err != nil {
				t.Fatal(err)
			}
			hook := f.request(cfnASGHookType, "Hook", cloudformation.Properties{"AutoScalingGroupName": "workers", "LifecycleHookName": "protect", "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING", "DefaultResult": "ABANDON", "HeartbeatTimeout": 30})
			boundary := &cfnComputeLostCreateReply{owner: f.groups, operation: "PutLifecycleHook", lose: true}
			handlers := CloudFormationComputeServiceHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"autoscaling": boundary}))
			admitted, err := handlers[hook.Type].Create(f.base.root, hook)
			var timeout *awswire.Error
			if admitted.PhysicalID != "workers|protect" || !errors.As(err, &timeout) || timeout.Code != "RequestTimeout" {
				t.Fatalf("lost admitted hook after native timeout: %+v %v", admitted, err)
			}
			hook.PhysicalID = admitted.PhysicalID
			f.native(t, "autoscaling", "PutLifecycleHook", map[string]any{"AutoScalingGroupName": "workers", "LifecycleHookName": "protect", "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING", "DefaultResult": "ABANDON", "HeartbeatTimeout": 30})
			f.reopen(t)
			replay := hook
			replay.PhysicalID = ""
			if got, err := f.handlers[hook.Type].Create(f.base.root, replay); err != nil || got.PhysicalID != hook.PhysicalID {
				t.Fatalf("direct native upsert erased admitted hook identity: %+v %v", got, err)
			}
			spec := []any{map[string]any{"LifecycleHookName": "protect", "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING", "DefaultResult": "CONTINUE", "HeartbeatTimeout": 90}}
			for _, direct := range []bool{false, true} {
				for _, removal := range []bool{false, true} {
					update := group
					update.CloudControl = direct
					update.Previous = p
					update.Properties = cfnComputeCopy(p, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity")
					update.Properties["MaxSize"] = 3
					if removal {
						update.Previous = cfnComputeCopy(p, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity")
						update.Previous["LifecycleHookSpecificationList"] = spec
					} else {
						update.Properties["LifecycleHookSpecificationList"] = spec
					}
					if _, err := f.handlers[group.Type].Update(f.base.root, update); err == nil {
						t.Fatalf("standalone hook accepted into inline transition direct=%t removal=%t", direct, removal)
					}
					current, err := cfnASGGet(f.base.root, f.commands, "workers")
					if err != nil {
						t.Fatal(err)
					}
					hooks := f.native(t, "autoscaling", "DescribeLifecycleHooks", map[string]any{"AutoScalingGroupName": "workers"}).(*asgapi.DescribeLifecycleHooksOutput)
					if int(*current.MaxSize) != 2 || len(hooks.LifecycleHooks) != 1 || string(*hooks.LifecycleHooks[0].DefaultResult) != "ABANDON" || int(*hooks.LifecycleHooks[0].HeartbeatTimeout) != 30 {
						t.Fatalf("rejected inline transition changed native group/hook: %+v %+v", current, hooks)
					}
				}
			}
			if err := f.handlers[hook.Type].Delete(f.base.root, hook); err != nil {
				t.Fatalf("standalone owner lost claim after rejected inline transition: %v", err)
			}
			inline := cfnComputeCopy(p, "AutoScalingGroupName", "MinSize", "MaxSize", "DesiredCapacity")
			inline["LifecycleHookSpecificationList"] = spec
			update := group
			update.Previous = p
			update.Properties = inline
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("own inline addition: %v", err)
			}
			update.Previous = inline
			update.Properties = p
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("own inline removal: %v", err)
			}
			hooks := f.native(t, "autoscaling", "DescribeLifecycleHooks", map[string]any{"AutoScalingGroupName": "workers"}).(*asgapi.DescribeLifecycleHooksOutput)
			if len(hooks.LifecycleHooks) != 0 {
				t.Fatalf("removed inline hook survived: %+v", hooks)
			}
			update.Previous = p
			update.Properties = inline
			if _, err := f.handlers[group.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("inline rollback: %v", err)
			}
		})
	}
}

// This accepted removal and rollback run with a real Docker executor, real EC2
// subnet selection and linked IAM sessions, not an echoed UpdateService input.
func TestComputeECSServiceLoadBalancerRemovalAndRollback(t *testing.T) {
	if os.Getenv("STACKD_ECS_DOCKER") != "1" {
		t.Skip("set STACKD_ECS_DOCKER=1 to provision real ECS execution dependencies")
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	networks, err := network.NewBridges(engine)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := computeecs.NewDockerExecutor(t.Context(), computeecs.DockerConfig{Client: engine, Networks: networks})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, executor)
			vpc := f.base.call(t, "ec2", "CreateVpc", map[string]any{"CidrBlock": "10.71.0.0/16"}).(*ec2api.CreateVpcResult).Vpc
			subnet := f.base.call(t, "ec2", "CreateSubnet", map[string]any{"VpcId": string(*vpc.VpcId), "CidrBlock": "10.71.1.0/24", "AvailabilityZone": "us-east-1a"}).(*ec2api.CreateSubnetResult).Subnet
			lb := f.loadBalancer(t, string(*vpc.VpcId))
			tg := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/dependency/0000000000000002"
			if err := f.elbRepo.Update(f.base.root, func(tx elbv2.Transaction) error {
				return tx.PutTargetGroup(elbv2.TargetGroupRecord{Scope: elbv2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Data: elbapi.TargetGroup{TargetGroupArn: new(elbapi.TargetGroupArn(tg)), TargetGroupName: new(elbapi.TargetGroupName("dependency")), VpcId: new(elbapi.VpcId(string(*vpc.VpcId))), TargetType: new(elbapi.TargetTypeEnum("ip")), LoadBalancerArns: elbapi.LoadBalancerArns{elbapi.LoadBalancerArn(lb)}}})
			}); err != nil {
				t.Fatal(err)
			}
			cluster := f.request(cfnECSClusterType, "Cluster", cloudformation.Properties{"ClusterName": "bindings"})
			f.create(t, &cluster)
			definition := f.request(cfnECSTaskDefinitionType, "Definition", cloudformation.Properties{"Family": "bindings", "Cpu": "256", "Memory": "512", "NetworkMode": "awsvpc", "RequiresCompatibilities": []any{"FARGATE"}, "ContainerDefinitions": []any{map[string]any{"Name": "web", "Image": "busybox:latest", "Essential": true, "PortMappings": []any{map[string]any{"ContainerPort": 80, "Protocol": "tcp"}}}}})
			f.create(t, &definition)
			p := cloudformation.Properties{"Cluster": cluster.PhysicalID, "ServiceName": "bindings", "TaskDefinition": definition.PhysicalID, "DesiredCount": 0, "LaunchType": "FARGATE", "NetworkConfiguration": map[string]any{"AwsvpcConfiguration": map[string]any{"Subnets": []any{string(*subnet.SubnetId)}, "AssignPublicIp": "DISABLED"}}, "LoadBalancers": []any{map[string]any{"TargetGroupArn": tg, "ContainerName": "web", "ContainerPort": 80}}}
			service := f.request(cfnECSServiceType, "Service", p)
			f.create(t, &service)
			f.reopen(t)
			removed := cfnComputeCopy(p, "Cluster", "ServiceName", "TaskDefinition", "DesiredCount", "LaunchType", "NetworkConfiguration")
			update := service
			update.Previous = p
			update.Properties = removed
			if _, err := f.handlers[service.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("accepted binding removal: %v", err)
			}
			describe := func() ecsapi.Service {
				arn, _, err := cfnECSServiceIdentity(service.PhysicalID)
				if err != nil {
					t.Fatal(err)
				}
				out := f.native(t, "ecs", "DescribeServices", map[string]any{"Cluster": cluster.PhysicalID, "Services": []string{arn}}).(*ecsapi.DescribeServicesOutput)
				if len(out.Services) != 1 {
					t.Fatalf("missing service: %+v", out)
				}
				return out.Services[0]
			}
			if current := describe(); len(current.LoadBalancers) != 0 {
				t.Fatalf("omitted binding retained native target group: %+v", current.LoadBalancers)
			}
			update.Previous = removed
			update.Properties = p
			if _, err := f.handlers[service.Type].Update(f.base.root, update); err != nil {
				t.Fatalf("binding rollback: %v", err)
			}
			if current := describe(); len(current.LoadBalancers) != 1 || string(*current.LoadBalancers[0].TargetGroupArn) != tg {
				t.Fatalf("rollback failed to restore native target group: %+v", current.LoadBalancers)
			}
			if err := f.handlers[service.Type].Delete(f.base.root, service); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A modeled wire timeout is injected only after real native commit. It is not
// treated as evidence that admission never happened.
type cfnComputeLostCreateReply struct {
	owner     awscommands.CommandExecutor
	operation string
	lose      bool
}

func (e *cfnComputeLostCreateReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.owner.ExecuteCommand(ctx, r)
	if err == nil && e.lose && string(r.Operation.Name) == e.operation {
		e.lose = false
		return nil, &awswire.Error{Code: "RequestTimeout", Message: "reply lost after native admission", StatusCode: 504}
	}
	return out, err
}
func TestComputeClusterAndTaskDefinitionPreserveAdmittedIDAfterLostReply(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			for _, test := range []struct {
				kind, logical, operation string
				p                        cloudformation.Properties
			}{
				{cfnECSClusterType, "Cluster", "CreateCluster", cloudformation.Properties{"ClusterName": "lost-reply"}},
				{cfnECSTaskDefinitionType, "Definition", "RegisterTaskDefinition", cloudformation.Properties{"Family": "lost-reply", "ContainerDefinitions": []any{map[string]any{"Name": "web", "Image": "busybox:latest", "Memory": 128}}}},
			} {
				boundary := &cfnComputeLostCreateReply{owner: f.replicas, operation: test.operation, lose: true}
				handlers := CloudFormationComputeServiceHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ecs": boundary}))
				r := f.request(test.kind, test.logical, test.p)
				admitted, err := handlers[r.Type].Create(f.base.root, r)
				var timeout *awswire.Error
				if admitted.PhysicalID == "" || !errors.As(err, &timeout) || timeout.Code != "RequestTimeout" {
					t.Fatalf("lost admitted %s: %+v %v", r.Type, admitted, err)
				}
				f.reopen(t)
				recovered := f.create(t, &r)
				if recovered.PhysicalID != admitted.PhysicalID {
					t.Fatalf("same-token replay changed admitted incarnation: %+v %+v", admitted, recovered)
				}
				wrong := r
				wrong.Token = "foreign-incarnation"
				if err := f.handlers[r.Type].Delete(f.base.root, wrong); err == nil {
					t.Fatalf("foreign incarnation deleted %s", r.Type)
				}
				if err := f.handlers[r.Type].Delete(f.base.root, r); err != nil {
					t.Fatal(err)
				}
				if r.Type == cfnECSTaskDefinitionType {
					replay := r
					replay.PhysicalID = ""
					if out, err := f.handlers[r.Type].Create(f.base.root, replay); err == nil || out.PhysicalID != admitted.PhysicalID {
						t.Fatalf("lost retired admitted revision or re-registered on replay: %+v %v", out, err)
					}
					active := f.native(t, "ecs", "ListTaskDefinitions", map[string]any{"FamilyPrefix": "lost-reply", "Status": "ACTIVE"}).(*ecsapi.ListTaskDefinitionsOutput)
					if len(active.TaskDefinitionArns) != 0 {
						t.Fatalf("replay resurrected a retired admitted revision: %+v", active)
					}
				}
				if r.Type == cfnECSClusterType {
					f.native(t, "ecs", "CreateCluster", map[string]any{"ClusterName": r.PhysicalID, "Tags": cfnECSTags(cfnComputeOwnedTags(r))})
					replay := r
					replay.PhysicalID = ""
					if out, err := f.handlers[r.Type].Create(f.base.root, replay); err == nil || out.PhysicalID != "" {
						t.Fatalf("adopted a native recreation of a retired incarnation: %+v %v", out, err)
					}
					if err := f.handlers[r.Type].Delete(f.base.root, r); err == nil {
						t.Fatal("retired owner deleted native recreation")
					}
					r.CloudControl = true
					if err := f.handlers[r.Type].Delete(f.base.root, r); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestComputeScalingPolicyAndScheduleRecoverPrivateOwnerAfterLostReply(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			group := f.base.group
			group.Data.AutoScalingGroupName = new(asgapi.XmlStringMaxLen255("workers"))
			group.Data.MinSize = new(asgapi.AutoScalingGroupMinSize(0))
			group.Data.MaxSize = new(asgapi.AutoScalingGroupMaxSize(2))
			group.Data.DesiredCapacity = new(asgapi.AutoScalingGroupDesiredCapacity(0))
			if err := f.asgRepo.Update(f.base.root, func(tx asg.Transaction) error { return tx.PutGroup(group) }); err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				kind, logical, operation string
				p                        cloudformation.Properties
			}{
				{cfnASGPolicyType, "Policy", "PutScalingPolicy", cloudformation.Properties{"AutoScalingGroupName": "workers", "PolicyType": "SimpleScaling", "AdjustmentType": "ChangeInCapacity", "ScalingAdjustment": 1, "Cooldown": 0}},
				{cfnASGScheduleType, "Schedule", "PutScheduledUpdateGroupAction", cloudformation.Properties{"AutoScalingGroupName": "workers", "StartTime": "2035-01-03T00:00:00Z", "MinSize": 0, "MaxSize": 2, "DesiredCapacity": 0}},
			} {
				boundary := &cfnComputeLostCreateReply{owner: f.groups, operation: test.operation, lose: true}
				handlers := CloudFormationComputeServiceHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"autoscaling": boundary}))
				r := f.request(test.kind, test.logical, test.p)
				admitted, err := handlers[r.Type].Create(f.base.root, r)
				var timeout *awswire.Error
				if admitted.PhysicalID == "" || !errors.As(err, &timeout) || timeout.Code != "RequestTimeout" {
					t.Fatalf("lost admitted %s: %+v %v", r.Type, admitted, err)
				}
				r.PhysicalID = admitted.PhysicalID
				read := r
				read.Properties = nil
				model, err := handlers[r.Type].(cloudformation.ResourceReader).Read(f.base.root, read)
				if err != nil {
					t.Fatal(err)
				}
				if model["AutoScalingGroupName"] != "workers" {
					t.Fatalf("admitted identifier lost native group identity: %+v", model)
				}
				nativeInput := cfnComputeCopy(test.p, "AutoScalingGroupName", "PolicyType", "AdjustmentType", "ScalingAdjustment", "Cooldown", "StartTime", "MinSize", "MaxSize", "DesiredCapacity")
				for _, name := range []string{"PolicyName", "ScheduledActionName"} {
					if value, present := model[name]; present {
						nativeInput[name] = value
					}
				}
				f.native(t, "autoscaling", test.operation, nativeInput)
				f.reopen(t)
				replay := r
				replay.PhysicalID = ""
				if out, err := f.handlers[r.Type].Create(f.base.root, replay); err != nil || out.PhysicalID != admitted.PhysicalID {
					t.Fatalf("native upsert lost private %s owner: %+v %v", r.Type, out, err)
				}
				wrong := r
				wrong.Token = "foreign-incarnation"
				if err := f.handlers[r.Type].Delete(f.base.root, wrong); err == nil {
					t.Fatalf("foreign incarnation deleted %s", r.Type)
				}
				if err := f.handlers[r.Type].Delete(f.base.root, r); err != nil {
					t.Fatalf("admitted owner cannot delete %s: %v", r.Type, err)
				}
			}
		})
	}
}

func TestComputeNativeServiceRoleProvisioningUsesCurrentScopedIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNComputeOwnerFixture(t, backend, nil)
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": f.identity})
			for _, service := range []string{ecs.ServicePrincipal, aas.ECSServicePrincipal} {
				var template iam.ServiceLinkedRoleTemplate
				for _, candidate := range f.identity.ServiceLinkedRoleTemplates() {
					if candidate.ServiceName == service {
						template = candidate
						break
					}
				}
				if template.RoleName == "" {
					t.Fatalf("missing authoritative role template for %s", service)
				}
				arn := "arn:aws:iam::123456789012:role/aws-service-role/" + service + "/" + template.RoleName
				policy := func(principal string) string {
					return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"` + arn + `","Condition":{"StringEquals":{"iam:AWSServiceName":"` + principal + `"}}}]}`
				}
				put := func(principal string) {
					t.Helper()
					if err := cfnComputeRun(f.base.root, commands, "iam", "PutUserPolicy", map[string]any{"UserName": f.base.user.UserName, "PolicyName": "compute-role", "PolicyDocument": policy(principal)}); err != nil {
						t.Fatal(err)
					}
				}
				put("unrelated.amazonaws.com")
				var rejection *awswire.Error
				if err := f.identity.EnsureServiceLinkedRole(f.base.caller, service); !errors.As(err, &rejection) || rejection.Code != "AccessDenied" {
					t.Fatalf("wrong service condition provisioned %s: %v", service, err)
				}
				if _, err := cfnComputeCall[iamapi.GetRoleOutput](f.base.root, commands, "iam", "GetRole", map[string]any{"RoleName": template.RoleName}); !cfnComputeMissing(err) {
					t.Fatalf("denied admission left a role for %s: %v", service, err)
				}
				put(service)
				if err := f.identity.EnsureServiceLinkedRole(f.base.caller, service); err != nil {
					t.Fatal(err)
				}
				if err := f.base.iam.View(f.base.root, func(tx iam.ReadTx) error {
					role, err := tx.Role(iam.Scope{Partition: "aws", AccountID: "123456789012"}, template.RoleName)
					if err != nil {
						return err
					}
					if role.Arn != arn || role.ServiceLinkedService != service || role.AssumeRolePolicyDocument != template.TrustPolicy {
						return fmt.Errorf("native sourced role authority mismatch: %+v", role)
					}
					for _, policyARN := range template.ManagedPolicyARNs {
						if _, ok := role.IdentityPolicies.Attached[policyARN]; !ok {
							return fmt.Errorf("native service policy %s is absent", policyARN)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func cfnComputeOwnedTags(r cloudformation.ResourceRequest) map[string]string {
	tags := make(map[string]string, len(r.Tags)+3)
	for key, value := range r.Tags {
		tags[key] = value
	}
	resource, _ := cfnComputeTags(r.Properties)
	for key, value := range resource {
		tags[key] = value
	}
	tags[cfnComputeTagPrefix+"stack-id"] = r.StackID
	tags[cfnComputeTagPrefix+"logical-id"] = r.LogicalID
	tags[cfnComputeTagPrefix+"incarnation"] = r.Token
	return tags
}
