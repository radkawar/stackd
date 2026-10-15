package ecs

import (
	"context"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func capacityProviderTestCluster(t *testing.T) (*Service, *MemoryRepository, context.Context, ClusterKey) {
	t.Helper()
	repository := NewMemoryRepository(nil)
	s := New(Config{Repository: repository, Clock: clock.NewManual(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
	key := ClusterKey{Scope: scopeFor(ctx), Name: "capacity"}
	creation := api.CreateClusterInput{ClusterName: new(api.String(key.Name))}
	data := newCluster(key, creation)
	data.Tags = nil
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutCluster(ClusterRecord{Key: key, Data: data, CreateInput: creation}); err != nil {
			return err
		}
		return tx.PutTags(TagRecord{Key: TagKey{Scope: key.Scope, ResourceARN: key.ARN()}, Tags: api.Tags{{Key: new(api.TagKey("Environment")), Value: new(api.TagValue("test"))}}})
	}); err != nil {
		t.Fatal(err)
	}
	return s, repository, ctx, key
}

func fargateCapacityProviderUpdate(key ClusterKey) *api.PutClusterCapacityProvidersInput {
	return &api.PutClusterCapacityProvidersInput{
		Cluster: new(api.String(key.ARN())), CapacityProviders: api.StringList{"FARGATE"},
		DefaultCapacityProviderStrategy: api.CapacityProviderStrategy{{CapacityProvider: new(api.String("FARGATE")), Weight: new(api.CapacityProviderStrategyItemWeight(1)), Base: new(api.CapacityProviderStrategyItemBase(0))}},
	}
}

func putTestCapacityProviders(s *Service, ctx context.Context, in *api.PutClusterCapacityProvidersInput) (*api.PutClusterCapacityProvidersOutput, *awswire.Error) {
	var out *api.PutClusterCapacityProvidersOutput
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		out, err = s.putClusterCapacityProviders(tx.Context(), tx, in)
		return err
	})
	return out, wireError(err)
}

func TestPutClusterCapacityProvidersPersistsLaunchInputs(t *testing.T) {
	s, repository, ctx, key := capacityProviderTestCluster(t)
	in := fargateCapacityProviderUpdate(key)
	out, rejected := putTestCapacityProviders(s, ctx, in)
	if rejected != nil || out == nil || !reflect.DeepEqual(out.Cluster.CapacityProviders, in.CapacityProviders) || !reflect.DeepEqual(out.Cluster.DefaultCapacityProviderStrategy, in.DefaultCapacityProviderStrategy) {
		t.Fatalf("update=%+v rejected=%v", out, rejected)
	}
	// Returned and caller-owned values cannot mutate the committed cluster.
	*out.Cluster.DefaultCapacityProviderStrategy[0].Weight = 99
	*in.DefaultCapacityProviderStrategy[0].Weight = 77
	in.CapacityProviders[0] = "FARGATE_SPOT"
	if err := repository.Update(ctx, func(tx Transaction) error {
		record, err := tx.Cluster(key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(record.Data.DefaultCapacityProviderStrategy, fargateCapacityProviderUpdate(key).DefaultCapacityProviderStrategy) || len(record.CreateInput.CapacityProviders) != 0 || len(record.CreateInput.DefaultCapacityProviderStrategy) != 0 || record.Data.Tags != nil {
			t.Fatalf("committed cluster or creation arguments changed: %+v", record)
		}
		launch, provider, rejected := taskLaunchType(&api.RunTaskInput{}, record.Data)
		if rejected != nil || launch != "FARGATE" || provider != "FARGATE" {
			t.Fatalf("RunTask default launch=%s provider=%s rejected=%v", launch, provider, rejected)
		}
		launch, provider, rejected = taskLaunchType(&api.RunTaskInput{LaunchType: new(api.LaunchType("FARGATE"))}, record.Data)
		if rejected != nil || launch != "FARGATE" || provider != "" {
			t.Fatalf("explicit launch overridden: launch=%s provider=%s rejected=%v", launch, provider, rejected)
		}
		// CreateService snapshots this authoritative default into its service
		// strategy; the actual scheduler then uses these shared execution helpers.
		service := ServiceRecord{Key: ServiceKey{ClusterKey: key, ServiceName: "default"}, Data: api.Service{ClusterArn: record.Data.ClusterArn, DesiredCount: new(api.Integer(1)), CapacityProviderStrategy: api.CloneCapacityProviderStrategy(record.Data.DefaultCapacityProviderStrategy)}}
		if err := validateServiceCapacity(service.Data.CapacityProviderStrategy); err != nil {
			t.Fatal(err)
		}
		input := serviceTaskInput(service)
		deployment := s.newServiceDeployment(ctx, service, TaskDefinitionRecord{}, nil)
		if input.LaunchType != nil || !reflect.DeepEqual(input.CapacityProviderStrategy, record.Data.DefaultCapacityProviderStrategy) || !reflect.DeepEqual(deployment.Input.CapacityProviderStrategy, input.CapacityProviderStrategy) {
			t.Fatal("service scheduler lost the persisted capacity strategy")
		}
		launch, provider, rejected = taskLaunchType(&deployment.Input, record.Data)
		if rejected != nil || launch != "FARGATE" || provider != "FARGATE" {
			t.Fatalf("service launch=%s provider=%s rejected=%v", launch, provider, rejected)
		}
		described, err := s.describeClusters(ctx, tx, &api.DescribeClustersInput{Clusters: api.StringList{api.String(key.Name)}})
		if err != nil {
			return err
		}
		if len(described.Clusters) != 1 || !reflect.DeepEqual(described.Clusters[0].DefaultCapacityProviderStrategy, input.CapacityProviderStrategy) {
			t.Fatal("DescribeClusters did not project persisted default strategy")
		}
		return tx.PutTask(TaskRecord{Key: TaskKey{ClusterKey: key, ID: "existing"}, Data: api.Task{LastStatus: new(api.String("RUNNING")), CapacityProviderName: new(api.String("FARGATE"))}})
	}); err != nil {
		t.Fatal(err)
	}
	// No-change Terraform applies work even while real provider-backed tasks run.
	first, rejected := putTestCapacityProviders(s, ctx, fargateCapacityProviderUpdate(key))
	if rejected != nil {
		t.Fatal(rejected)
	}
	second, rejected := putTestCapacityProviders(s, ctx, fargateCapacityProviderUpdate(key))
	if rejected != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("no-change update=%+v rejected=%v", second, rejected)
	}
}

func TestPutClusterCapacityProvidersInvalidSettings(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		change func(*api.PutClusterCapacityProvidersInput)
		code   string
	}{
		{"duplicate association", func(in *api.PutClusterCapacityProvidersInput) {
			in.CapacityProviders = api.StringList{"FARGATE", "FARGATE"}
		}, "InvalidParameterException"},
		{"unassociated strategy", func(in *api.PutClusterCapacityProvidersInput) { in.CapacityProviders = api.StringList{} }, "InvalidParameterException"},
		{"duplicate strategy", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy = append(in.DefaultCapacityProviderStrategy, in.DefaultCapacityProviderStrategy[0])
		}, "InvalidParameterException"},
		{"negative base", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy[0].Base = new(api.CapacityProviderStrategyItemBase(-1))
		}, "InvalidParameterException"},
		{"excessive base", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy[0].Base = new(api.CapacityProviderStrategyItemBase(100001))
		}, "InvalidParameterException"},
		{"negative weight", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy[0].Weight = new(api.CapacityProviderStrategyItemWeight(-1))
		}, "InvalidParameterException"},
		{"excessive weight", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy[0].Weight = new(api.CapacityProviderStrategyItemWeight(1001))
		}, "InvalidParameterException"},
		{"zero weight", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy[0].Weight = new(api.CapacityProviderStrategyItemWeight(0))
		}, "InvalidParameterException"},
		{"omitted weight", func(in *api.PutClusterCapacityProvidersInput) { in.DefaultCapacityProviderStrategy[0].Weight = nil }, "InvalidParameterException"},
		{"spot association", func(in *api.PutClusterCapacityProvidersInput) {
			in.CapacityProviders = append(in.CapacityProviders, "FARGATE_SPOT")
		}, "NotImplementedException"},
		{"custom association", func(in *api.PutClusterCapacityProvidersInput) {
			in.CapacityProviders = append(in.CapacityProviders, "custom")
		}, "NotImplementedException"},
		{"missing strategy provider", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy[0].CapacityProvider = nil
		}, "InvalidParameterException"},
		{"too many associations", func(in *api.PutClusterCapacityProvidersInput) { in.CapacityProviders = make(api.StringList, 21) }, "InvalidParameterException"},
		{"too many strategies", func(in *api.PutClusterCapacityProvidersInput) {
			in.DefaultCapacityProviderStrategy = make(api.CapacityProviderStrategy, 21)
		}, "InvalidParameterException"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s, repository, ctx, key := capacityProviderTestCluster(t)
			in := fargateCapacityProviderUpdate(key)
			scenario.change(in)
			if out, rejected := putTestCapacityProviders(s, ctx, in); out != nil || rejected == nil || rejected.Code != scenario.code {
				t.Fatalf("out=%+v rejected=%v; want %s", out, rejected, scenario.code)
			}
			if err := repository.View(ctx, func(r Reader) error {
				record, err := r.Cluster(key)
				if err == nil && (len(record.Data.CapacityProviders) != 0 || len(record.Data.DefaultCapacityProviderStrategy) != 0) {
					t.Fatal("rejected update persisted settings")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPutClusterCapacityProvidersAuthorizationAndMissingCluster(t *testing.T) {
	s, repository, ctx, key := capacityProviderTestCluster(t)
	restricted := awsctx.FromContext(ctx)
	restricted.HasSessionPolicy = true
	restricted.SessionPolicies = []string{`{"Statement":[{"Effect":"Allow","Action":"ecs:*","Resource":"*"},{"Effect":"Deny","Action":"ecs:PutClusterCapacityProviders","Resource":"*"}]}`}
	if _, rejected := putTestCapacityProviders(s, awsctx.WithMetadata(ctx, restricted), fargateCapacityProviderUpdate(key)); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("denied update=%v", rejected)
	}
	restricted.SessionPolicies = []string{`{"Statement":[{"Effect":"Allow","Action":"ecs:PutClusterCapacityProviders","Resource":"` + key.ARN() + `","Condition":{"StringEquals":{"aws:ResourceTag/Environment":"test"},"ForAllValues:StringEquals":{"ecs:capacity-provider":"FARGATE"}}}]}`}
	if _, rejected := putTestCapacityProviders(s, awsctx.WithMetadata(ctx, restricted), fargateCapacityProviderUpdate(key)); rejected != nil {
		t.Fatalf("tag/provider conditional update=%v", rejected)
	}
	disallowed := fargateCapacityProviderUpdate(key)
	disallowed.CapacityProviders = api.StringList{"FARGATE_SPOT"}
	if _, rejected := putTestCapacityProviders(s, awsctx.WithMetadata(ctx, restricted), disallowed); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("provider conditional restriction bypassed: %v", rejected)
	}
	missing := key
	missing.Name = "missing"
	if _, rejected := putTestCapacityProviders(s, ctx, fargateCapacityProviderUpdate(missing)); rejected == nil || rejected.Code != "ClusterNotFoundException" {
		t.Fatalf("missing cluster=%v", rejected)
	}
	if err := repository.Update(ctx, func(tx Transaction) error {
		_, err := s.deleteCluster(ctx, tx, &api.DeleteClusterInput{Cluster: new(api.String(key.Name))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, rejected := putTestCapacityProviders(s, ctx, fargateCapacityProviderUpdate(key)); rejected == nil || rejected.Code != "ClientException" {
		t.Fatalf("inactive cluster=%v", rejected)
	}
}

func TestPutClusterCapacityProvidersRemovalDependenciesAndClear(t *testing.T) {
	for _, scenario := range []struct {
		name             string
		taskStatus       string
		taskProvider     string
		serviceStatus    string
		serviceStrategy  bool
		deploymentStatus string
		blocked          bool
	}{
		{name: "running provider task", taskStatus: "RUNNING", taskProvider: "FARGATE", blocked: true},
		{name: "provisioning provider task", taskStatus: "PROVISIONING", taskProvider: "FARGATE", blocked: true},
		{name: "deprovisioning provider task", taskStatus: "DEPROVISIONING", taskProvider: "FARGATE", blocked: true},
		{name: "stopped provider task", taskStatus: "STOPPED", taskProvider: "FARGATE"},
		{name: "explicit launch task", taskStatus: "RUNNING"},
		{name: "active service", serviceStatus: "ACTIVE", serviceStrategy: true, blocked: true},
		{name: "draining service", serviceStatus: "DRAINING", serviceStrategy: true, blocked: true},
		{name: "inactive service", serviceStatus: "INACTIVE", serviceStrategy: true},
		{name: "old active deployment", serviceStatus: "ACTIVE", deploymentStatus: "ACTIVE", blocked: true},
		{name: "retired deployment", serviceStatus: "ACTIVE", deploymentStatus: "INACTIVE"},
		{name: "empty cluster"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s, repository, ctx, key := capacityProviderTestCluster(t)
			if _, rejected := putTestCapacityProviders(s, ctx, fargateCapacityProviderUpdate(key)); rejected != nil {
				t.Fatal(rejected)
			}
			if err := repository.Update(ctx, func(tx Transaction) error {
				if scenario.taskStatus != "" {
					task := TaskRecord{Key: TaskKey{ClusterKey: key, ID: "dependency"}, Data: api.Task{LastStatus: new(api.String(scenario.taskStatus)), LaunchType: new(api.LaunchType("FARGATE"))}}
					if scenario.taskProvider != "" {
						task.Data.CapacityProviderName = new(api.String(scenario.taskProvider))
					}
					if err := tx.PutTask(task); err != nil {
						return err
					}
				}
				if scenario.serviceStatus != "" {
					service := ServiceRecord{Key: ServiceKey{ClusterKey: key, ServiceName: "dependency"}, Data: api.Service{Status: new(api.String(scenario.serviceStatus)), LaunchType: new(api.LaunchType("FARGATE"))}}
					if scenario.serviceStrategy {
						service.Data.CapacityProviderStrategy = fargateCapacityProviderUpdate(key).DefaultCapacityProviderStrategy
						service.Data.LaunchType = nil
					}
					if scenario.deploymentStatus != "" {
						service.Deployments = []ServiceDeployment{{Data: api.Deployment{Status: new(api.String(scenario.deploymentStatus))}, Input: api.RunTaskInput{CapacityProviderStrategy: fargateCapacityProviderUpdate(key).DefaultCapacityProviderStrategy}}}
					}
					return tx.PutService(service)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Changing the default alone never rewrites existing service/task intent.
			withoutDefault := fargateCapacityProviderUpdate(key)
			withoutDefault.DefaultCapacityProviderStrategy = api.CapacityProviderStrategy{}
			if _, rejected := putTestCapacityProviders(s, ctx, withoutDefault); rejected != nil {
				t.Fatal(rejected)
			}
			clear := &api.PutClusterCapacityProvidersInput{Cluster: new(api.String(key.Name)), CapacityProviders: api.StringList{}, DefaultCapacityProviderStrategy: api.CapacityProviderStrategy{}}
			out, rejected := putTestCapacityProviders(s, ctx, clear)
			if scenario.blocked {
				if rejected == nil || rejected.Code != "ResourceInUseException" {
					t.Fatalf("dependency allowed removal: out=%+v rejected=%v", out, rejected)
				}
				return
			}
			if rejected != nil || len(out.Cluster.CapacityProviders) != 0 || len(out.Cluster.DefaultCapacityProviderStrategy) != 0 {
				t.Fatalf("clear=%+v rejected=%v", out, rejected)
			}
			if _, rejected := putTestCapacityProviders(s, ctx, clear); rejected != nil {
				t.Fatalf("idempotent clear=%v", rejected)
			}
			if err := repository.View(ctx, func(r Reader) error {
				record, err := r.Cluster(key)
				if err != nil {
					return err
				}
				launch, provider, rejected := taskLaunchType(&api.RunTaskInput{}, record.Data)
				if len(record.Data.CapacityProviders) != 0 || len(record.Data.DefaultCapacityProviderStrategy) != 0 || rejected != nil || launch != "FARGATE" || provider != "" {
					t.Fatal("clear did not persist or launch selection retained a provider")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
