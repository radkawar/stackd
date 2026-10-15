package ecs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
)

func terraformDeploymentFixture(t *testing.T) (*Service, *MemoryRepository, *clock.Manual, context.Context, ServiceRecord) {
	t.Helper()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	source := clock.NewManual(now)
	repository := NewMemoryRepository(nil)
	s := New(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	key := ServiceKey{ClusterKey: ClusterKey{Scope: scopeFor(ctx), Name: "deployments"}, ServiceName: "worker"}
	record := ServiceRecord{Key: key, Data: api.Service{
		ServiceArn: new(api.String(key.ARN())), ServiceName: new(api.String(key.ServiceName)), ClusterArn: new(api.String(key.ClusterKey.ARN())),
		Status: new(api.String("ACTIVE")), CreatedAt: new(now), DesiredCount: new(api.Integer(1)),
		DeploymentConfiguration: &api.DeploymentConfiguration{MaximumPercent: new(api.BoxedInteger(100)), MinimumHealthyPercent: new(api.BoxedInteger(100))},
	}}
	if err := repository.Update(ctx, func(tx Transaction) error {
		return tx.PutCluster(ClusterRecord{Key: key.ClusterKey, Data: api.Cluster{Status: new(api.String("ACTIVE"))}})
	}); err != nil {
		t.Fatal(err)
	}
	return s, repository, source, ctx, record
}

func putTerraformDeploymentFixture(t *testing.T, repository Repository, ctx context.Context, record ServiceRecord) {
	t.Helper()
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutService(record) }); err != nil {
		t.Fatal(err)
	}
}

func TestTerraformDeploymentScopedIdentitiesAndMissing(t *testing.T) {
	s, repository, source, ctx, record := terraformDeploymentFixture(t)
	deployment := s.newServiceDeployment(ctx, record, TaskDefinitionRecord{}, nil)
	deployment.Data.Id = new(api.String("ecs-svc/123456789"))
	record.Deployments = []ServiceDeployment{deployment}
	putTerraformDeploymentFixture(t, repository, ctx, record)
	arn := "arn:aws:ecs:us-east-1:123456789012:service-deployment/deployments/worker/123456789"
	revision := "arn:aws:ecs:us-east-1:123456789012:service-revision/deployments/worker/123456789"
	listed, rejected := runCommand(s, ctx, "ListServiceDeployments", &api.ListServiceDeploymentsInput{Cluster: new(api.String(record.Key.ClusterKey.ARN())), Service: new(api.String(record.Key.ARN()))}, s.listServiceDeployments)
	if rejected != nil || len(listed.ServiceDeployments) != 1 {
		t.Fatalf("list out=%+v err=%v", listed, rejected)
	}
	brief := listed.ServiceDeployments[0]
	if value(brief.ServiceDeploymentArn) != arn || value(brief.TargetServiceRevisionArn) != revision || value(brief.ServiceArn) != record.Key.ARN() || value(brief.ClusterArn) != record.Key.ClusterKey.ARN() || !brief.CreatedAt.Equal(source.Now()) || brief.FinishedAt != nil {
		t.Fatalf("scoped pending brief=%+v", brief)
	}
	missing := terraformDeploymentKey{ServiceKey: record.Key, ID: "999"}.ARN()
	described, rejected := runCommand(s, ctx, "DescribeServiceDeployments", &api.DescribeServiceDeploymentsInput{ServiceDeploymentArns: api.StringList{api.String(arn), api.String(missing)}}, s.describeServiceDeployments)
	if rejected != nil || len(described.ServiceDeployments) != 1 || len(described.Failures) != 1 || value(described.Failures[0].Arn) != missing || value(described.Failures[0].Reason) != "MISSING" || value(described.ServiceDeployments[0].TargetServiceRevision.Arn) != revision {
		t.Fatalf("describe out=%+v err=%v", described, rejected)
	}
	for _, invalid := range []string{
		strings.Replace(arn, "arn:aws:", "arn:aws-cn:", 1),
		strings.Replace(arn, "us-east-1", "us-west-2", 1),
		strings.Replace(arn, "123456789012:", "999999999999:", 1),
		strings.Replace(arn, "service-deployment/", "service-revision/", 1),
		"123456789", arn + "/extra", strings.TrimSuffix(arn, "123456789") + "+123456789",
	} {
		if _, rejected := runCommand(s, ctx, "DescribeServiceDeployments", &api.DescribeServiceDeploymentsInput{ServiceDeploymentArns: api.StringList{api.String(invalid)}}, s.describeServiceDeployments); rejected == nil || rejected.Code != "InvalidParameterException" {
			t.Fatalf("invalid ARN %q accepted: %v", invalid, rejected)
		}
	}
	if _, rejected := runCommand(s, ctx, "ListServiceDeployments", &api.ListServiceDeploymentsInput{Cluster: new(api.String(record.Key.Name)), Service: new(api.String(strings.Replace(record.Key.ARN(), "/deployments/", "/other/", 1)))}, s.listServiceDeployments); rejected == nil || rejected.Code != "InvalidParameterException" {
		t.Fatalf("cross cluster service accepted: %v", rejected)
	}
	other := terraformDeploymentKey{ServiceKey: record.Key, ID: "1"}
	other.ServiceName = "other"
	if _, rejected := runCommand(s, ctx, "DescribeServiceDeployments", &api.DescribeServiceDeploymentsInput{ServiceDeploymentArns: api.StringList{api.String(arn), api.String(other.ARN())}}, s.describeServiceDeployments); rejected == nil || rejected.Code != "InvalidParameterException" {
		t.Fatalf("cross service batch accepted: %v", rejected)
	}
}

func TestTerraformDeploymentFiltersAndStablePages(t *testing.T) {
	s, repository, source, ctx, record := terraformDeploymentFixture(t)
	base := source.Now()
	for i, rollout := range []string{"COMPLETED", "IN_PROGRESS", "FAILED", "COMPLETED", "IN_PROGRESS"} {
		deployment := s.newServiceDeployment(ctx, record, TaskDefinitionRecord{}, nil)
		deployment.Data.Id = new(api.String(fmt.Sprintf("ecs-svc/%d", i+1)))
		deployment.Data.CreatedAt = new(base.Add(time.Duration(i) * time.Second))
		deployment.Data.RolloutState = new(api.DeploymentRolloutState(rollout))
		if rollout != "IN_PROGRESS" {
			deployment.FinishedAt = deployment.Data.CreatedAt.Add(time.Second)
		}
		record.Deployments = append([]ServiceDeployment{deployment}, record.Deployments...)
	}
	putTerraformDeploymentFixture(t, repository, ctx, record)
	request := &api.ListServiceDeploymentsInput{Cluster: new(api.String(record.Key.Name)), Service: new(api.String(record.Key.ServiceName)), MaxResults: new(api.BoxedInteger(1)),
		CreatedAt: &api.CreatedAt{After: new(base), Before: new(base.Add(4 * time.Second))},
		Status:    api.ServiceDeploymentStatusList{api.ServiceDeploymentStatusSUCCESSFUL, api.ServiceDeploymentStatusIN_PROGRESS},
	}
	first, rejected := runCommand(s, ctx, "ListServiceDeployments", request, s.listServiceDeployments)
	if rejected != nil || len(first.ServiceDeployments) != 1 || first.NextToken == nil || value(first.ServiceDeployments[0].ServiceDeploymentArn) != (terraformDeploymentKey{ServiceKey: record.Key, ID: "2"}).ARN() {
		t.Fatalf("first filtered page=%+v err=%v", first, rejected)
	}
	// Retiring a deployment changes its storage slice, not its public keyset.
	record.DeploymentHistory = append(record.DeploymentHistory, terraformServiceDeployment(record, record.Deployments[1]))
	record.Deployments = append(record.Deployments[:1], record.Deployments[2:]...)
	putTerraformDeploymentFixture(t, repository, ctx, record)
	request.NextToken = first.NextToken
	request.Status = api.ServiceDeploymentStatusList{api.ServiceDeploymentStatusIN_PROGRESS, api.ServiceDeploymentStatusSUCCESSFUL, api.ServiceDeploymentStatusSUCCESSFUL}
	second, rejected := runCommand(s, ctx, "ListServiceDeployments", request, s.listServiceDeployments)
	if rejected != nil || len(second.ServiceDeployments) != 1 || second.NextToken != nil || value(second.ServiceDeployments[0].ServiceDeploymentArn) != (terraformDeploymentKey{ServiceKey: record.Key, ID: "4"}).ARN() {
		t.Fatalf("stable second page=%+v err=%v", second, rejected)
	}
	request.CreatedAt.Before = new(base.Add(3 * time.Second))
	if _, rejected := runCommand(s, ctx, "ListServiceDeployments", request, s.listServiceDeployments); rejected == nil || rejected.Code != "InvalidParameterException" {
		t.Fatalf("filter-bound token accepted: %v", rejected)
	}
	request.NextToken = nil
	request.Status = api.ServiceDeploymentStatusList{api.ServiceDeploymentStatusSTOPPED}
	request.CreatedAt = nil
	failed, rejected := runCommand(s, ctx, "ListServiceDeployments", request, s.listServiceDeployments)
	if rejected != nil || len(failed.ServiceDeployments) != 1 || value(failed.ServiceDeployments[0].Status) != "STOPPED" || failed.ServiceDeployments[0].FinishedAt == nil {
		t.Fatalf("failed filter=%+v err=%v", failed, rejected)
	}
	request.Status = api.ServiceDeploymentStatusList{"FAILED"}
	if _, rejected := runCommand(s, ctx, "ListServiceDeployments", request, s.listServiceDeployments); rejected == nil || rejected.Code != "InvalidParameterException" {
		t.Fatalf("non-native status accepted: %v", rejected)
	}
}

func TestTerraformDeploymentRealHealthyRolloutAndFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			s, repository, source, ctx, record := terraformDeploymentFixture(t)
			definition := api.TaskDefinition{ContainerDefinitions: api.ContainerDefinitions{{Name: new(api.String("worker")), Essential: new(api.BoxedBoolean(true)), HealthCheck: &api.HealthCheck{Command: api.StringList{"CMD-SHELL", "true"}}}}}
			deployment := s.newServiceDeployment(ctx, record, TaskDefinitionRecord{Data: definition}, nil)
			record.Deployments = []ServiceDeployment{deployment}
			task := TaskRecord{Key: TaskKey{ClusterKey: record.Key.ClusterKey, ID: "native-task"}, ServiceName: record.Key.ServiceName, ServiceDeploymentID: value(deployment.Data.Id), Definition: definition,
				Data: api.Task{TaskArn: new(api.String("native-task")), LastStatus: new(api.String("RUNNING")), DesiredStatus: new(api.String("RUNNING")), StartedAt: new(source.Now()), HealthStatus: new(api.HealthStatus("UNKNOWN"))},
			}
			if failed {
				record.Data.DeploymentConfiguration.DeploymentCircuitBreaker = &api.DeploymentCircuitBreaker{Enable: new(api.Boolean(true)), Rollback: new(api.Boolean(false))}
				record.Deployments[0].Failures = 2
				task.Data.LastStatus = new(api.String("STOPPED"))
				task.Data.DesiredStatus = new(api.String("STOPPED"))
				task.Data.StopCode = new(api.TaskStopCode("TaskFailedToStart"))
			}
			if err := repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutService(record); err != nil {
					return err
				}
				return tx.PutTask(task)
			}); err != nil {
				t.Fatal(err)
			}
			arn := terraformDeploymentID(record.Key, value(deployment.Data.Id)).ARN()
			read := func(want string) api.ServiceDeployment {
				t.Helper()
				out, rejected := runCommand(s, ctx, "DescribeServiceDeployments", &api.DescribeServiceDeploymentsInput{ServiceDeploymentArns: api.StringList{api.String(arn)}}, s.describeServiceDeployments)
				if rejected != nil || len(out.ServiceDeployments) != 1 || value(out.ServiceDeployments[0].Status) != want {
					t.Fatalf("want %s out=%+v err=%v", want, out, rejected)
				}
				return out.ServiceDeployments[0]
			}
			read("IN_PROGRESS")
			reconcile := func() {
				t.Helper()
				if err := repository.Update(ctx, func(tx Transaction) error {
					r, err := tx.Service(record.Key)
					if err != nil {
						return err
					}
					_, err = s.reconcileService(tx.Context(), tx, &r, nil)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			reconcile()
			if failed {
				out := read("STOPPED")
				if out.FinishedAt == nil || out.StoppedAt == nil || !out.FinishedAt.Equal(source.Now()) || !strings.Contains(value(out.StatusReason), "circuit breaker") {
					t.Fatalf("native failed rollout lost terminal details: %+v", out)
				}
				return
			}
			if out := read("IN_PROGRESS"); out.FinishedAt != nil || *out.TargetServiceRevision.RunningTaskCount != 1 {
				t.Fatalf("running but unhealthy rollout completed: %+v", out)
			}
			if err := source.Advance(24 * time.Hour); err != nil {
				t.Fatal(err)
			}
			reconcile()
			read("IN_PROGRESS")
			task.Data.HealthStatus = new(api.HealthStatus("HEALTHY"))
			if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutTask(task) }); err != nil {
				t.Fatal(err)
			}
			reconcile()
			out := read("SUCCESSFUL")
			if out.FinishedAt == nil || !out.FinishedAt.Equal(source.Now()) || out.StoppedAt != nil {
				t.Fatalf("native healthy completion timestamp=%+v", out)
			}
			finished := *out.FinishedAt
			if err := source.Advance(time.Hour); err != nil {
				t.Fatal(err)
			}
			reconcile()
			if out := read("SUCCESSFUL"); !out.FinishedAt.Equal(finished) {
				t.Fatalf("completion timestamp drifted: %+v", out)
			}
		})
	}
}

func TestTerraformDeploymentAuthorization(t *testing.T) {
	s, repository, _, ctx, record := terraformDeploymentFixture(t)
	deployment := s.newServiceDeployment(ctx, record, TaskDefinitionRecord{}, nil)
	record.Deployments = []ServiceDeployment{deployment}
	putTerraformDeploymentFixture(t, repository, ctx, record)
	arn := terraformDeploymentID(record.Key, value(deployment.Data.Id)).ARN()
	list := &api.ListServiceDeploymentsInput{Cluster: new(api.String(record.Key.Name)), Service: new(api.String(record.Key.ServiceName))}
	describe := &api.DescribeServiceDeploymentsInput{ServiceDeploymentArns: api.StringList{api.String(arn)}}
	metadata := awsctx.FromContext(ctx)
	metadata.HasSessionPolicy = true
	metadata.SessionPolicies = []string{fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"ecs:ListServiceDeployments","Resource":%q,"Condition":{"StringEquals":{"ecs:cluster":%q,"ecs:service":%q}}},{"Effect":"Allow","Action":"ecs:DescribeServiceDeployments","Resource":%q,"Condition":{"StringEquals":{"ecs:service":%q}}}]}`, record.Key.ARN(), record.Key.ClusterKey.ARN(), record.Key.ARN(), arn, record.Key.ARN())}
	restricted := awsctx.WithMetadata(ctx, metadata)
	if _, rejected := runCommand(s, restricted, "ListServiceDeployments", list, s.listServiceDeployments); rejected != nil {
		t.Fatalf("scoped list denied: %v", rejected)
	}
	if _, rejected := runCommand(s, restricted, "DescribeServiceDeployments", describe, s.describeServiceDeployments); rejected != nil {
		t.Fatalf("scoped describe denied: %v", rejected)
	}
	metadata.SessionPolicies = []string{`{"Statement":[{"Effect":"Allow","Action":"ecs:*","Resource":"*"},{"Effect":"Deny","Action":["ecs:ListServiceDeployments","ecs:DescribeServiceDeployments"],"Resource":"*"}]}`}
	restricted = awsctx.WithMetadata(ctx, metadata)
	if _, rejected := runCommand(s, restricted, "ListServiceDeployments", list, s.listServiceDeployments); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("list bypassed authorization: %v", rejected)
	}
	if _, rejected := runCommand(s, restricted, "DescribeServiceDeployments", describe, s.describeServiceDeployments); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("describe bypassed authorization: %v", rejected)
	}
}

func TestTerraformDeploymentRetirementPreservesTerminalSnapshot(t *testing.T) {
	s, repository, source, ctx, record := terraformDeploymentFixture(t)
	record.Data.DesiredCount = new(api.Integer(0))
	var firstARN string
	for i := range 3 {
		for j := range record.Deployments {
			record.Deployments[j].Data.Status = new(api.String("ACTIVE"))
		}
		deployment := s.newServiceDeployment(ctx, record, TaskDefinitionRecord{}, nil)
		if i == 0 {
			firstARN = terraformDeploymentID(record.Key, value(deployment.Data.Id)).ARN()
		}
		record.Deployments = append([]ServiceDeployment{deployment}, record.Deployments...)
		putTerraformDeploymentFixture(t, repository, ctx, record)
		if err := repository.Update(ctx, func(tx Transaction) error {
			var err error
			record, err = tx.Service(record.Key)
			if err != nil {
				return err
			}
			_, err = s.reconcileService(tx.Context(), tx, &record, nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := source.Advance(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if len(record.DeploymentHistory) != 1 {
		t.Fatalf("native retirement did not retain history: %+v", record.DeploymentHistory)
	}
	request := &api.DescribeServiceDeploymentsInput{ServiceDeploymentArns: api.StringList{api.String(firstARN)}}
	out, rejected := runCommand(s, ctx, "DescribeServiceDeployments", request, s.describeServiceDeployments)
	if rejected != nil || len(out.ServiceDeployments) != 1 || value(out.ServiceDeployments[0].Status) != "SUCCESSFUL" || out.ServiceDeployments[0].FinishedAt == nil || !out.ServiceDeployments[0].FinishedAt.Equal(*record.Data.CreatedAt) {
		t.Fatalf("retired deployment lost: out=%+v err=%v", out, rejected)
	}
	*out.ServiceDeployments[0].Status = "IN_PROGRESS"
	*out.ServiceDeployments[0].TargetServiceRevision.Arn = "mutated"
	out, rejected = runCommand(s, ctx, "DescribeServiceDeployments", request, s.describeServiceDeployments)
	if rejected != nil || value(out.ServiceDeployments[0].Status) != "SUCCESSFUL" || value(out.ServiceDeployments[0].TargetServiceRevision.Arn) == "mutated" {
		t.Fatalf("retired read mutated durable state: out=%+v err=%v", out, rejected)
	}
}
