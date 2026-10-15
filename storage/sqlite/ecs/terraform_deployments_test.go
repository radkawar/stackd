package ecs_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	owner "stackd/internal/services/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite"
	ecsstore "stackd/storage/sqlite/ecs"
)

func terraformDeploymentCommand(t *testing.T, service *owner.Service, ctx context.Context, operation string, input any) any {
	t.Helper()
	model, ok := awscatalog.LookupService("ecs")
	if !ok {
		t.Fatal("missing ECS model")
	}
	op, ok := model.Operation(operation)
	if !ok {
		t.Fatalf("missing ECS operation %s", operation)
	}
	out, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		t.Fatalf("%s: %v", operation, rejected)
	}
	return out
}

func TestTerraformDeploymentHistoryAndFinishSurviveSQLiteReopen(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	path := filepath.Join(t.TempDir(), "deployments.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := ecsstore.New(db)
	created := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	finished := created.Add(time.Minute)
	updated := finished.Add(time.Hour)
	key := domain.ServiceKey{ClusterKey: domain.ClusterKey{Scope: domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "durable"}, ServiceName: "worker"}
	arn := "arn:aws:ecs:us-east-1:123456789012:service-deployment/durable/worker/2"
	retiredARN := "arn:aws:ecs:us-east-1:123456789012:service-deployment/durable/worker/1"
	revisionARN := "arn:aws:ecs:us-east-1:123456789012:service-revision/durable/worker/1"
	record := domain.ServiceRecord{Key: key, Data: api.Service{Status: new(api.String("ACTIVE")), ServiceArn: new(api.String(key.ARN())), ClusterArn: new(api.String(key.ClusterKey.ARN())), ServiceName: new(api.String(key.ServiceName)), CreatedAt: new(created), DesiredCount: new(api.Integer(0))},
		Deployments: []domain.ServiceDeployment{{Completed: true, FinishedAt: finished, Data: api.Deployment{
			Id: new(api.String("ecs-svc/2")), Status: new(api.String("PRIMARY")), RolloutState: new(api.DeploymentRolloutState("COMPLETED")), RolloutStateReason: new(api.String("ECS deployment completed.")),
			CreatedAt: new(created), UpdatedAt: new(updated), DesiredCount: new(api.Integer(0)), RunningCount: new(api.Integer(0)), PendingCount: new(api.Integer(0)),
		}}},
		DeploymentHistory: api.ServiceDeployments{{
			ServiceDeploymentArn: new(api.String(retiredARN)), ServiceArn: new(api.String(key.ARN())), ClusterArn: new(api.String(key.ClusterKey.ARN())),
			CreatedAt: new(created.Add(-time.Hour)), StartedAt: new(created.Add(-time.Hour)), UpdatedAt: new(created), FinishedAt: new(created),
			Status: new(api.ServiceDeploymentStatus("SUCCESSFUL")), StatusReason: new(api.String("ECS deployment completed.")),
			TargetServiceRevision: &api.ServiceRevisionSummary{Arn: new(api.String(revisionARN)), RequestedTaskCount: new(api.Integer(0)), RunningTaskCount: new(api.Integer(0)), PendingTaskCount: new(api.Integer(0))},
		}},
	}
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutCluster(domain.ClusterRecord{Key: key.ClusterKey, Data: api.Cluster{Status: new(api.String("ACTIVE")), ClusterArn: new(api.String(key.ClusterKey.ARN())), ClusterName: new(api.String(key.Name))}}); err != nil {
			return err
		}
		return tx.PutService(record)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	repository = ecsstore.New(db)
	service := owner.New(owner.Config{Repository: repository, Clock: clock.NewManual(updated)})
	t.Cleanup(func() { _ = service.Close() })
	if err := repository.View(ctx, func(r domain.Reader) error {
		stored, err := r.Service(key)
		if err != nil {
			return err
		}
		if len(stored.Deployments) != 1 || !stored.Deployments[0].FinishedAt.Equal(finished) || len(stored.DeploymentHistory) != 1 {
			t.Fatalf("reopened native timestamps/history=%+v", stored)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	list := terraformDeploymentCommand(t, service, ctx, "ListServiceDeployments", &api.ListServiceDeploymentsInput{Cluster: new(api.String(key.Name)), Service: new(api.String(key.ServiceName)), MaxResults: new(api.BoxedInteger(1)), Status: api.ServiceDeploymentStatusList{"SUCCESSFUL"}}).(*api.ListServiceDeploymentsOutput)
	if len(list.ServiceDeployments) != 1 || list.NextToken == nil || string(*list.ServiceDeployments[0].ServiceDeploymentArn) != retiredARN || !list.ServiceDeployments[0].FinishedAt.Equal(created) {
		t.Fatalf("reopened first page=%+v", list)
	}
	page := terraformDeploymentCommand(t, service, ctx, "ListServiceDeployments", &api.ListServiceDeploymentsInput{Cluster: new(api.String(key.Name)), Service: new(api.String(key.ServiceName)), NextToken: list.NextToken, MaxResults: new(api.BoxedInteger(1)), Status: api.ServiceDeploymentStatusList{"SUCCESSFUL"}}).(*api.ListServiceDeploymentsOutput)
	if len(page.ServiceDeployments) != 1 || page.NextToken != nil || string(*page.ServiceDeployments[0].ServiceDeploymentArn) != arn || !page.ServiceDeployments[0].FinishedAt.Equal(finished) {
		t.Fatalf("reopened second page=%+v", page)
	}
	describe := &api.DescribeServiceDeploymentsInput{ServiceDeploymentArns: api.StringList{api.String(retiredARN), api.String(arn)}}
	out := terraformDeploymentCommand(t, service, ctx, "DescribeServiceDeployments", describe).(*api.DescribeServiceDeploymentsOutput)
	if len(out.ServiceDeployments) != 2 || len(out.Failures) != 0 || string(*out.ServiceDeployments[0].TargetServiceRevision.Arn) != revisionARN || !out.ServiceDeployments[1].FinishedAt.Equal(finished) || !out.ServiceDeployments[1].UpdatedAt.Equal(updated) {
		t.Fatalf("reopened describe=%+v", out)
	}
	*out.ServiceDeployments[0].TargetServiceRevision.Arn = "mutated"
	out = terraformDeploymentCommand(t, service, ctx, "DescribeServiceDeployments", describe).(*api.DescribeServiceDeploymentsOutput)
	if string(*out.ServiceDeployments[0].TargetServiceRevision.Arn) != revisionARN {
		t.Fatal("returned history aliases durable revision summary")
	}
	// Replacing the service instance must remove old read-history rows too.
	record.Deployments, record.DeploymentHistory = nil, nil
	if err := repository.Update(ctx, func(tx domain.Transaction) error { return tx.PutService(record) }); err != nil {
		t.Fatal(err)
	}
	out = terraformDeploymentCommand(t, service, ctx, "DescribeServiceDeployments", describe).(*api.DescribeServiceDeploymentsOutput)
	if len(out.ServiceDeployments) != 0 || len(out.Failures) != 2 {
		t.Fatalf("replacement retained old deployments=%+v", out)
	}
	if err := repository.View(ctx, func(r domain.Reader) error {
		stored, err := r.Service(key)
		if err == nil && (stored.Deployments != nil || stored.DeploymentHistory != nil) {
			t.Fatalf("nil owned collections changed presence: %+v", stored)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
