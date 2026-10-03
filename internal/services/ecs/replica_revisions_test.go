package ecs

import (
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
)

// Exercise the real zero-task controller's retirement/deletion transitions: an
// old revision must outlive its execution snapshot, but not its service instance.
func TestServiceRevisionRetirementAndReadiness(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC))
	repository := NewMemoryRepository(nil)
	s := New(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
	key := ServiceKey{ClusterKey: ClusterKey{Scope: scopeFor(ctx), Name: "revisions"}, ServiceName: "zero"}
	record := ServiceRecord{Key: key, Data: api.Service{
		ServiceArn: new(api.String(key.ARN())), ServiceName: new(api.String(key.ServiceName)), ClusterArn: new(api.String(key.ClusterKey.ARN())),
		Status: new(api.String("ACTIVE")), DesiredCount: new(api.Integer(0)),
		DeploymentConfiguration: &api.DeploymentConfiguration{MaximumPercent: new(api.BoxedInteger(200)), MinimumHealthyPercent: new(api.BoxedInteger(100))},
	}}
	definition := TaskDefinitionRecord{Data: api.TaskDefinition{TaskDefinitionArn: new(api.String("arn:aws:ecs:us-east-1:000000000000:task-definition/revisions:1"))}}
	monitoring := &api.MonitoringConfiguration{MetricConfigurations: api.MetricConfigurationList{{MetricNames: api.MetricNamesList{"CPUUtilization"}, ResolutionSeconds: new(api.MetricResolutionSeconds(20))}}}
	readiness := &api.DescribeServicesInput{Cluster: new(api.String(key.Name)), Services: api.StringList{api.String(key.ServiceName)}}
	write := func(fn func(Transaction) error) {
		t.Helper()
		if err := repository.Update(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	write(func(tx Transaction) error {
		return tx.PutCluster(ClusterRecord{Key: key.ClusterKey, Data: api.Cluster{Status: new(api.String("ACTIVE"))}})
	})
	reconcile := func() {
		t.Helper()
		write(func(tx Transaction) error {
			var err error
			record, err = tx.Service(key)
			if err != nil {
				return err
			}
			_, err = s.reconcileService(tx.Context(), tx, &record, nil)
			return err
		})
	}
	var firstARN string
	for i := range 3 {
		for j := range record.Deployments {
			record.Deployments[j].Data.Status = new(api.String("ACTIVE"))
		}
		deployment := s.newServiceDeployment(ctx, record, definition, monitoring)
		record.Deployments = append([]ServiceDeployment{deployment}, record.Deployments...)
		if i == 0 {
			firstARN = deploymentRevisionKey(key, value(deployment.Data.Id)).ARN()
		}
		write(func(tx Transaction) error { return s.putService(tx, record) })
		if ready, err := s.HighResolutionReady(ctx, readiness, "CPUUtilization"); err != nil || ready {
			t.Fatalf("pending monitoring deployment ready=%v err=%v", ready, err)
		}
		reconcile()
		if ready, err := s.HighResolutionReady(ctx, readiness, "CPUUtilization"); err != nil || !ready {
			t.Fatalf("completed CPU monitoring ready=%v err=%v", ready, err)
		}
		if err := source.Advance(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if ready, err := s.HighResolutionReady(ctx, readiness, "MemoryUtilization"); err != nil || ready {
		t.Fatalf("CPU-only monitoring enabled memory: ready=%v err=%v", ready, err)
	}
	restricted := awsctx.FromContext(ctx)
	restricted.HasSessionPolicy = true
	restricted.SessionPolicies = []string{`{"Statement":[{"Effect":"Allow","Action":"ecs:*","Resource":"*"},{"Effect":"Deny","Action":"ecs:DescribeServiceRevisions","Resource":"*"}]}`}
	if ready, rejected := s.HighResolutionReady(awsctx.WithMetadata(ctx, restricted), readiness, "CPUUtilization"); ready || rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("readiness bypassed revision authorization: ready=%v err=%v", ready, rejected)
	}
	request := &api.DescribeServiceRevisionsInput{ServiceRevisionArns: api.StringList{api.String(firstARN)}}
	retained, err := s.DescribeServiceRevisions(ctx, request)
	if err != nil || len(retained.ServiceRevisions) != 1 || serviceMetricResolution(retained.ServiceRevisions[0].Monitoring, "CPUUtilization") != 20 {
		t.Fatalf("retired revision lost: out=%+v err=%v", retained, err)
	}
	// A consumer changing its returned monitoring must not mutate the archive.
	*retained.ServiceRevisions[0].Monitoring.MetricConfigurations[0].ResolutionSeconds = 60
	retained, err = s.DescribeServiceRevisions(ctx, request)
	if err != nil || len(retained.ServiceRevisions) != 1 || serviceMetricResolution(retained.ServiceRevisions[0].Monitoring, "CPUUtilization") != 20 {
		t.Fatalf("revision alias mutated archive: %v", err)
	}
	_, rejected := runCommand(s, ctx, "DeleteService", &api.DeleteServiceInput{Cluster: readiness.Cluster, Service: new(api.String(key.ServiceName))}, s.deleteService)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if _, rejected := s.DescribeServiceRevisions(ctx, request); rejected == nil || rejected.Code != "InvalidParameterException" {
		t.Fatalf("inactive service revision remained visible: %v", rejected)
	}
	record.Data.Status = new(api.String("ACTIVE"))
	record.Deployments = []ServiceDeployment{s.newServiceDeployment(ctx, record, definition, nil)}
	write(func(tx Transaction) error { return s.putService(tx, record) })
	retained, err = s.DescribeServiceRevisions(ctx, request)
	if err != nil || len(retained.ServiceRevisions) != 0 || len(retained.Failures) != 1 || value(retained.Failures[0].Reason) != "MISSING" {
		t.Fatalf("name reuse resurrected revision: out=%+v err=%v", retained, err)
	}
}
