package kafka

import (
	"context"
	"errors"
	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"testing"
	"time"
)

type controlledRuntime struct {
	ensure func(context.Context, Specification) (Endpoint, error)
	status func(context.Context, Specification) (Endpoint, error)
}

func (r controlledRuntime) Ensure(ctx context.Context, v Specification) (Endpoint, error) {
	return r.ensure(ctx, v)
}
func (r controlledRuntime) Status(ctx context.Context, v Specification) (Endpoint, error) {
	return r.status(ctx, v)
}
func (controlledRuntime) Reboot(context.Context, Specification, int32) (Endpoint, error) {
	return Endpoint{}, errors.New("unexpected reboot")
}
func (controlledRuntime) Delete(context.Context, Specification) error {
	return errors.New("unexpected deletion")
}
func (controlledRuntime) Close() error { return nil }
func retainedCluster(now time.Time) ClusterRecord {
	return ClusterRecord{Scope: Scope{"aws", "111111111111", "us-east-1"}, ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/incarnation", Name: "owned", Incarnation: "incarnation", KafkaVersion: "3.7.1", SecurityMode: "PLAINTEXT", Brokers: 1, State: "CREATING", Operation: "create", Version: 1, Created: now, Due: now}
}
func seedCluster(t *testing.T, s *Service, v ClusterRecord) {
	t.Helper()
	if e := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(v) }); e != nil {
		t.Fatal(e)
	}
}
func readCluster(t *testing.T, s *Service, arn string) ClusterRecord {
	t.Helper()
	var v ClusterRecord
	if e := s.repository.View(t.Context(), func(r Reader) error { var e error; v, e = r.Cluster(arn); return e }); e != nil {
		t.Fatal(e)
	}
	return v
}

func TestNativeCompletionFencesReplacementIncarnation(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	v := retainedCluster(now)
	var s *Service
	runtime := controlledRuntime{ensure: func(ctx context.Context, _ Specification) (Endpoint, error) {
		// A repository mutation during native I/O also proves no resource transaction
		// is held across the effect. Replacement deliberately reuses the generation.
		e := s.repository.Update(ctx, func(tx Transaction) error {
			replacement := v
			replacement.Incarnation = "replacement"
			replacement.State = "DELETING"
			replacement.Operation = "delete"
			return tx.PutCluster(replacement)
		})
		return Endpoint{SecurityMode: "PLAINTEXT", Brokers: []Broker{{ID: 1, Address: "127.0.0.1:19092"}}}, e
	}}
	s = New(Config{Runtime: runtime, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	seedCluster(t, s, v)
	job, found, e := (clusterJobs{s}).Next(t.Context())
	if e != nil || !found {
		t.Fatalf("select job: %v %v", found, e)
	}
	if e = (clusterJobs{s}).Run(t.Context(), job); e != nil {
		t.Fatal(e)
	}
	got := readCluster(t, s, v.ARN)
	if got.Incarnation != "replacement" || got.State != "DELETING" || got.Operation != "delete" || len(got.Endpoint.Brokers) != 0 {
		t.Fatalf("stale native completion resurrected replaced cluster: %#v", got)
	}
}
func TestFailedConfigurationDoesNotPublishPendingRevision(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	v := retainedCluster(now)
	v.State = "UPDATING"
	v.Operation = "UPDATE_CLUSTER_CONFIGURATION"
	v.ConfigurationARN = "configuration"
	v.ConfigurationRevision = 1
	v.ServerProperties = "num.partitions=1\n"
	v.PendingConfigurationARN = "configuration"
	v.PendingConfigurationRevision = 2
	v.PendingServerProperties = "num.partitions=2\n"
	v.OperationARN = "operation"
	s := New(Config{Runtime: controlledRuntime{ensure: func(context.Context, Specification) (Endpoint, error) {
		return Endpoint{}, errors.New("broker failed protocol readiness")
	}}, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	seedCluster(t, s, v)
	if e := s.repository.Update(t.Context(), func(tx Transaction) error {
		return tx.PutOperation(OperationRecord{ARN: v.OperationARN, ClusterARN: v.ARN, State: "PENDING", Created: now})
	}); e != nil {
		t.Fatal(e)
	}
	job, _, e := (clusterJobs{s}).Next(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if e = (clusterJobs{s}).Run(t.Context(), job); e != nil {
		t.Fatal(e)
	}
	got := readCluster(t, s, v.ARN)
	if got.State != "FAILED" || got.ConfigurationRevision != 1 || got.ServerProperties != v.ServerProperties || got.PendingConfigurationRevision != 2 || len(got.Endpoint.Brokers) != 0 {
		t.Fatalf("failed apply published unready configuration: %#v", got)
	}
	if e = s.repository.View(t.Context(), func(r Reader) error {
		o, e := r.Operation(v.OperationARN)
		if e == nil && (o.State != "UPDATE_FAILED" || o.Ended.IsZero()) {
			t.Fatalf("failed operation not terminal: %#v", o)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

type revocableAuthorizer struct{ denied bool }

func (a *revocableAuthorizer) Authorize(context.Context, authorization.Request) *awswire.Error {
	if a.denied {
		return failure("ForbiddenException", "Current authority revoked", 403)
	}
	return nil
}
func TestResolverRepeatsAuthorityAfterNativeObservation(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	v := retainedCluster(now)
	v.State = "ACTIVE"
	v.Operation = ""
	auth := &revocableAuthorizer{}
	s := New(Config{Clock: clock.NewManual(now), Authorizer: auth, Runtime: controlledRuntime{status: func(context.Context, Specification) (Endpoint, error) {
		auth.denied = true
		return Endpoint{SecurityMode: "PLAINTEXT", Brokers: []Broker{{ID: 1, Address: "127.0.0.1:19092"}}}, nil
	}}})
	t.Cleanup(func() { _ = s.Close() })
	seedCluster(t, s, v)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region})
	connection, e := s.ResolveCluster(ctx, v.ARN, RequireDescribeClusterV2)
	var rejected *awswire.Error
	if !errors.As(e, &rejected) || rejected.Code != "ForbiddenException" || len(connection.Brokers) != 0 {
		t.Fatalf("resolver exposed endpoint after authority revocation: %+v %v", connection, e)
	}
}
