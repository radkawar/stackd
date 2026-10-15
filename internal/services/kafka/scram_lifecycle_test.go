package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
)

type synchronizationSecrets struct {
	user   SCRAMUser
	denied error
	calls  int
}

func (s *synchronizationSecrets) ResolveSCRAM(context.Context, string, string) (SCRAMUser, error) {
	return s.user, s.denied
}
func (s *synchronizationSecrets) LoadSCRAM(ctx context.Context, arn, incarnation string, association SCRAMAssociation) (SCRAMUser, error) {
	s.calls++
	metadata := awsctx.FromContext(ctx)
	if association.Incarnation != incarnation {
		return SCRAMUser{}, errors.New("credential read lost exact cluster incarnation")
	}
	if metadata.ServicePrincipal.SourceARN != arn {
		return SCRAMUser{}, errors.New("credential read lost exact cluster source")
	}
	return s.user, s.denied
}
func (*synchronizationSecrets) AssociateSCRAM(_ context.Context, _, incarnation, secretARN string, _ SCRAMAssociation) (SCRAMAssociation, error) {
	return SCRAMAssociation{SecretARN: secretARN, KMSKeyARN: "key", GrantID: "grant", Incarnation: incarnation}, nil
}
func (*synchronizationSecrets) ReleaseSCRAM(context.Context, string, string, SCRAMAssociation) error {
	return nil
}

type synchronizationRuntime struct {
	controlledRuntime
	quarantined []Specification
}

func (r *synchronizationRuntime) Quarantine(ctx context.Context, spec Specification) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.quarantined = append(r.quarantined, spec)
	return nil
}

func TestSCRAMSynchronizationRetainsOnlyPublishedNativeEndpointsWithoutPublicOperation(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now)})
	s.JobDriver().Close()
	t.Cleanup(func() { _ = s.Close() })
	v := retainedCluster(now)
	v.State = "ACTIVE"
	v.Operation = ""
	v.SecurityMode = "SASL_SCRAM"
	v.Secrets = []SCRAMAssociation{{SecretARN: "secret-current", KMSKeyARN: "key", GrantID: "grant", Incarnation: v.Incarnation}}
	v.Endpoint = Endpoint{SecurityMode: "SASL_SCRAM", CAPEM: []byte("native-test-ca"), Brokers: []Broker{{ID: 1, Address: "127.0.0.1:19092"}}}
	seedCluster(t, s, v)
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return s.queueSCRAMSynchronization(tx, &v) }); err != nil {
		t.Fatal(err)
	}
	queued := readCluster(t, s, v.ARN)
	if queued.State != "ACTIVE" || len(queued.Endpoint.Brokers) != 1 || queued.Operation != "reconcile" || queued.OperationARN != "" || queued.Due != now {
		t.Fatalf("credential propagation fabricated a cluster operation or erased live listeners: %#v", queued)
	}
	if err := s.repository.View(t.Context(), func(r Reader) error {
		operations, err := r.Operations(v.ARN)
		if err != nil {
			return err
		}
		if len(operations) != 0 {
			t.Fatal("SCRAM propagation manufactured public operations")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A failed/unready cluster must not gain readiness from merely queued credentials.
	v.State = "FAILED"
	v.Endpoint = Endpoint{}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return s.queueSCRAMSynchronization(tx, &v) }); err != nil {
		t.Fatal(err)
	}
	if got := readCluster(t, s, v.ARN); got.State != "FAILED" || len(got.Endpoint.Brokers) != 0 {
		t.Fatal("queued secret intent manufactured native readiness")
	}
}

func TestSCRAMQueuedExecutionReloadsReplacementCredentialsAndRechecksAuthority(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	v := retainedCluster(now)
	v.State = "ACTIVE"
	v.Operation = ""
	v.SecurityMode = "SASL_SCRAM"
	v.Secrets = []SCRAMAssociation{{SecretARN: "secret-current", KMSKeyARN: "key", GrantID: "grant", Incarnation: v.Incarnation}}
	secrets := &synchronizationSecrets{user: SCRAMUser{Username: "replacement", Password: "current-password"}}
	var executed Specification
	runtime := &synchronizationRuntime{controlledRuntime: controlledRuntime{ensure: func(_ context.Context, spec Specification) (Endpoint, error) {
		executed = spec
		return Endpoint{SecurityMode: "SASL_SCRAM", CAPEM: []byte("native-test-ca"), Brokers: []Broker{{ID: 1, Address: "127.0.0.1:19092"}}}, nil
	}}}
	s := New(Config{Clock: clock.NewManual(now), Runtime: runtime, Secrets: secrets})
	s.JobDriver().Close()
	t.Cleanup(func() { _ = s.Close() })
	seedCluster(t, s, v)
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return s.queueSCRAMSynchronization(tx, &v) }); err != nil {
		t.Fatal(err)
	}
	job, found, err := (clusterJobs{s}).Next(t.Context())
	if err != nil || !found {
		t.Fatal(err)
	}
	if err = (clusterJobs{s}).Run(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	if secrets.calls != 1 || len(executed.Users) != 1 || executed.Users[0].Username != "replacement" || executed.Users[0].Password != "current-password" {
		t.Fatal("queued execution reused stale credentials")
	}
	current := readCluster(t, s, v.ARN)
	current.ClientSubnets = []string{"subnet-a", "subnet-b"}
	current.Brokers = 2
	if err = s.repository.Update(t.Context(), func(tx Transaction) error { return s.queueSCRAMSynchronization(tx, &current) }); err != nil {
		t.Fatal(err)
	}
	secrets.denied = errors.New("current secret/KMS authority revoked")
	job, found, err = (clusterJobs{s}).Next(t.Context())
	if err != nil || !found {
		t.Fatal(err)
	}
	if err = (clusterJobs{s}).Run(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	failed := readCluster(t, s, v.ARN)
	if failed.State != "FAILED" || len(failed.Endpoint.Brokers) != 0 || len(runtime.quarantined) != 1 || runtime.quarantined[0].Incarnation != v.Incarnation || secrets.calls != 2 {
		t.Fatal("revoked credential authority retained old ready listeners")
	}
}

func TestSCRAMQueuedIntentSurvivesRestartAndRequiresFreshNativeCompletion(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	v := retainedCluster(now)
	v.State = "ACTIVE"
	v.Operation = "reconcile"
	v.SecurityMode = "SASL_SCRAM"
	v.Secrets = []SCRAMAssociation{{SecretARN: "secret-retained", KMSKeyARN: "key", GrantID: "grant", Incarnation: v.Incarnation}}
	v.Endpoint = Endpoint{SecurityMode: "SASL_SCRAM", CAPEM: []byte("native-test-ca"), Brokers: []Broker{{ID: 1, Address: "127.0.0.1:19092"}}}
	entered := make(chan Specification, 1)
	release := make(chan struct{})
	secrets := &synchronizationSecrets{user: SCRAMUser{Username: "retained", Password: "current-password"}}
	runtime := controlledRuntime{ensure: func(ctx context.Context, spec Specification) (Endpoint, error) {
		entered <- spec
		select {
		case <-release:
			return Endpoint{SecurityMode: "SASL_SCRAM", CAPEM: []byte("native-test-ca"), Brokers: []Broker{{ID: 1, Address: "127.0.0.1:19092"}}}, nil
		case <-ctx.Done():
			return Endpoint{}, ctx.Err()
		}
	}}
	s := New(Config{Clock: clock.NewManual(now), Runtime: runtime, Secrets: secrets})
	t.Cleanup(func() { _ = s.Close() })
	seedCluster(t, s, v)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case spec := <-entered:
		if len(spec.Users) != 1 || spec.Users[0].Username != "retained" {
			t.Fatal("restart discarded queued credential intent")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("restart did not execute retained synchronization")
	}
	pending := readCluster(t, s, v.ARN)
	if pending.State != "UPDATING" || len(pending.Endpoint.Brokers) != 0 || len(pending.Secrets) != 1 {
		t.Fatal("restart exposed retained endpoints before native readiness")
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		ready := readCluster(t, s, v.ARN)
		if ready.State == "ACTIVE" {
			if len(ready.Endpoint.Brokers) != 1 || ready.Operation != "" {
				t.Fatal("native completion did not settle queued synchronization")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native restart synchronization did not converge")
		}
		time.Sleep(time.Millisecond)
	}
}
