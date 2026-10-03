package elbv2_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	api "stackd/internal/awsapi/elbv2"
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/elbv2"
)

func TestMetricWindowsSurviveDeletionRestartAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	repo := backend.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "819230000001", Region: "us-east-1"}
	arn := "arn:aws:elasticloadbalancing:us-east-1:819230000001:loadbalancer/app/metrics/1"
	at := time.Date(2031, 1, 1, 0, 1, 0, 0, time.UTC)
	key := domain.MetricPublicationKey{Scope: scope, LoadBalancerARN: arn, Due: at}
	sample := domain.MetricSample{Name: "RequestCountPerTarget", TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:819230000001:targetgroup/metrics/2", Minimum: .5, Maximum: .5, Sum: .5, Count: 1}
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutLoadBalancer(domain.LoadBalancerRecord{Scope: scope, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(arn))}}); err != nil {
			return err
		}
		if err := tx.SetNextMetricAt(scope, arn, at); err != nil {
			return err
		}
		return tx.AddMetricSamples(key, []domain.MetricSample{sample, sample})
	}); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("publication failed")
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.DeleteMetricPublication(key); err != nil {
			return err
		}
		return failed
	}); !errors.Is(err, failed) {
		t.Fatalf("unexpected publication outcome: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo = backend.New(db)
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error {
		lb, err := tx.LoadBalancer(scope, arn)
		if err != nil {
			return err
		}
		if !lb.NextMetricAt.Equal(at) {
			t.Fatalf("sampler deadline lost: %s", lb.NextMetricAt)
		}
		return tx.DeleteLoadBalancer(scope, arn)
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.View(t.Context(), func(tx domain.Reader) error {
		next, found, err := tx.NextMetricPublication()
		if err != nil {
			return err
		}
		if !found || next != key {
			t.Fatalf("deletion erased accepted request work: %+v %t", next, found)
		}
		samples, err := tx.MetricSamples(key)
		if err != nil {
			return err
		}
		if len(samples) != 1 || samples[0].Sum != 1 || samples[0].Count != 2 {
			t.Fatalf("restart or rollback changed numerator: %+v", samples)
		}
		other := key
		other.AccountID = "819230000002"
		samples, err = tx.MetricSamples(other)
		if err != nil {
			return err
		}
		if len(samples) != 0 {
			t.Fatal("metric source crossed account scope")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteMetricPublication(key) }); err != nil {
		t.Fatal(err)
	}
	if err = repo.View(t.Context(), func(tx domain.Reader) error {
		_, found, err := tx.NextMetricPublication()
		if found {
			t.Fatal("committed publication remained eligible")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
