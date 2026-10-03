package mq

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

type metricScriptRuntime struct {
	testRuntime
	ensure func(context.Context, BrokerRecord) (Endpoint, error)
	read   func(context.Context, BrokerRecord) (MetricSnapshot, error)
}

func (r metricScriptRuntime) Ensure(ctx context.Context, v BrokerRecord) (Endpoint, error) {
	if r.ensure != nil {
		return r.ensure(ctx, v)
	}
	return r.testRuntime.Ensure(ctx, v)
}

func (r metricScriptRuntime) ReadMetrics(ctx context.Context, v BrokerRecord) (MetricSnapshot, error) {
	return r.read(ctx, v)
}

type metricPublication struct {
	at time.Time
}

type transactionalMetricPublisher struct {
	store *memory.Store[[]metricPublication]
	fail  error
}

func (p *transactionalMetricPublisher) PublishMQMetrics(ctx context.Context, _ BrokerRecord, _ MetricSnapshot, at time.Time) error {
	if err := p.store.Update(ctx, func(rows *[]metricPublication, _ *memory.Transaction) error {
		*rows = append(*rows, metricPublication{at: at})
		return nil
	}); err != nil {
		return err
	}
	// Fail after a successful related write: only the caller's transaction can
	// roll this partial publication back while retaining native readiness.
	return p.fail
}

func (p *transactionalMetricPublisher) publications(t *testing.T) []metricPublication {
	t.Helper()
	var rows []metricPublication
	if err := p.store.View(t.Context(), func(current *[]metricPublication, _ *memory.Transaction) error {
		rows = slices.Clone(*current)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

func metricFixture(t *testing.T, engine string) (*Service, context.Context, BrokerRecord, *transactionalMetricPublisher) {
	t.Helper()
	domain := memory.NewDomain()
	publisher := &transactionalMetricPublisher{store: memory.New(domain, []metricPublication(nil), slices.Clone[[]metricPublication])}
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Repository: NewMemoryRepository(domain), Clock: clock.NewManual(now), Runtime: testRuntime{}, Metrics: publisher})
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	v := BrokerRecord{
		Engine: engine,
		Scope:  Scope{"aws", "123456789012", "us-east-1"}, ID: "b-metrics", ARN: "arn:aws:mq:us-east-1:123456789012:broker:metrics:b-metrics",
		Name: "metrics", EngineVersion: "3.13.7", State: "RUNNING", Version: 1, Due: now,
		Endpoint: Endpoint{Address: "ssl://127.0.0.1:1234", NativeID: "owned", CAPEM: []byte("ca")},
	}
	if engine == "ACTIVEMQ" {
		v.EngineVersion = "5.18"
	}
	putMetricBroker(t, s, v)
	return s, ctx, v, publisher
}

func metricTestSnapshot(engine string) MetricSnapshot {
	switch engine {
	case "RABBITMQ":
		return MetricSnapshot{RabbitMQ: &RabbitMQMetrics{Connections: 2, Exchanges: 1, Channels: 3}}
	case "ACTIVEMQ":
		return MetricSnapshot{ActiveMQ: &ActiveMQMetrics{Connections: 2, Consumers: 1, Messages: 3, Producers: 1}}
	default:
		panic("unsupported metric fixture engine")
	}
}

func putMetricBroker(t *testing.T, s *Service, v BrokerRecord) {
	t.Helper()
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutBroker(v) }); err != nil {
		t.Fatal(err)
	}
}

func metricJob(v BrokerRecord) scheduler.Job {
	return scheduler.Job{Key: v.ARN, Version: v.Version, Due: v.Due}
}

func TestMetricReadOutsideTransactionsSeesCommittedReadiness(t *testing.T) {
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		t.Run(engine, func(t *testing.T) {
			s, ctx, v, publisher := metricFixture(t, engine)
			v.State, v.Operation, v.Endpoint = "CREATION_IN_PROGRESS", "create", Endpoint{}
			putMetricBroker(t, s, v)
			reads := 0
			s.runtime = metricScriptRuntime{read: func(_ context.Context, observed BrokerRecord) (MetricSnapshot, error) {
				reads++
				if observed.State != "RUNNING" || observed.Operation != "" || observed.Endpoint.NativeID != "owned" {
					t.Fatalf("source received uncommitted readiness: %+v", observed)
				}
				// An independent writer must acquire the domain while the native read is
				// in progress. Borrowing a write transaction would hide that violation.
				independent, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				err := s.repository.Update(independent, func(tx Transaction) error {
					current, err := tx.Broker(v.Scope, v.ID)
					if err != nil {
						return err
					}
					if current.State != "RUNNING" || current.Endpoint.NativeID != "owned" || !current.Due.Equal(s.clock.Now().Add(30*time.Second)) {
						t.Fatalf("readiness and the next observation were not committed: %+v", current)
					}
					current.Tags = map[string]string{"during-native-read": "committed"}
					return tx.PutBroker(current)
				})
				return metricTestSnapshot(engine), err
			}}
			if err := (brokerJobs{s}).Run(ctx, metricJob(v)); err != nil {
				t.Fatal(err)
			}
			if reads != 1 || len(publisher.publications(t)) != 1 || storedBroker(t, s, v).Tags["during-native-read"] != "committed" {
				t.Fatal("native observation blocked or overwrote a concurrent independent write")
			}
		})
	}
}

func TestMetricFailuresPreserveReadinessAndOnlyRetryFutureObservations(t *testing.T) {
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		for _, failurePoint := range []string{"read", "publication"} {
			t.Run(engine+"/"+failurePoint, func(t *testing.T) {
				s, ctx, v, publisher := metricFixture(t, engine)
				v.State, v.Operation, v.Endpoint = "CREATION_IN_PROGRESS", "create", Endpoint{}
				putMetricBroker(t, s, v)
				failure := errors.New("metrics owner unavailable")
				reads := 0
				failRead := failurePoint == "read"
				if failurePoint == "publication" {
					publisher.fail = failure
				}
				s.runtime = metricScriptRuntime{read: func(context.Context, BrokerRecord) (MetricSnapshot, error) {
					reads++
					if failRead {
						return MetricSnapshot{}, failure
					}
					return metricTestSnapshot(engine), nil
				}}
				original := metricJob(v)
				if err := (brokerJobs{s}).Run(ctx, original); !errors.Is(err, failure) {
					t.Fatalf("metric failure was lost: %v", err)
				}
				current := storedBroker(t, s, v)
				if current.State != "RUNNING" || current.Operation != "" || current.Endpoint.NativeID != "owned" || current.Failure != "" || !current.Due.Equal(s.clock.Now().Add(30*time.Second)) {
					t.Fatalf("metric failure reverted successful creation or lost its schedule: %+v", current)
				}
				if got := publisher.publications(t); len(got) != 0 {
					t.Fatalf("failed publication committed partial metrics: %+v", got)
				}
				failRead, publisher.fail = false, nil
				if err := (brokerJobs{s}).Run(ctx, original); err != nil {
					t.Fatal(err)
				}
				if result, err := s.JobDriver().RunDue(ctx, 100); err != nil || result.Processed != 0 || reads != 1 {
					t.Fatalf("failed sample retried before the retained deadline: result=%+v reads=%d err=%v", result, reads, err)
				}
				// A delayed controller samples now once, rather than inventing missing
				// samples for every elapsed thirty-second interval.
				s.clock.(*clock.Manual).Advance(5 * time.Minute)
				if result, err := s.JobDriver().RunDue(ctx, 100); err != nil || result.Processed != 1 || reads != 2 {
					t.Fatalf("late reconciliation did not make exactly one new observation: result=%+v reads=%d err=%v", result, reads, err)
				}
				if got := publisher.publications(t); len(got) != 1 || !got[0].at.Equal(s.clock.Now()) {
					t.Fatalf("late publication was missing, duplicated or backdated: %+v", got)
				}
			})
		}
	}
}

func TestMetricSamplesExcludeConcurrentDeletedOrChangedBrokers(t *testing.T) {
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		for _, change := range []string{"deleted", "deleting", "reboot", "version", "native-identity", "failed", "engine", "observation"} {
			t.Run(engine+"/"+change, func(t *testing.T) {
				s, ctx, v, publisher := metricFixture(t, engine)
				started, release := make(chan struct{}), make(chan struct{})
				s.runtime = metricScriptRuntime{read: func(ctx context.Context, _ BrokerRecord) (MetricSnapshot, error) {
					close(started)
					select {
					case <-release:
						return metricTestSnapshot(engine), nil
					case <-ctx.Done():
						return MetricSnapshot{}, ctx.Err()
					}
				}}
				result := make(chan error, 1)
				go func() { result <- (brokerJobs{s}).Run(ctx, metricJob(v)) }()
				select {
				case <-started:
				case err := <-result:
					t.Fatalf("reconciliation ended before the native read: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				err := s.repository.Update(ctx, func(tx Transaction) error {
					current, err := tx.Broker(v.Scope, v.ID)
					if err != nil {
						return err
					}
					switch change {
					case "deleted":
						return tx.DeleteBroker(v.Scope, v.ID)
					case "deleting":
						current.State, current.Operation = "DELETION_IN_PROGRESS", "delete"
					case "reboot":
						current.State, current.Operation = "REBOOT_IN_PROGRESS", "reboot"
						current.Version++
					case "version":
						current.Version++
					case "native-identity":
						current.Endpoint.NativeID = "replacement"
					case "failed":
						current.State = "CRITICAL_ACTION_REQUIRED"
					case "engine":
						current.Engine = "ACTIVEMQ"
						if engine == "ACTIVEMQ" {
							current.Engine = "RABBITMQ"
						}
					case "observation":
						current.Due = current.Due.Add(30 * time.Second)
					}
					return tx.PutBroker(current)
				})
				close(release)
				if err != nil {
					t.Fatal(err)
				}
				if err := <-result; err != nil {
					t.Fatal(err)
				}
				if got := publisher.publications(t); len(got) != 0 {
					t.Fatalf("published an observation after %s invalidated it: %+v", change, got)
				}
			})
		}
	}
}

func TestNewerReconciliationFencesAnOlderNativeMetricRead(t *testing.T) {
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		t.Run(engine, func(t *testing.T) {
			s, ctx, v, publisher := metricFixture(t, engine)
			started, release := make(chan struct{}), make(chan struct{})
			var reads atomic.Int32
			s.runtime = metricScriptRuntime{read: func(ctx context.Context, _ BrokerRecord) (MetricSnapshot, error) {
				if reads.Add(1) == 1 {
					close(started)
					select {
					case <-release:
					case <-ctx.Done():
						return MetricSnapshot{}, ctx.Err()
					}
				}
				return metricTestSnapshot(engine), nil
			}}
			result := make(chan error, 1)
			go func() { result <- (brokerJobs{s}).Run(ctx, metricJob(v)) }()
			select {
			case <-started:
			case err := <-result:
				t.Fatalf("reconciliation ended before the native read: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			current := storedBroker(t, s, v)
			s.clock.(*clock.Manual).Advance(30 * time.Second)
			err := (brokerJobs{s}).Run(ctx, metricJob(current))
			close(release)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if reads.Load() != 2 {
				t.Fatalf("expected overlapping physical observations, got %d", reads.Load())
			}
			if got := publisher.publications(t); len(got) != 1 || !got[0].at.Equal(s.clock.Now()) {
				t.Fatalf("older read published after a newer reconciliation: %+v", got)
			}
		})
	}
}

func TestMetricSourceSkipsSupersededReadinessBeforeNativeIO(t *testing.T) {
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		for _, change := range []string{"deleted", "observation", "failed", "engine"} {
			t.Run(engine+"/"+change, func(t *testing.T) {
				s, ctx, observed, publisher := metricFixture(t, engine)
				s.runtime = metricScriptRuntime{read: func(context.Context, BrokerRecord) (MetricSnapshot, error) {
					t.Fatal("native metrics read started for superseded readiness")
					return MetricSnapshot{}, nil
				}}
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					if change == "deleted" {
						return tx.DeleteBroker(observed.Scope, observed.ID)
					}
					current := observed
					switch change {
					case "observation":
						current.Due = current.Due.Add(30 * time.Second)
					case "failed":
						current.State = "CRITICAL_ACTION_REQUIRED"
					case "engine":
						current.Engine = "ACTIVEMQ"
						if engine == "ACTIVEMQ" {
							current.Engine = "RABBITMQ"
						}
					}
					return tx.PutBroker(current)
				}); err != nil {
					t.Fatal(err)
				}
				if err := s.deliverMetrics(ctx, observed); err != nil {
					t.Fatal(err)
				}
				if got := publisher.publications(t); len(got) != 0 {
					t.Fatalf("superseded readiness published: %+v", got)
				}
			})
		}
	}
}

func TestMetricInvalidVariantsFailWithoutRevertingReadiness(t *testing.T) {
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		for _, variant := range []string{"absent", "wrong-engine", "both-engines"} {
			t.Run(engine+"/"+variant, func(t *testing.T) {
				s, ctx, v, publisher := metricFixture(t, engine)
				v.State, v.Operation, v.Endpoint = "CREATION_IN_PROGRESS", "create", Endpoint{}
				putMetricBroker(t, s, v)
				var sample MetricSnapshot
				switch variant {
				case "wrong-engine":
					if engine == "ACTIVEMQ" {
						sample = metricTestSnapshot("RABBITMQ")
					} else {
						sample = metricTestSnapshot("ACTIVEMQ")
					}
				case "both-engines":
					sample = metricTestSnapshot("RABBITMQ")
					sample.ActiveMQ = metricTestSnapshot("ACTIVEMQ").ActiveMQ
				}
				reads := 0
				s.runtime = metricScriptRuntime{read: func(context.Context, BrokerRecord) (MetricSnapshot, error) {
					reads++
					return sample, nil
				}}
				if err := (brokerJobs{s}).Run(ctx, metricJob(v)); err == nil {
					t.Fatal("invalid metric variant succeeded")
				}
				current := storedBroker(t, s, v)
				if reads != 1 || current.State != "RUNNING" || current.Operation != "" || current.Endpoint.NativeID != "owned" || current.Failure != "" || !current.Due.Equal(s.clock.Now().Add(30*time.Second)) {
					t.Fatalf("invalid metric variant reverted readiness or lost the next observation: reads=%d broker=%+v", reads, current)
				}
				if got := publisher.publications(t); len(got) != 0 {
					t.Fatalf("invalid metric variant published invented data: %+v", got)
				}
			})
		}
	}
}

func TestMetricSamplingRequiresHealthySupportedEngineAndConfiguredOwners(t *testing.T) {
	t.Run("unsupported-engine", func(t *testing.T) {
		s, ctx, v, publisher := metricFixture(t, "UNSUPPORTED")
		s.runtime = metricScriptRuntime{read: func(context.Context, BrokerRecord) (MetricSnapshot, error) {
			t.Fatal("metrics read for an unsupported engine")
			return MetricSnapshot{}, nil
		}}
		if err := (brokerJobs{s}).Run(ctx, metricJob(v)); err != nil {
			t.Fatal(err)
		}
		if got := publisher.publications(t); len(got) != 0 {
			t.Fatalf("unsupported engine published: %+v", got)
		}
	})
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		for _, excluded := range []string{"no-publisher", "no-source", "native-failure", "delete"} {
			t.Run(engine+"/"+excluded, func(t *testing.T) {
				s, ctx, v, publisher := metricFixture(t, engine)
				runtime := metricScriptRuntime{read: func(context.Context, BrokerRecord) (MetricSnapshot, error) {
					t.Fatal("metrics read for an ineligible broker or unconfigured owner")
					return MetricSnapshot{}, nil
				}}
				switch excluded {
				case "no-publisher":
					s.metrics = nil
				case "native-failure":
					runtime.ensure = func(context.Context, BrokerRecord) (Endpoint, error) {
						return Endpoint{}, errors.New("native broker is unavailable")
					}
				case "delete":
					v.State, v.Operation = "DELETION_IN_PROGRESS", "delete"
				}
				putMetricBroker(t, s, v)
				if excluded != "no-source" {
					s.runtime = runtime
				}
				if err := (brokerJobs{s}).Run(ctx, metricJob(v)); err != nil {
					t.Fatal(err)
				}
				if got := publisher.publications(t); len(got) != 0 {
					t.Fatalf("ineligible broker published: %+v", got)
				}
			})
		}
	}
}
