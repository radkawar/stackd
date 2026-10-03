package integrations

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/services/logs"
	"stackd/internal/services/mq"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqllogs "stackd/storage/sqlite/logs"
	sqlmq "stackd/storage/sqlite/mq"
)

// The unit source supplies known bytes; these tests exercise the real scheduler,
// adapter, authorization and joined repositories, not native-engine production.
type mqScheduledLogSource struct {
	batch      mq.LogBatch
	beforeRead func(context.Context) error
}

func (s *mqScheduledLogSource) ReadLogs(ctx context.Context, _ mq.BrokerRecord, _ mq.LogType, cursor mq.LogCursor) (mq.LogBatch, error) {
	if s.beforeRead != nil {
		if err := s.beforeRead(ctx); err != nil {
			return mq.LogBatch{}, err
		}
	}
	if cursor == s.batch.Next {
		return mq.LogBatch{Next: cursor}, nil
	}
	return s.batch, nil
}

func (*mqScheduledLogSource) Ensure(context.Context, mq.BrokerRecord) (mq.Endpoint, error) {
	return mq.Endpoint{}, errors.New("unexpected lifecycle Ensure in log-only test")
}
func (*mqScheduledLogSource) Reboot(context.Context, mq.BrokerRecord) (mq.Endpoint, error) {
	return mq.Endpoint{}, errors.New("unexpected lifecycle Reboot in log-only test")
}
func (*mqScheduledLogSource) Delete(context.Context, mq.BrokerRecord) error {
	return errors.New("unexpected lifecycle Delete in log-only test")
}
func (*mqScheduledLogSource) Close() error { return nil }

var errMQLogCursorWrite = errors.New("injected MQ cursor persistence failure")

type mqCursorFailureRepository struct {
	mq.Repository
	fail bool
}

type mqCursorFailureTransaction struct {
	mq.Transaction
	repository *mqCursorFailureRepository
}

func (r *mqCursorFailureRepository) Update(ctx context.Context, fn func(mq.Transaction) error) error {
	return r.Repository.Update(ctx, func(tx mq.Transaction) error {
		return fn(mqCursorFailureTransaction{Transaction: tx, repository: r})
	})
}

func (tx mqCursorFailureTransaction) PutBroker(broker mq.BrokerRecord) error {
	if tx.repository.fail && broker.GeneralLogCursor.Offset != 0 {
		tx.repository.fail = false
		return errMQLogCursorWrite
	}
	return tx.Transaction.PutBroker(broker)
}

func forMQLogRepositories(t *testing.T, run func(*testing.T, mq.Repository, logs.Repository)) {
	t.Helper()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "memory" {
				domain := memory.NewDomain()
				run(t, mq.NewMemoryRepository(domain), logs.NewMemoryRepository(domain))
				return
			}
			db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "mq-logs.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			run(t, sqlmq.New(db), sqllogs.New(db))
		})
	}
}

func newMQLogScheduler(t *testing.T, f *mqLogsFixture, repository mq.Repository, source *mqScheduledLogSource) *mq.Service {
	t.Helper()
	f.broker.State, f.broker.Version = "RUNNING", 1
	f.broker.Logs.General = true
	f.broker.LogDue, f.broker.Due = f.now, f.now.Add(24*time.Hour)
	if err := repository.Update(f.root, func(tx mq.Transaction) error { return tx.PutBroker(f.broker) }); err != nil {
		t.Fatal(err)
	}
	if wire := f.adapter.Prepare(f.root, f.broker, f.broker.Logs); wire != nil {
		t.Fatal(wire)
	}
	service := mq.New(mq.Config{Repository: repository, Clock: f.clock, Runtime: source, Logs: f.adapter})
	t.Cleanup(func() { service.Close() })
	return service
}

func mqRetainedLogBroker(t *testing.T, f *mqLogsFixture, repository mq.Repository) mq.BrokerRecord {
	t.Helper()
	var broker mq.BrokerRecord
	if err := repository.View(f.root, func(r mq.Reader) error {
		var err error
		broker, err = r.Broker(f.broker.Scope, f.broker.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return broker
}

func mqAssertNoLogStream(t *testing.T, f *mqLogsFixture) {
	t.Helper()
	out := f.command(t, f.root, "DescribeLogStreams", &api.DescribeLogStreamsRequest{LogGroupName: new(api.LogGroupName("/aws/amazonmq/broker/b-native-logs/general"))}).(*api.DescribeLogStreamsResponse)
	if len(out.LogStreams) != 0 {
		t.Fatal("uncommitted or fenced delivery left a log stream")
	}
}

func TestMQLogsSchedulerRollsBackAcceptedEventsWhenCursorWriteFails(t *testing.T) {
	forMQLogRepositories(t, func(t *testing.T, repository mq.Repository, logRepository logs.Repository) {
		f := newMQLogsFixtureWithRepository(t, logRepository)
		record := mq.LogRecord{Timestamp: f.now, Message: "transactional source bytes\n"}
		source := &mqScheduledLogSource{batch: mq.LogBatch{Records: []mq.LogRecord{record}, Next: mq.LogCursor{FileID: "activemq.log:1", Offset: 128}}}
		faults := &mqCursorFailureRepository{Repository: repository, fail: true}
		service := newMQLogScheduler(t, f, faults, source)
		f.putPolicy(t, "mq", f.policy())
		_, err := service.JobDriver().RunDue(f.root, 1)
		if !errors.Is(err, errMQLogCursorWrite) {
			t.Fatalf("expected failure after Logs accepted the batch, got %v", err)
		}
		broker := mqRetainedLogBroker(t, f, repository)
		if broker.GeneralLogCursor != (mq.LogCursor{}) || !strings.Contains(broker.LogDeliveryError, errMQLogCursorWrite.Error()) {
			t.Fatalf("failed cursor write was advanced or not reported: %+v", broker)
		}
		mqAssertNoLogStream(t, f)
		if err := f.clock.Advance(5 * time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := service.JobDriver().RunDue(f.root, 2); err != nil {
			t.Fatal(err)
		}
		broker = mqRetainedLogBroker(t, f, repository)
		if broker.GeneralLogCursor != source.batch.Next || broker.LogDeliveryError != "" {
			t.Fatalf("retry did not commit the acknowledged cursor: %+v", broker)
		}
		f.assertEvents(t, record)
		if err := f.clock.Advance(5 * time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := service.JobDriver().RunDue(f.root, 1); err != nil {
			t.Fatal(err)
		}
		f.assertEvents(t, record)
	})
}

func TestMQLogsSchedulerAuthorityRevocationRetainsCursorForRetry(t *testing.T) {
	forMQLogRepositories(t, func(t *testing.T, repository mq.Repository, logRepository logs.Repository) {
		f := newMQLogsFixtureWithRepository(t, logRepository)
		first := mq.LogRecord{Timestamp: f.now, Message: "first authorized source event\n"}
		source := &mqScheduledLogSource{batch: mq.LogBatch{Records: []mq.LogRecord{first}, Next: mq.LogCursor{FileID: "activemq.log:1", Offset: 100}}}
		service := newMQLogScheduler(t, f, repository, source)
		_, err := service.JobDriver().RunDue(f.root, 1)
		requireMQLogError(t, err, "AccessDeniedException")
		if broker := mqRetainedLogBroker(t, f, repository); broker.GeneralLogCursor != (mq.LogCursor{}) {
			t.Fatalf("denied initial delivery advanced cursor: %+v", broker.GeneralLogCursor)
		}
		mqAssertNoLogStream(t, f)
		f.putPolicy(t, "mq", f.policy())
		if err := f.clock.Advance(5 * time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := service.JobDriver().RunDue(f.root, 1); err != nil {
			t.Fatal(err)
		}
		accepted := source.batch.Next
		f.assertEvents(t, first)
		second := mq.LogRecord{Timestamp: f.clock.Now(), Message: "source bytes retained during denial\n"}
		source.batch = mq.LogBatch{Records: []mq.LogRecord{second}, Next: mq.LogCursor{FileID: accepted.FileID, Offset: 200}}
		f.putPolicy(t, "deny", `{"Statement":{"Effect":"Deny","Principal":{"Service":"mq.amazonaws.com"},"Action":"logs:PutLogEvents","Resource":"*"}}`)
		_, err = service.JobDriver().RunDue(f.root, 1)
		requireMQLogError(t, err, "AccessDeniedException")
		if broker := mqRetainedLogBroker(t, f, repository); broker.GeneralLogCursor != accepted || !strings.Contains(broker.LogDeliveryError, "AccessDenied") {
			t.Fatalf("explicit denial lost cursor or diagnostic: %+v", broker)
		}
		f.assertEvents(t, first)
		f.command(t, f.root, "DeleteResourcePolicy", &api.DeleteResourcePolicyRequest{PolicyName: new(api.PolicyName("deny"))})
		if err := f.clock.Advance(5 * time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := service.JobDriver().RunDue(f.root, 2); err != nil {
			t.Fatal(err)
		}
		if broker := mqRetainedLogBroker(t, f, repository); broker.GeneralLogCursor != source.batch.Next || broker.LogDeliveryError != "" {
			t.Fatalf("restored authority did not advance cursor: %+v", broker)
		}
		f.assertEvents(t, first, second)
	})
}

func TestMQLogsSchedulerFencesBrokerChangedDuringSourceRead(t *testing.T) {
	forMQLogRepositories(t, func(t *testing.T, repository mq.Repository, logRepository logs.Repository) {
		for _, change := range []string{"version", "state"} {
			t.Run(change, func(t *testing.T) {
				f := newMQLogsFixtureWithRepository(t, logRepository)
				record := mq.LogRecord{Timestamp: f.now, Message: "stale native read must not publish\n"}
				source := &mqScheduledLogSource{batch: mq.LogBatch{Records: []mq.LogRecord{record}, Next: mq.LogCursor{FileID: "activemq.log:1", Offset: 100}}}
				service := newMQLogScheduler(t, f, repository, source)
				f.putPolicy(t, "mq", f.policy())
				source.beforeRead = func(ctx context.Context) error {
					// This write would deadlock if native reads held the shared
					// transaction. It also simulates concurrent reboot/deletion.
					ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
					return repository.Update(ctx, func(tx mq.Transaction) error {
						broker, err := tx.Broker(f.broker.Scope, f.broker.ID)
						if err != nil {
							return err
						}
						if change == "version" {
							broker.Version++
						} else {
							broker.State = "REBOOT_IN_PROGRESS"
						}
						return tx.PutBroker(broker)
					})
				}
				if _, err := service.JobDriver().RunDue(f.root, 1); err != nil {
					t.Fatal(err)
				}
				if broker := mqRetainedLogBroker(t, f, repository); broker.GeneralLogCursor != (mq.LogCursor{}) {
					t.Fatalf("fenced read advanced cursor: %+v", broker.GeneralLogCursor)
				}
				mqAssertNoLogStream(t, f)
			})
		}
	})
}
