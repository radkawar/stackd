package mq

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/mq"
	"stackd/internal/awswire"
)

type loggingControlRuntime struct{ testRuntime }

func (loggingControlRuntime) ReadLogs(_ context.Context, _ BrokerRecord, _ LogType, cursor LogCursor) (LogBatch, error) {
	return LogBatch{Next: cursor}, nil
}

type loggingControlDelivery struct{}

func (loggingControlDelivery) Prepare(context.Context, BrokerRecord, LogSettings) *awswire.Error {
	return nil
}
func (loggingControlDelivery) Write(context.Context, BrokerRecord, LogType, []LogRecord) error {
	return errors.New("control fixture has no log publisher")
}

func TestLoggingChangesRequireSuccessfulNativeReboot(t *testing.T) {
	s, ctx, v := controlFixture(t)
	fail := true
	s.runtime = loggingControlRuntime{testRuntime{reboot: func(context.Context, BrokerRecord) (Endpoint, error) {
		if fail {
			return Endpoint{}, errors.New("native restart failed")
		}
		return Endpoint{Address: "ssl://localhost:1234", NativeID: "owned", CAPEM: []byte("ca")}, nil
	}}}
	s.logs = loggingControlDelivery{}
	update := func(settings *api.Logs) {
		t.Helper()
		in := &api.UpdateBrokerInput{Logs: settings}
		text(&in.BrokerId, v.ID)
		if err := s.repository.Attempt(ctx, func(tx Transaction) error { _, err := s.updateBroker(tx.Context(), tx, in); return err }); err != nil {
			t.Fatal(err)
		}
	}
	general := &api.Logs{}
	boolean(&general.General, true)
	update(general)
	audit := &api.Logs{}
	boolean(&audit.Audit, true)
	update(audit)
	pending := storedBroker(t, s, v)
	if pending.Logs != (LogSettings{}) || pending.PendingLogs == nil || *pending.PendingLogs != (LogSettings{General: true, Audit: true}) {
		t.Fatalf("partial update lost pending intent or activated logging: %+v", pending)
	}
	boolean(&general.General, false)
	update(general)
	pending = storedBroker(t, s, v)
	if pending.PendingLogs == nil || *pending.PendingLogs != (LogSettings{Audit: true}) {
		t.Fatal("partial disable discarded the pending audit change")
	}
	reboot := &api.RebootBrokerInput{}
	text(&reboot.BrokerId, v.ID)
	if err := s.repository.Attempt(ctx, func(tx Transaction) error { _, err := s.rebootBroker(tx.Context(), tx, reboot); return err }); err != nil {
		t.Fatal(err)
	}
	jobs := brokerJobs{s}
	run := func() {
		t.Helper()
		job, ok, err := jobs.Next(ctx)
		if err != nil || !ok {
			t.Fatalf("missing reboot job: %v", err)
		}
		if err = jobs.Run(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	run()
	failed := storedBroker(t, s, v)
	if failed.State != "CRITICAL_ACTION_REQUIRED" || failed.Logs != (LogSettings{}) || failed.PendingLogs == nil || !failed.PendingLogs.Audit || !failed.LogDue.IsZero() {
		t.Fatalf("failed reboot promoted logging or lost intent: %+v", failed)
	}
	fail = false
	s.clock.(*clock.Manual).Advance(31 * time.Second)
	run()
	current := storedBroker(t, s, v)
	if current.State != "RUNNING" || current.Logs != (LogSettings{Audit: true}) || current.PendingLogs != nil || current.LogDue.IsZero() {
		t.Fatalf("successful retry did not promote and schedule audit delivery: %+v", current)
	}
	// Cancelling a pending enable preserves the currently effective setting.
	boolean(&general.General, true)
	update(general)
	boolean(&general.General, false)
	update(general)
	current = storedBroker(t, s, v)
	if current.PendingLogs != nil || current.Logs != (LogSettings{Audit: true}) {
		t.Fatal("cancelled pending enable changed effective audit logging")
	}
}

func TestRabbitMQAuditRejectionPreservesPendingGeneralLogging(t *testing.T) {
	s, ctx, v := controlFixture(t)
	s.runtime = loggingControlRuntime{}
	s.logs = loggingControlDelivery{}
	v.Engine = "RABBITMQ"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutBroker(v) }); err != nil {
		t.Fatal(err)
	}
	update := func(settings *api.Logs) error {
		in := &api.UpdateBrokerInput{Logs: settings}
		text(&in.BrokerId, v.ID)
		return s.repository.Attempt(ctx, func(tx Transaction) error {
			_, err := s.updateBroker(tx.Context(), tx, in)
			return err
		})
	}
	general := &api.Logs{}
	boolean(&general.General, true)
	if err := update(general); err != nil {
		t.Fatal(err)
	}
	audit := &api.Logs{}
	boolean(&audit.General, false)
	boolean(&audit.Audit, true)
	if err := update(audit); err == nil {
		t.Fatal("unsupported RabbitMQ audit logging was accepted")
	}
	current := storedBroker(t, s, v)
	if current.Logs != (LogSettings{}) || current.PendingLogs == nil || *current.PendingLogs != (LogSettings{General: true}) {
		t.Fatalf("rejected audit update changed effective or pending logs: %+v", current)
	}
	in := &api.DescribeBrokerInput{}
	text(&in.BrokerId, v.ID)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.describeBroker(tx.Context(), tx, in)
		if err != nil {
			return err
		}
		if out.Logs == nil || truth(out.Logs.General) || out.Logs.Pending == nil || !truth(out.Logs.Pending.General) {
			t.Fatalf("RabbitMQ description lost effective/pending general logs: %+v", out.Logs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
