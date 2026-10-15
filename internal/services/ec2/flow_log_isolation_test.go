package ec2

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

func TestFlowLogUnavailableCaptureNeverClaimsReadinessOrInventsNoData(t *testing.T) {
	f := newFlowTest(t)
	f.service.flowLogCapture = nil
	r := f.create(t, f.input())
	if r.Status != "ACTIVE" || r.DeliveryStatus != "FAILED" || r.CaptureError == "" {
		t.Fatal("unavailable native capture advertised readiness")
	}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	rows := f.aggregates(t, r.Key)
	if len(rows) != 1 || !rows[0].Lost || rows[0].Packets != 0 || rows[0].Bytes != 0 {
		t.Fatalf("capture failure invented packet counters: %#v", rows)
	}
	line := formatFlowLog(r, rows[0])
	if !strings.HasSuffix(line, "- SKIPDATA") || strings.Contains(line, "NODATA") {
		t.Fatalf("capture failure formatted as data: %s", line)
	}
	// Empty successful observation sets contain no evidence of an idle interval.
	// They must not synthesize an AWS NODATA record.
	f.service.flowLogCapture = f.capture
	f.capture.batch = FlowLogCaptureBatch{Cursor: "healthy-empty"}
	if err := f.clock.Advance(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	if len(f.aggregates(t, r.Key)) != 1 {
		t.Fatal("empty capture manufactured an idle record")
	}
}

func TestFlowLogMemoryDetachedTagsLinesAndAtomicRollback(t *testing.T) {
	f := newFlowTest(t)
	in := f.input()
	in.TagSpecifications = api.TagSpecificationList{{ResourceType: new(api.ResourceType("vpc-flow-log")), Tags: api.TagList{{Key: new(api.String("team")), Value: new(api.String("original"))}}}}
	r := f.create(t, in)
	delivery := FlowLogDeliveryRecord{Key: key(f.ctx, "immutable-batch"), FlowLogKey: r.Key, Incarnation: r.Incarnation, WindowStart: f.clock.Now(), Due: f.clock.Now(), Version: 1, Lines: []FlowLogLine{{Start: f.clock.Now(), InterfaceID: f.eni.Key.ID, Message: "retained"}}}
	if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.PutFlowLogDelivery(delivery) }); err != nil {
		t.Fatal(err)
	}
	*r.Tags[0].Value = "caller mutation"
	delivery.Lines[0].Message = "caller mutation"
	if err := f.repo.View(f.ctx, func(tx Reader) error {
		current, e := tx.FlowLog(r.Key)
		if e != nil {
			return e
		}
		if str(current.Tags[0].Value) != "original" {
			t.Fatal("input tag pointer leaked into storage")
		}
		*current.Tags[0].Value = "reader mutation"
		rows, e := tx.FlowLogDeliveries()
		if e != nil {
			return e
		}
		if rows[0].Lines[0].Message != "retained" {
			t.Fatal("input line slice leaked into storage")
		}
		rows[0].Lines[0].Message = "reader mutation"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("rollback")
	if err := f.repo.Update(f.ctx, func(tx Transaction) error {
		if e := tx.DeleteFlowLog(r.Key); e != nil {
			return e
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if err := f.repo.View(f.ctx, func(tx Reader) error {
		current, e := tx.FlowLog(r.Key)
		if e != nil {
			return e
		}
		if str(current.Tags[0].Value) != "original" {
			t.Fatal("read tag pointer leaked into storage")
		}
		rows, e := tx.FlowLogDeliveries()
		if e != nil {
			return e
		}
		if len(rows) != 1 || rows[0].Lines[0].Message != "retained" {
			t.Fatal("rollback or read mutated sealed lines")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFlowLogStaleDeliverySelectionDoesNotWriteOrResurrect(t *testing.T) {
	f := newFlowTest(t)
	r := f.create(t, f.input())
	d := FlowLogDeliveryRecord{Key: key(f.ctx, "versioned-batch"), FlowLogKey: r.Key, Incarnation: r.Incarnation, Version: 2, Due: f.clock.Now()}
	if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.PutFlowLogDelivery(d) }); err != nil {
		t.Fatal(err)
	}
	if err := f.service.deliverFlowLogs(f.ctx, scheduler.Job{Key: flowLogDeliveryJob(d), Version: 1, Due: d.Due}); err != nil {
		t.Fatal(err)
	}
	if len(f.destination.writes) != 0 || len(f.deliveries(t)) != 1 {
		t.Fatal("stale selected version wrote or consumed delivery")
	}
	wrong := d
	wrong.Key.Scope.AccountID = "222222222222"
	if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.PutFlowLogDelivery(wrong) }); err == nil {
		t.Fatal("cross-account delivery parent accepted")
	}
}

type blockingFlowCapture struct{ entered chan struct{} }

func (c *blockingFlowCapture) Read(ctx context.Context, _ []FlowLogInterface, _ string) (FlowLogCaptureBatch, error) {
	close(c.entered)
	<-ctx.Done()
	return FlowLogCaptureBatch{}, ctx.Err()
}
func (*blockingFlowCapture) Acknowledge(context.Context, string) error { return nil }

func TestFlowLogNativeEffectsReleaseSharedSchedulerAndCloseJoins(t *testing.T) {
	f := newFlowTest(t)
	f.create(t, f.input())
	capture := &blockingFlowCapture{entered: make(chan struct{})}
	f.service.flowLogCapture = capture
	source := flowLogJobs{f.service}
	job, found, err := source.Next(f.ctx)
	if err != nil || !found {
		t.Fatalf("missing source work: %v", err)
	}
	if err = source.Run(f.ctx, job); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	select {
	case <-capture.entered:
	case <-ctx.Done():
		t.Fatal("native work did not dispatch")
	}
	if _, found, err = source.Next(f.ctx); err != nil || found {
		t.Fatalf("in-flight effect was redispatched: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- f.service.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not cancel and join native capture")
	}
}

func TestFlowLogPacketAddressesTCPFlagsAndInstancePrivacy(t *testing.T) {
	f := newFlowTest(t)
	r := f.create(t, f.input())
	for index, flags := range []uint8{16, 66, 18} {
		o := f.observation()
		o.SourcePort += uint16(index)
		o.TCPFlags = flags
		if err := f.repo.Update(f.ctx, func(tx Transaction) error {
			return f.service.mergeFlowLogObservation(tx, r, FlowLogInterface{Key: f.eni.Key, Address: "10.0.0.4"}, o, make(map[FlowLogAggregateKey]FlowLogAggregateRecord))
		}); err != nil {
			t.Fatal(err)
		}
	}
	expected := map[uint16]uint8{42000: 0, 42001: 2, 42002: 18}
	for _, aggregate := range f.aggregates(t, r.Key) {
		if aggregate.TCPFlags != expected[aggregate.SourcePort] {
			t.Fatalf("unsupported TCP flags leaked into AWS field: %+v", aggregate)
		}
	}
	r.LogFormat = "${srcaddr} ${dstaddr} ${pkt-srcaddr} ${pkt-dstaddr} ${instance-id}"
	r.FormatVersion = 3
	a := FlowLogAggregateRecord{
		Interface:     FlowLogInterface{Key: f.eni.Key, Address: "10.0.0.4", InstanceID: "i-owned"},
		SourceAddress: "172.16.1.2", DestinationAddress: "10.0.0.8", Direction: "egress",
	}
	if got := formatFlowLog(r, a); got != "10.0.0.4 10.0.0.8 172.16.1.2 10.0.0.8 i-owned" {
		t.Fatalf("default and packet-level egress addresses collapsed: %s", got)
	}
	a.Direction = "ingress"
	a.SourceAddress, a.DestinationAddress = "10.0.0.8", "10.0.0.9"
	r.Key.Scope.AccountID = "222222222222"
	if got := formatFlowLog(r, a); got != "10.0.0.8 10.0.0.4 10.0.0.8 10.0.0.9 -" {
		t.Fatalf("ingress primary address or cross-account instance privacy changed: %s", got)
	}
}

func TestFlowLogCaptureRecoveryCannotEraseDestinationFailure(t *testing.T) {
	f := newFlowTest(t)
	r := f.create(t, f.input())
	d := FlowLogDeliveryRecord{Key: key(f.ctx, "independent-errors"), FlowLogKey: r.Key, Incarnation: r.Incarnation, Due: f.clock.Now(), Version: 1}
	if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.PutFlowLogDelivery(d) }); err != nil {
		t.Fatal(err)
	}
	f.destination.reject = &awswire.Error{Code: "AccessDenied", Message: "destination policy revoked", StatusCode: 403}
	if err := f.service.deliverFlowLogs(f.ctx, scheduler.Job{Key: flowLogDeliveryJob(d), Version: d.Version, Due: d.Due}); err != nil {
		t.Fatal(err)
	}
	f.capture.err = errors.New("collector unavailable")
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	f.capture.err = nil
	if err := f.clock.Advance(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.View(f.ctx, func(tx Reader) error {
		current, err := tx.FlowLog(r.Key)
		if err != nil {
			return err
		}
		if current.CaptureError != "" || current.DeliveryError != "destination policy revoked" || current.DeliveryStatus != "FAILED" {
			t.Fatalf("capture recovery erased destination failure: %+v", current)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFlowLogAdvancingUnreadyBatchCommitsAndDrainsBacklog(t *testing.T) {
	f := newFlowTest(t)
	f.capture.batch = FlowLogCaptureBatch{CoverageError: "desired ENI has no current native coverage"}
	r := f.create(t, f.input())
	if r.DeliveryStatus != "FAILED" || r.CaptureError == "" {
		t.Fatal("admission ignored current coverage failure")
	}
	f.capture.batch = FlowLogCaptureBatch{
		Cursor: "covered-page-1", More: true,
		CoverageError: "desired ENI has no current native coverage",
		Observations:  []FlowLogObservation{f.observation()},
	}
	acked := ""
	f.capture.ack = func(cursor string) error { acked = cursor; return nil }
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	if acked != "covered-page-1" || len(f.aggregates(t, r.Key)) != 1 {
		t.Fatal("coverage failure discarded an advancing durable packet batch")
	}
	if err := f.repo.View(f.ctx, func(tx Reader) error {
		state, err := tx.FlowLogCaptureState()
		if err != nil {
			return err
		}
		if state.Cursor != acked || !state.Due.Equal(f.clock.Now()) {
			t.Fatal("backlog was delayed or checkpoint omitted")
		}
		current, err := tx.FlowLog(r.Key)
		if err != nil {
			return err
		}
		if current.CaptureError == "" || current.DeliveryStatus != "FAILED" {
			t.Fatal("transport success hid missing current coverage")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.capture.batch = FlowLogCaptureBatch{Cursor: "covered-page-2", Observations: []FlowLogObservation{{Lost: true, Start: f.clock.Now(), End: f.clock.Now()}}}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.View(f.ctx, func(tx Reader) error {
		current, err := tx.FlowLog(r.Key)
		if err != nil {
			return err
		}
		if current.CaptureError != "" || current.DeliveryStatus != "SUCCESS" {
			t.Fatal("historical journal loss was confused with current coverage")
		}
		state, err := tx.FlowLogCaptureState()
		if err == nil && !state.Due.Equal(f.clock.Now().Add(10*time.Second)) {
			t.Fatal("drained journal did not resume idle polling")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
