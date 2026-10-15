package ec2

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type testFlowCapture struct {
	batch    FlowLogCaptureBatch
	err      error
	reads    int
	bindings []FlowLogInterface
	cursor   string
	read     func()
	ack      func(string) error
}

func (c *testFlowCapture) Read(_ context.Context, bindings []FlowLogInterface, cursor string) (FlowLogCaptureBatch, error) {
	c.reads++
	c.bindings = bindings
	c.cursor = cursor
	if c.read != nil {
		c.read()
	}
	return c.batch, c.err
}
func (c *testFlowCapture) Acknowledge(_ context.Context, cursor string) error {
	if c.ack != nil {
		return c.ack(cursor)
	}
	return nil
}

type testFlowDestination struct {
	writes          []FlowLogDeliveryRecord
	validated       []FlowLogRecord
	reject          *awswire.Error
	validate, write func()
}

func (d *testFlowDestination) Validate(_ context.Context, r FlowLogRecord) *awswire.Error {
	d.validated = append(d.validated, r)
	if d.validate != nil {
		d.validate()
	}
	return nil
}
func (d *testFlowDestination) Write(_ context.Context, r FlowLogDeliveryRecord, _ []FlowLogLine) *awswire.Error {
	d.writes = append(d.writes, r)
	if d.write != nil {
		d.write()
	}
	return d.reject
}

type flowTest struct {
	service     *Service
	repo        *MemoryRepository
	clock       *clock.Manual
	ctx         context.Context
	capture     *testFlowCapture
	destination *testFlowDestination
	eni         NetworkInterfaceRecord
}

func newFlowTest(t *testing.T) *flowTest {
	t.Helper()
	account := "111111111111"
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
	now := clock.NewManual(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	repo := NewMemoryRepository(nil)
	capture := &testFlowCapture{}
	dest := &testFlowDestination{}
	s := New(Config{Repository: repo, Clock: now, FlowLogCapture: capture, FlowLogDestination: dest})
	t.Cleanup(func() { _ = s.Close() })
	f := &flowTest{service: s, repo: repo, clock: now, ctx: ctx, capture: capture, destination: dest}
	f.eni = NetworkInterfaceRecord{Key: key(ctx, "eni-11111111111111111"), Data: api.NetworkInterface{NetworkInterfaceId: new(api.String("eni-11111111111111111")), OwnerId: new(api.String(account)), VpcId: new(api.String("vpc-11111111111111111")), SubnetId: new(api.String("subnet-11111111111111111")), PrivateIpAddress: new(api.String("10.0.0.4")), AvailabilityZoneId: new(api.String("use1-az1"))}}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if err := tx.PutVPC(VPCRecord{Key: key(ctx, "vpc-11111111111111111"), Data: api.Vpc{VpcId: new(api.String("vpc-11111111111111111"))}}); err != nil {
			return err
		}
		if err := tx.PutSubnet(SubnetRecord{Key: key(ctx, "subnet-11111111111111111"), Data: api.Subnet{SubnetId: new(api.String("subnet-11111111111111111")), VpcId: new(api.String("vpc-11111111111111111"))}}); err != nil {
			return err
		}
		return tx.PutNetworkInterface(f.eni)
	}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *flowTest) input() *api.CreateFlowLogsRequest {
	return &api.CreateFlowLogsRequest{ClientToken: new(api.String("flow-token")), ResourceType: new(api.FlowLogsResourceType("VPC")), ResourceIds: api.FlowLogResourceIds{"vpc-11111111111111111"}, TrafficType: new(api.TrafficType("ALL")), LogDestinationType: new(api.LogDestinationType("s3")), LogDestination: new(api.String("arn:aws:s3:::flow-bucket")), MaxAggregationInterval: new(api.Integer(60))}
}
func (f *flowTest) create(t *testing.T, in *api.CreateFlowLogsRequest) FlowLogRecord {
	t.Helper()
	out, err := f.service.createFlowLogs(f.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.FlowLogIds) != 1 || len(out.Unsuccessful) != 0 {
		t.Fatalf("unexpected admission: %#v", out)
	}
	var r FlowLogRecord
	if err = f.repo.View(f.ctx, func(tx Reader) error { var e error; r, e = tx.FlowLog(key(f.ctx, string(out.FlowLogIds[0]))); return e }); err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *flowTest) captureJob(t *testing.T) scheduler.Job {
	t.Helper()
	var state FlowLogCaptureState
	if err := f.repo.View(f.ctx, func(tx Reader) error { var e error; state, e = tx.FlowLogCaptureState(); return e }); err != nil {
		t.Fatal(err)
	}
	return scheduler.Job{Key: "flow-capture", Version: state.Version, Due: state.Due}
}
func (f *flowTest) aggregates(t *testing.T, k ResourceKey) []FlowLogAggregateRecord {
	t.Helper()
	var rows []FlowLogAggregateRecord
	if err := f.repo.View(f.ctx, func(tx Reader) error { var e error; rows, e = tx.FlowLogAggregates(k); return e }); err != nil {
		t.Fatal(err)
	}
	return rows
}
func (f *flowTest) deliveries(t *testing.T) []FlowLogDeliveryRecord {
	t.Helper()
	var rows []FlowLogDeliveryRecord
	if err := f.repo.View(f.ctx, func(tx Reader) error { var e error; rows, e = tx.FlowLogDeliveries(); return e }); err != nil {
		t.Fatal(err)
	}
	return rows
}
func (f *flowTest) observation() FlowLogObservation {
	return FlowLogObservation{InterfaceKey: f.eni.Key, Incarnation: f.eni.Key.ID, SourceAddress: "10.0.0.4", DestinationAddress: "10.0.0.8", SourcePort: 42000, DestinationPort: 443, Protocol: 6, Action: "ACCEPT", Direction: "egress", Packets: 2, Bytes: 120, Start: f.clock.Now(), End: f.clock.Now().Add(time.Second), TCPFlags: 18}
}

func TestFlowLogAdmissionTokenDryRunAndExplicitUnsupported(t *testing.T) {
	f := newFlowTest(t)
	in := f.input()
	in.DryRun = new(api.Boolean(true))
	if _, err := f.service.createFlowLogs(f.ctx, in); wireError(err).Code != "DryRunOperation" {
		t.Fatalf("dry run: %v", err)
	}
	if err := f.repo.View(f.ctx, func(tx Reader) error {
		rows, e := tx.FlowLogs(scopeFor(f.ctx))
		if len(rows) != 0 {
			t.Fatal("dry run created flow logs")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	in.DryRun = nil
	r := f.create(t, in)
	in.TrafficType = new(api.TrafficType("REJECT"))
	replayed := f.create(t, in)
	if r.Key != replayed.Key || replayed.TrafficType != "ALL" {
		t.Fatal("token replay changed immutable admission")
	}
	if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.DeleteFlowLog(r.Key) }); err != nil {
		t.Fatal(err)
	}
	out, err := f.service.createFlowLogs(f.ctx, in)
	if err != nil || len(out.FlowLogIds) != 1 || string(out.FlowLogIds[0]) == r.Key.ID {
		t.Fatalf("deleted token member was not recreated: %#v %v", out, err)
	}
	for name, change := range map[string]func(*api.CreateFlowLogsRequest){"firehose": func(i *api.CreateFlowLogsRequest) {
		i.LogDestinationType = new(api.LogDestinationType("kinesis-data-firehose"))
	}, "parquet": func(i *api.CreateFlowLogsRequest) {
		i.DestinationOptions = &api.DestinationOptionsRequest{FileFormat: new(api.DestinationFileFormat("parquet"))}
	}, "transit": func(i *api.CreateFlowLogsRequest) { i.ResourceType = new(api.FlowLogsResourceType("TransitGateway")) }, "invented metric": func(i *api.CreateFlowLogsRequest) { i.LogFormat = new(api.String("${pkt-src-aws-service}")) }} {
		t.Run(name, func(t *testing.T) {
			request := f.input()
			change(request)
			_, err := f.service.createFlowLogs(f.ctx, request)
			if err == nil {
				t.Fatalf("unsupported mode admitted: %v", err)
			}
		})
	}
}

func TestFlowLogCaptureCheckpointSealingRetryAndRestart(t *testing.T) {
	f := newFlowTest(t)
	r := f.create(t, f.input())
	f.capture.batch = FlowLogCaptureBatch{Cursor: "native-1", Observations: []FlowLogObservation{f.observation()}}
	f.capture.ack = func(cursor string) error {
		return f.repo.View(f.ctx, func(tx Reader) error {
			state, e := tx.FlowLogCaptureState()
			if e != nil {
				return e
			}
			if cursor != state.Cursor {
				t.Fatal("native Ack preceded durable checkpoint")
			}
			rows, e := tx.FlowLogAggregates(r.Key)
			if e != nil {
				return e
			}
			if len(rows) != 1 || rows[0].Packets != 2 {
				t.Fatal("Ack preceded aggregate commit")
			}
			return nil
		})
	}
	readsBefore := f.capture.reads
	job := f.captureJob(t)
	if err := f.service.captureFlowLogs(f.ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := f.service.captureFlowLogs(f.ctx, job); err != nil {
		t.Fatal(err)
	}
	if f.capture.reads != readsBefore+1 {
		t.Fatal("stale capture selection duplicated records")
	}
	if !f.clock.Now().Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("native timestamps advanced modeled time")
	}
	rows := f.aggregates(t, r.Key)
	a := rows[0]
	if err := f.clock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := f.service.sealFlowLogs(f.ctx, scheduler.Job{Key: flowLogAggregateJob(a), Due: a.Due}); err != nil {
		t.Fatal(err)
	}
	sealed := f.deliveries(t)
	if len(sealed) != 1 || !sealed[0].Due.Equal(time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)) {
		t.Fatalf("S3 cadence replaced aggregation: %#v", sealed)
	}
	d := sealed[0]
	if len(d.Lines) != 1 || !strings.HasSuffix(d.Lines[0].Message, "2 120 1767225600 1767225601 ACCEPT OK") {
		t.Fatalf("native fields not preserved: %#v", d.Lines)
	}
	if err := f.clock.Advance(4 * time.Minute); err != nil {
		t.Fatal(err)
	}
	f.destination.reject = &awswire.Error{Code: "AccessDenied", Message: "policy revoked", StatusCode: 403}
	deliver := scheduler.Job{Key: flowLogDeliveryJob(d), Version: d.Version, Due: d.Due}
	if err := f.service.deliverFlowLogs(f.ctx, deliver); err != nil {
		t.Fatal(err)
	}
	retry := f.deliveries(t)[0]
	if retry.Key != d.Key || !retry.WindowStart.Equal(d.WindowStart) || retry.Lines[0] != d.Lines[0] || retry.Version != 2 {
		t.Fatal("retry mutated sealed delivery")
	}
	f.destination.reject = nil
	if err := f.clock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	restarted := New(Config{Repository: f.repo, Clock: f.clock, FlowLogCapture: f.capture, FlowLogDestination: f.destination})
	defer restarted.Close()
	if err := restarted.deliverFlowLogs(f.ctx, scheduler.Job{Key: flowLogDeliveryJob(retry), Version: retry.Version, Due: retry.Due}); err != nil {
		t.Fatal(err)
	}
	if len(f.deliveries(t)) != 0 || len(f.destination.writes) != 2 {
		t.Fatal("restart did not recover immutable delivery")
	}
}

func TestFlowLogFutureInterfacesOverlapAndCaptureLoss(t *testing.T) {
	f := newFlowTest(t)
	vpc := f.create(t, f.input())
	in := f.input()
	in.ClientToken = new(api.String("eni-log"))
	in.ResourceType = new(api.FlowLogsResourceType("NetworkInterface"))
	in.ResourceIds = api.FlowLogResourceIds{api.FlowLogResourceId(f.eni.Key.ID)}
	eniLog := f.create(t, in)
	future := f.eni
	future.Key.ID = "eni-22222222222222222"
	future.Data.NetworkInterfaceId = new(api.String(future.Key.ID))
	future.Data.PrivateIpAddress = new(api.String("10.0.0.5"))
	if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.PutNetworkInterface(future) }); err != nil {
		t.Fatal(err)
	}
	f.capture.batch = FlowLogCaptureBatch{Cursor: "once", Observations: []FlowLogObservation{f.observation()}}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	if len(f.capture.bindings) != 2 || len(f.aggregates(t, vpc.Key)) != 1 || len(f.aggregates(t, eniLog.Key)) != 1 {
		t.Fatal("selector snapshot lost future ENI or overlapping subscription")
	}
	if err := f.clock.Advance(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	f.capture.err = errors.New("verified native receiver loss")
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	losses := 0
	for _, a := range f.aggregates(t, vpc.Key) {
		if a.Lost {
			losses++
			line := formatFlowLog(vpc, a)
			if !strings.HasSuffix(line, "- SKIPDATA") || strings.Contains(line, "NODATA") {
				t.Fatalf("loss represented as packet metrics: %s", line)
			}
		}
	}
	if losses != 2 {
		t.Fatalf("global loss not fanned out to ENIs: %d", losses)
	}
}

func TestFlowLogDeletionFencesExternalReadAndDeliveryCompletion(t *testing.T) {
	f := newFlowTest(t)
	r := f.create(t, f.input())
	f.capture.batch = FlowLogCaptureBatch{Cursor: "must-not-ack", Observations: []FlowLogObservation{f.observation()}}
	acks := 0
	f.capture.ack = func(string) error { acks++; return nil }
	f.capture.read = func() {
		if err := f.repo.Update(f.ctx, func(tx Transaction) error {
			_, e := f.service.deleteFlowLogs(tx.Context(), tx, &api.DeleteFlowLogsRequest{FlowLogIds: api.FlowLogIdList{api.VpcFlowLogId(r.Key.ID)}})
			return e
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	if acks != 0 || len(f.aggregates(t, r.Key)) != 0 {
		t.Fatal("retired cursor or subscription was resurrected")
	}
	// An already-started native write may finish while deletion commits. Its
	// completion must not recreate the subscription, batch, or status afterward.
	in := f.input()
	in.ClientToken = new(api.String("new-log"))
	r = f.create(t, in)
	d := FlowLogDeliveryRecord{Key: key(f.ctx, "batch"), FlowLogKey: r.Key, Incarnation: r.Incarnation, Due: f.clock.Now(), Version: 1, Lines: []FlowLogLine{{Start: f.clock.Now(), Message: "real sealed test record"}}}
	if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.PutFlowLogDelivery(d) }); err != nil {
		t.Fatal(err)
	}
	validatedBefore := len(f.destination.validated)
	f.destination.write = func() {
		if err := f.repo.Update(f.ctx, func(tx Transaction) error { return tx.DeleteFlowLog(r.Key) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.service.deliverFlowLogs(f.ctx, scheduler.Job{Key: flowLogDeliveryJob(d), Version: d.Version, Due: d.Due}); err != nil {
		t.Fatal(err)
	}
	if len(f.destination.writes) != 1 || len(f.deliveries(t)) != 0 || len(f.destination.validated) != validatedBefore {
		t.Fatal("delivery revalidated configuring authority or resurrected a retired batch")
	}
}

func TestFlowLogScopedDiscoveryTagsAndReadOnlyNext(t *testing.T) {
	f := newFlowTest(t)
	for i := range 6 {
		in := f.input()
		in.ClientToken = new(api.String(fmt.Sprint(i)))
		in.LogFormat = new(api.String(strings.Repeat("${interface-id} ", i+1)))
		f.create(t, in)
	}
	readsBefore := f.capture.reads
	if _, found, err := (flowLogJobs{f.service}).Next(f.ctx); err != nil || !found {
		t.Fatalf("missing persisted capture job: %v", err)
	}
	var page *api.DescribeFlowLogsResult
	if err := f.repo.Update(f.ctx, func(tx Transaction) error {
		var e error
		page, e = f.service.describeFlowLogs(tx.Context(), tx, &api.DescribeFlowLogsRequest{MaxResults: new(api.Integer(5))})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if len(page.FlowLogs) != 5 || page.NextToken == nil {
		t.Fatal("missing scoped pagination")
	}
	id := str(page.FlowLogs[0].FlowLogId)
	if err := f.repo.Update(f.ctx, func(tx Transaction) error {
		_, e := f.service.createTags(tx.Context(), tx, &api.CreateTagsRequest{Resources: api.ResourceIdList{api.TaggableResourceId(id)}, Tags: api.TagList{{Key: new(api.String("team")), Value: new(api.String("network"))}}})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Update(f.ctx, func(tx Transaction) error {
		out, e := f.service.describeFlowLogs(tx.Context(), tx, &api.DescribeFlowLogsRequest{Filter: api.FilterList{{Name: new(api.String("tag:team")), Values: api.ValueStringList{"network"}}}})
		if e == nil && (len(out.FlowLogs) != 1 || str(out.FlowLogs[0].FlowLogId) != id) {
			t.Fatal("flow log tag filter/readback missing")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	other := awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: "us-east-1", PrincipalARN: "arn:aws:iam::222222222222:root", PrincipalID: "222222222222"})
	if err := f.repo.Update(other, func(tx Transaction) error {
		_, e := f.service.describeFlowLogs(tx.Context(), tx, &api.DescribeFlowLogsRequest{NextToken: page.NextToken})
		if e == nil {
			t.Fatal("pagination crossed accounts")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if f.capture.reads != readsBefore || len(f.destination.writes) != 0 {
		t.Fatal("scheduler Next performed external effects")
	}
}

func TestFlowLogFormatVersionAndUnavailableFields(t *testing.T) {
	if v, e := validateFlowLogFormat(defaultFlowLogFormat); e != nil || v != 2 {
		t.Fatalf("default format version: %d %v", v, e)
	}
	if v, e := validateFlowLogFormat("${interface-id} ${vpc-id} ${tcp-flags} ${flow-direction}"); e != nil || v != 5 {
		t.Fatalf("maximum field version: %d %v", v, e)
	}
	if _, e := validateFlowLogFormat("${ecs-cluster-name}"); e == nil {
		t.Fatal("unsupported ECS enrichment invented")
	}
	owner := Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	participant := owner
	participant.AccountID = "222222222222"
	r := FlowLogRecord{Key: ResourceKey{Scope: owner, ID: "fl-shared"}, ResourceType: "VPC", ResourceID: "vpc-shared", LogFormat: defaultFlowLogFormat, FormatVersion: 2}
	i := FlowLogInterface{Key: ResourceKey{Scope: participant, ID: "eni-participant"}, NetworkID: resourceARN(owner, "vpc", "vpc-shared"), VPCID: "vpc-shared"}
	if !flowLogMatches(r, i) {
		t.Fatal("VPC owner cannot log authoritative participant ENI")
	}
	a := FlowLogAggregateRecord{Interface: i, Lost: true, Start: time.Unix(1, 0), End: time.Unix(2, 0)}
	if line := formatFlowLog(r, a); !strings.HasPrefix(line, "2 222222222222 eni-participant ") {
		t.Fatalf("subscription owner spoofed ENI account: %s", line)
	}
	r.Key.Scope.AccountID = "333333333333"
	if flowLogMatches(r, i) {
		t.Fatal("unrelated account captured participant ENI")
	}
}

func TestFlowLogNativeTokenFormatGroupsLiveResourcesAndDuplicateConfiguration(t *testing.T) {
	f := newFlowTest(t)
	baseline := f.create(t, f.input())
	if len(f.destination.validated) != 1 || f.destination.validated[0].Key != baseline.Key || f.destination.validated[0].Incarnation != baseline.Incarnation {
		t.Fatal("destination preflight did not use the concrete planned subscription identity")
	}
	secondVPC := "vpc-22222222222222222"
	if err := f.repo.Update(f.ctx, func(tx Transaction) error {
		return tx.PutVPC(VPCRecord{Key: key(f.ctx, secondVPC), Data: api.Vpc{VpcId: new(api.String(secondVPC))}})
	}); err != nil {
		t.Fatal(err)
	}
	request := f.input()
	request.ResourceIds = api.FlowLogResourceIds{api.FlowLogResourceId(secondVPC)}
	group, err := f.service.createFlowLogs(f.ctx, request)
	if err != nil || len(group.FlowLogIds) != 2 {
		t.Fatalf("resource did not join token format group: %#v %v", group, err)
	}
	request = f.input()
	request.LogDestination = new(api.String("arn:aws:s3:::different-bucket/changed-prefix"))
	request.TrafficType = new(api.TrafficType("REJECT"))
	replayed, err := f.service.createFlowLogs(f.ctx, request)
	if err != nil || len(replayed.FlowLogIds) != 2 {
		t.Fatalf("replay lost accumulated group: %#v %v", replayed, err)
	}
	if len(f.destination.validated) != 2 {
		t.Fatal("existing token member revalidated a changed ignored destination")
	}
	request = f.input()
	request.LogFormat = new(api.String("${interface-id}"))
	custom := f.create(t, request)
	if custom.Key == baseline.Key {
		t.Fatal("new format reused old token format group")
	}
	request = f.input()
	request.ClientToken = new(api.String("fresh-token"))
	if _, err := f.service.createFlowLogs(f.ctx, request); err == nil || wireError(err).Code != "FlowLogAlreadyExists" {
		t.Fatalf("new token silently duplicated an existing configuration: %v", err)
	}
	request.TrafficType = new(api.TrafficType("REJECT"))
	reject := f.create(t, request)
	if reject.TrafficType != "REJECT" || reject.Key == baseline.Key {
		t.Fatal("new-token distinct traffic configuration did not create a subscription")
	}
}

func TestFlowLogCreateResourceLimit(t *testing.T) {
	f := newFlowTest(t)
	request := f.input()
	for len(request.ResourceIds) < 300 {
		request.ResourceIds = append(request.ResourceIds, request.ResourceIds[0])
	}
	if _, _, err := flowLogRequest(request); err != nil {
		t.Fatalf("documented 300-resource boundary rejected: %v", err)
	}
	request.ResourceIds = append(request.ResourceIds, request.ResourceIds[0])
	if _, _, err := flowLogRequest(request); err == nil || wireError(err).Code != "InvalidParameterValue" {
		t.Fatalf("over-limit flow selection admitted: %v", err)
	}
}

func TestFlowLogLateCaptureDoesNotReplaceSealedDelivery(t *testing.T) {
	f := newFlowTest(t)
	r := f.create(t, f.input())
	first := f.observation()
	f.capture.batch = FlowLogCaptureBatch{Cursor: "first", Observations: []FlowLogObservation{first}}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	a := f.aggregates(t, r.Key)[0]
	if err := f.clock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := f.service.sealFlowLogs(f.ctx, scheduler.Job{Key: flowLogAggregateJob(a), Due: a.Due}); err != nil {
		t.Fatal(err)
	}
	original := f.deliveries(t)[0]
	late := first
	late.Start, late.End = first.Start.Add(2*time.Second), first.End.Add(2*time.Second)
	late.Packets, late.Bytes = 1, 60
	f.capture.batch = FlowLogCaptureBatch{Cursor: "late", Observations: []FlowLogObservation{late}}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	a = f.aggregates(t, r.Key)[0]
	if err := f.clock.Advance(a.Due.Sub(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	if err := f.service.sealFlowLogs(f.ctx, scheduler.Job{Key: flowLogAggregateJob(a), Due: a.Due}); err != nil {
		t.Fatal(err)
	}
	deliveries := f.deliveries(t)
	if len(deliveries) != 2 {
		t.Fatalf("late packet replaced an immutable S3 object batch: %+v", deliveries)
	}
	var packets, bytes uint64
	for _, batch := range deliveries {
		if batch.Key == original.Key && !reflect.DeepEqual(batch, original) {
			t.Fatal("late capture mutated sealed delivery")
		}
		for _, line := range batch.Lines {
			fields := strings.Fields(line.Message)
			n, err := strconv.ParseUint(fields[8], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			packets += n
			n, err = strconv.ParseUint(fields[9], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			bytes += n
		}
	}
	if packets != 3 || bytes != 180 {
		t.Fatalf("late capture lost packet counts: packets=%d bytes=%d", packets, bytes)
	}
}

func TestFlowLogSealingBatchesClosedFlowsWithoutLosingTuples(t *testing.T) {
	f := newFlowTest(t)
	r := f.create(t, f.input())
	var observations []FlowLogObservation
	for port := uint16(42000); port < 42003; port++ {
		o := f.observation()
		o.SourcePort = port
		observations = append(observations, o)
	}
	f.capture.batch = FlowLogCaptureBatch{Cursor: "three-flows", Observations: observations}
	if err := f.service.captureFlowLogs(f.ctx, f.captureJob(t)); err != nil {
		t.Fatal(err)
	}
	a := f.aggregates(t, r.Key)[0]
	if err := f.clock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := f.service.sealFlowLogs(f.ctx, scheduler.Job{Key: flowLogAggregateJob(a), Due: a.Due}); err != nil {
		t.Fatal(err)
	}
	deliveries := f.deliveries(t)
	if len(deliveries) != 1 || len(f.aggregates(t, r.Key)) != 0 {
		t.Fatal("closed flows were not sealed in one publication batch")
	}
	ports := map[string]bool{}
	for _, line := range deliveries[0].Lines {
		fields := strings.Fields(line.Message)
		if ports[fields[5]] || fields[8] != "2" || fields[9] != "120" {
			t.Fatalf("duplicate or damaged flow: %s", line.Message)
		}
		ports[fields[5]] = true
	}
	if !ports["42000"] || !ports["42001"] || !ports["42002"] || len(ports) != 3 {
		t.Fatalf("publication lost flow tuples: %+v", ports)
	}
}
