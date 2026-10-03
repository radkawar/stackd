package stackd_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"stackd"
	"stackd/clock"
)

type s3ExecutionScenario struct {
	Name  string
	TLS   bool
	Setup []s3KMSCall
	Calls []s3ObjectCall
}

type s3ExecutionCall struct {
	s3MultipartCall
	At               time.Time
	Drain            bool
	Notifications    []s3NotifyDelivery
	QuietQueues      []string
	AbsentHeaders    []string
	InventoryReports []s3InventoryReportExpectation
}

type s3ExecutionWorkflow struct {
	Name, AuditBucket, AuditPrefix string
	TLS                            bool
	RequiredCloudTrailEvents       []string
	ForbiddenCloudTrailEvents      []string
	Setup                          []s3KMSCall
	Calls                          []s3ExecutionCall
}

type s3ExecutionFixture struct {
	Scenarios []s3ExecutionScenario
	Payloads  map[string][]s3MultipartPayload
	Workflows []s3ExecutionWorkflow
}

// Execution fixtures distinguish documented behavior from native observations.
// At/Drain express the local daily scheduler contract, not an AWS completion SLA.
func runS3ExecutionReplay(t *testing.T, path string) {
	t.Helper()
	var fixture s3ExecutionFixture
	awsReadFixture(t, path, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				runS3ObjectCalls(t, backend, scenario.Setup, scenario.Calls, scenario.TLS)
			})
		}
		for _, scenario := range fixture.Workflows {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				source := clock.NewManual(scenario.Calls[0].At)
				clients, reopen := retainedS3ReplayCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, scenario.TLS)
				replay := newS3KMSReplay(clients)
				for _, row := range scenario.Setup {
					replay.call(t, row)
				}
				for _, row := range scenario.Calls {
					if !t.Run(fmt.Sprintf("%03d-%s", row.Sequence, row.Label), func(t *testing.T) {
						if row.Reopen {
							replay.clients, replay.httpClient = reopen(), nil
						}
						advanceClock(t, source, row.At.Sub(source.Now()))
						if row.Drain {
							trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
						}
						wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
						replay.httpClient = wire
						if row.Payload != "" || row.Digest != nil {
							s3MultipartReplayCall(t, replay, fixture.Payloads, row.s3MultipartCall)
						} else {
							replay.call(t, row.s3KMSCall)
						}
						var details, headers map[string]string
						if err := json.Unmarshal(replay.rebind(t, row.ErrorDetails), &details); err != nil {
							t.Fatal(err)
						}
						assertS3ErrorDetails(t, wire.body, details)
						if err := json.Unmarshal(replay.rebind(t, row.Headers), &headers); err != nil {
							t.Fatal(err)
						}
						for name, want := range headers {
							if got := wire.header.Get(name); got != want {
								t.Fatalf("%s = %q; want %q", name, got, want)
							}
						}
						for _, name := range row.AbsentHeaders {
							if _, exists := wire.header[http.CanonicalHeaderKey(name)]; exists {
								t.Fatalf("unexpected header %s", name)
							}
						}
						var deliveries []s3NotifyDelivery
						if err := json.Unmarshal(replay.rebind(t, row.Notifications), &deliveries); err != nil {
							t.Fatal(err)
						}
						receipts := make(map[string][]s3NotifyReceipt)
						for _, expected := range deliveries {
							if _, collected := receipts[expected.Queue]; !collected {
								receipts[expected.Queue] = nil
								s3NotifyCollect(t, replay, expected.Queue, receipts)
							}
							found := -1
							for i, got := range receipts[expected.Queue] {
								if expected.Kind == "eventbridge" {
									if got.payload["detail-type"] != expected.Payload["detail-type"] || awsFixtureField(got.payload, "detail.object.key") != awsFixtureField(expected.Payload, "detail.object.key") {
										continue
									}
								} else if got.payload["eventName"] != expected.Payload["eventName"] || awsFixtureField(got.payload, "s3.object.key") != awsFixtureField(expected.Payload, "s3.object.key") {
									continue
								}
								found = i
								break
							}
							if found < 0 {
								t.Fatalf("missing document-derived S3 delivery: %#v; received %#v", expected.Payload, receipts[expected.Queue])
							}
							s3NativeProjection(t, row.Label, expected.Payload, receipts[expected.Queue][found].payload)
							receipts[expected.Queue] = append(receipts[expected.Queue][:found], receipts[expected.Queue][found+1:]...)
						}
						for queue, remaining := range receipts {
							for _, got := range remaining {
								if got.payload["Event"] != "s3:TestEvent" {
									t.Fatalf("unexpected delivery on %s: %#v", queue, got.payload)
								}
							}
						}
						var quiet []string
						if err := json.Unmarshal(replay.rebind(t, row.QuietQueues), &quiet); err != nil {
							t.Fatal(err)
						}
						for _, queue := range quiet {
							got := make(map[string][]s3NotifyReceipt)
							s3NotifyCollect(t, replay, queue, got)
							if len(got[queue]) != 0 {
								t.Fatalf("unexpected repeated S3 delivery on %s: %#v", queue, got[queue])
							}
						}
						if len(row.InventoryReports) != 0 {
							assertS3InventoryReports(t, replay, row.InventoryReports)
						}
					}) {
						return
					}
				}
				if scenario.AuditBucket != "" {
					replay.clients, replay.httpClient = reopen(), nil
					advanceClock(t, source, 6*time.Minute)
					trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
					records := trailNativeRecords(t, trailNativeObjects(t, replay.s3Client("caller"), scenario.AuditBucket, scenario.AuditPrefix))
					seen := make(map[string]bool)
					for _, record := range records {
						if record["eventSource"] != "s3.amazonaws.com" {
							continue
						}
						name, _ := record["eventName"].(string)
						seen[name] = true
						for _, forbidden := range scenario.ForbiddenCloudTrailEvents {
							if name == forbidden {
								t.Fatalf("S3 execution fabricated a CloudTrail object API: %#v", record)
							}
						}
					}
					for _, required := range scenario.RequiredCloudTrailEvents {
						if !seen[required] {
							t.Fatalf("missing real %s CloudTrail positive control", required)
						}
					}
				}
			})
		}
	}
}
