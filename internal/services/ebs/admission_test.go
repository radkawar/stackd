package ebs

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
)

func TestSnapshotAdmissionBoundaries(t *testing.T) {
	var fixture struct {
		AccountRates []struct {
			Action, Region string
			Rate           int
		} `json:"account_rates"`
		SnapshotRates []struct {
			Action string
			Rate   int
		} `json:"snapshot_rates"`
	}
	data, err := os.ReadFile("../../../testdata/integration/ebs/admission.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.AccountRates {
		t.Run(row.Action+"/"+row.Region, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC))
			s := &Service{clock: source}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: row.Region})
			for i := 0; i < row.Rate; i++ {
				if rejected := s.admitAccount(ctx, row.Action); rejected != nil {
					t.Fatalf("request %d: %v", i+1, rejected)
				}
			}
			if rejected := s.admitAccount(ctx, row.Action); rejected == nil || rejected.Code != "RequestThrottledException" || rejected.Reason != "ACCOUNT_THROTTLED" || rejected.StatusCode != 400 {
				t.Fatalf("account boundary: %v", rejected)
			}
			other := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: row.Region})
			if rejected := s.admitAccount(other, row.Action); rejected != nil {
				t.Fatalf("other account throttled: %v", rejected)
			}
			source.Advance(time.Second / time.Duration(row.Rate))
			if rejected := s.admitAccount(ctx, row.Action); rejected != nil {
				t.Fatalf("refilled request: %v", rejected)
			}
			if rejected := s.admitAccount(ctx, row.Action); rejected == nil {
				t.Fatal("one refill admitted two requests")
			}
		})
	}
	for _, row := range fixture.SnapshotRates {
		t.Run(row.Action+"/snapshot", func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC))
			s := &Service{clock: source}
			key := SnapshotKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, ID: "snap-00000000000000001"}
			for i := 0; i < row.Rate; i++ {
				if rejected := s.admitBlock(key, row.Action); rejected != nil {
					t.Fatalf("request %d: %v", i+1, rejected)
				}
			}
			if rejected := s.admitBlock(key, row.Action); rejected == nil || rejected.Code != "RequestThrottledException" || rejected.Reason != "RESOURCE_LEVEL_THROTTLE" || rejected.StatusCode != 400 {
				t.Fatalf("snapshot boundary: %v", rejected)
			}
			other := key
			other.ID = "snap-00000000000000002"
			if rejected := s.admitBlock(other, row.Action); rejected != nil {
				t.Fatalf("other snapshot throttled: %v", rejected)
			}
			source.Advance(time.Second / time.Duration(row.Rate))
			if rejected := s.admitBlock(key, row.Action); rejected != nil {
				t.Fatalf("refilled request: %v", rejected)
			}
			if rejected := s.admitBlock(key, row.Action); rejected == nil {
				t.Fatal("one refill admitted two requests")
			}
		})
	}
}
