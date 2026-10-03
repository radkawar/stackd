package codebuild

import (
	"context"
	"errors"
	"testing"
	"time"

	runtime "stackd/compute/codebuild"
	api "stackd/internal/awsapi/codebuild"
)

type idleFleetExecutor struct {
	runtime.Executor
	runtime.FleetExecutor
}

func (idleFleetExecutor) ReleaseFleet(context.Context, string) error { return nil }

func TestDeletingFleetDrainsRetainedAdmissionAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name                                           string
		admitted, complete, pending, foreign, retained bool
	}{
		{"preparing", true, false, false, false, true},
		{"cleanup", true, true, true, false, true},
		{"drained", true, true, false, false, false},
		{"queued", false, false, false, false, false},
		{"old-incarnation", true, false, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, build := seededBuild(t)
			s.executor = idleFleetExecutor{}
			key := FleetKey{Scope: build.Key.Scope, Name: "reserved"}
			arn := key.ARN("00000000-0000-4000-8000-000000000001")
			build.FleetARN = arn
			if tc.foreign {
				build.FleetARN = key.ARN("00000000-0000-4000-8000-000000000002")
			}
			if tc.admitted {
				build.Deadline = s.clock.Now().Add(time.Minute)
			}
			build.Data.BuildComplete = new(api.Boolean(tc.complete))
			build.CleanupPending = tc.pending
			if err := s.repository.Update(context.Background(), func(tx Transaction) error {
				if err := tx.PutBuild(build); err != nil {
					return err
				}
				return tx.PutFleet(FleetRecord{Key: key, Data: api.Fleet{Arn: new(api.NonEmptyString(arn)), Status: &api.FleetStatus{StatusCode: new(api.FleetStatusCode("DELETING"))}}})
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.controller.reconcileFleets(); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(context.Background(), func(r Reader) error {
				fleet, err := r.Fleet(key)
				if tc.retained {
					if err != nil || value(fleet.Data.Status.StatusCode) != "DELETING" {
						t.Fatalf("lost admitted fleet: %+v, %v", fleet, err)
					}
				} else if !errors.Is(err, ErrNotFound) {
					t.Fatalf("drained fleet retained: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
