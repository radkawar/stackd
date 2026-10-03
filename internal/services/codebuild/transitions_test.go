package codebuild

import (
	"context"
	"encoding/json"
	"os"
	"stackd/clock"
	runtime "stackd/compute/codebuild"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/scheduler"
	"testing"
	"time"
)

type nativeOutcome struct {
	Case          string `json:"case"`
	BuildStatus   string `json:"buildStatus"`
	CurrentPhase  string `json:"currentPhase"`
	BuildComplete bool   `json:"buildComplete"`
	BuildPhase    struct {
		Status   string `json:"phaseStatus"`
		Contexts []struct {
			Code string `json:"statusCode"`
		} `json:"contexts"`
	} `json:"build_phase"`
	UploadPhase struct {
		Status string `json:"phaseStatus"`
	} `json:"upload_artifacts_phase"`
}

func nativeOutcomes(t *testing.T) map[string]nativeOutcome {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/aws/codebuild/capture_summary.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Outcomes []nativeOutcome `json:"build_outcomes"`
	}
	if err = json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	out := map[string]nativeOutcome{}
	for _, v := range capture.Outcomes {
		out[v.Case] = v
	}
	return out
}
func seededBuild(t *testing.T) (*Service, BuildRecord) {
	t.Helper()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now)})
	t.Cleanup(func() { s.Close() })
	r := BuildRecord{Key: BuildKey{Scope: Scope{"aws", "111122223333", "us-east-1"}, ID: "project:build"}, Data: api.Build{ProjectName: new(api.NonEmptyString("project")), CurrentPhase: new(api.String("BUILD")), BuildStatus: new(api.StatusType("IN_PROGRESS")), BuildComplete: new(api.Boolean(false)), StartTime: &now, Phases: api.BuildPhases{{PhaseType: new(api.BuildPhaseType("BUILD")), StartTime: &now}}}}
	if err := s.repository.Update(context.Background(), func(tx Transaction) error { return tx.PutBuild(r) }); err != nil {
		t.Fatal(err)
	}
	return s, r
}
func requireNativeTerminal(t *testing.T, s *Service, r BuildRecord, want nativeOutcome) {
	t.Helper()
	got, err := s.controller.load(r.Key)
	if err != nil {
		t.Fatal(err)
	}
	if value(got.Data.BuildStatus) != want.BuildStatus || value(got.Data.CurrentPhase) != want.CurrentPhase || complete(got) != want.BuildComplete {
		t.Fatalf("terminal: %+v; native %+v", got.Data, want)
	}
	found := false
	for _, phase := range got.Data.Phases {
		if value(phase.PhaseType) == "BUILD" {
			found = true
			if value(phase.PhaseStatus) != want.BuildPhase.Status {
				t.Fatalf("build phase=%s native=%s", value(phase.PhaseStatus), want.BuildPhase.Status)
			}
			if len(want.BuildPhase.Contexts) > 0 && want.BuildPhase.Contexts[0].Code != "" {
				if len(phase.Contexts) != 1 || value(phase.Contexts[0].StatusCode) != want.BuildPhase.Contexts[0].Code {
					t.Fatalf("contexts=%+v native=%+v", phase.Contexts, want.BuildPhase.Contexts)
				}
			}
		}
	}
	if !found {
		t.Fatal("lost BUILD phase")
	}
	if !got.CleanupPending {
		t.Fatal("terminal transition lost native cleanup intent")
	}
}
func TestObservedFailureRetainsSuccessfulArtifactPhase(t *testing.T) {
	native := nativeOutcomes(t)["failure_status"]
	s, r := seededBuild(t)
	observation := runtime.Status{State: "exited", ExitCode: 7, Phases: []runtime.Phase{{Name: "BUILD", Status: "FAILED", Message: "exit status 7"}, {Name: "POST_BUILD", Status: "SUCCEEDED"}}}
	for range 2 {
		if err := s.controller.observe(r, observation); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.controller.phase(r.Key, "UPLOAD_ARTIFACTS"); err != nil {
		t.Fatal(err)
	}
	if err := s.controller.completeUpload(r.Key, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.controller.finish(r, "FAILED", "Build command exited with status 7."); err != nil {
		t.Fatal(err)
	}
	requireNativeTerminal(t, s, r, native)
	got, err := s.controller.load(r.Key)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range got.Data.Phases {
		if value(phase.PhaseType) == "UPLOAD_ARTIFACTS" && value(phase.PhaseStatus) != native.UploadPhase.Status {
			t.Fatalf("upload=%s native=%s", value(phase.PhaseStatus), native.UploadPhase.Status)
		}
	}
}
func TestNativeBuildTimeoutIsDistinctFromCancellation(t *testing.T) {
	native := nativeOutcomes(t)
	for _, name := range []string{"timeout_status", "cancellation_status"} {
		t.Run(name, func(t *testing.T) {
			s, r := seededBuild(t)
			if name == "timeout_status" {
				r.Deadline = s.clock.Now()
				if err := s.repository.Update(context.Background(), func(tx Transaction) error { return tx.PutBuild(r) }); err != nil {
					t.Fatal(err)
				}
				j := deadlineJobs{s}
				if err := j.Run(context.Background(), scheduler.Job{Key: "aws/111122223333/us-east-1/project:build", Due: r.Deadline}); err != nil {
					t.Fatal(err)
				}
			} else {
				r.StopRequested = true
				if err := s.repository.Update(context.Background(), func(tx Transaction) error { return tx.PutBuild(r) }); err != nil {
					t.Fatal(err)
				}
			}
			latest, err := s.controller.load(r.Key)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.controller.finish(latest, terminalStop(latest), "Execution terminated."); err != nil {
				t.Fatal(err)
			}
			requireNativeTerminal(t, s, r, native[name])
		})
	}
}
func TestPaginationRejectsForeignScopeAndFilter(t *testing.T) {
	scope := Scope{"aws", "111122223333", "us-east-1"}
	_, token, err := page(scope, "builds/project/DESCENDING", "", []string{"one", "two"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	foreign := scope
	foreign.AccountID = "444455556666"
	if _, _, err = page(foreign, "builds/project/DESCENDING", value(token), []string{"secret", "two"}, 1); err == nil {
		t.Fatal("foreign account token accepted")
	}
	if _, _, err = page(scope, "builds/other/DESCENDING", value(token), []string{"one", "two"}, 1); err == nil {
		t.Fatal("token changed project filter")
	}
}
func TestFleetAdmissionWaitsForNativeCleanup(t *testing.T) {
	s, previous := seededBuild(t)
	fleet := FleetKey{Scope: previous.Key.Scope, Name: "reserved"}
	fleetARN := fleet.ARN("00000000-0000-4000-8000-000000000001")
	previous.FleetARN = fleetARN
	previous.Deadline = s.clock.Now().Add(time.Minute)
	previous.Data.BuildComplete = new(api.Boolean(true))
	previous.CleanupPending = true
	queued := BuildRecord{
		Key:      BuildKey{Scope: previous.Key.Scope, ID: "project:queued"},
		FleetARN: fleetARN,
		Data: api.Build{
			ProjectName:      new(api.NonEmptyString("project")),
			CurrentPhase:     new(api.String("QUEUED")),
			TimeoutInMinutes: new(api.WrapperInt(5)),
			BuildComplete:    new(api.Boolean(false)),
		},
	}
	err := s.repository.Update(context.Background(), func(tx Transaction) error {
		if err := tx.PutFleet(FleetRecord{Key: fleet, Data: api.Fleet{
			Arn:              new(api.NonEmptyString(fleetARN)),
			Id:               new(api.NonEmptyString("00000000-0000-4000-8000-000000000001")),
			BaseCapacity:     new(api.FleetCapacity(1)),
			OverflowBehavior: new(api.FleetOverflowBehavior("QUEUE")),
			Status:           &api.FleetStatus{StatusCode: new(api.FleetStatusCode("ACTIVE"))},
		}}); err != nil {
			return err
		}
		if err := tx.PutBuild(previous); err != nil {
			return err
		}
		return tx.PutBuild(queued)
	})
	if err != nil {
		t.Fatal(err)
	}
	if admitted, err := s.controller.claim(queued.Key); err != nil || admitted {
		t.Fatalf("admitted before native slot release: admitted=%v error=%v", admitted, err)
	}
	previous.CleanupPending = false
	if err := s.repository.Update(context.Background(), func(tx Transaction) error { return tx.PutBuild(previous) }); err != nil {
		t.Fatal(err)
	}
	if admitted, err := s.controller.claim(queued.Key); err != nil || !admitted {
		t.Fatalf("did not admit after native slot release: admitted=%v error=%v", admitted, err)
	}
}
