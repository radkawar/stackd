package codebuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

// This opt-in test exercises actual Engine capacity and customer commands. It
// requires an explicitly pinned local Linux amd64 image with /bin/sh and sleep.
func TestDockerFleetCapacityRecoveryIsolation(t *testing.T) {
	image := os.Getenv("STACKD_CODEBUILD_FLEET_TEST_IMAGE")
	if image == "" {
		t.Skip("set STACKD_CODEBUILD_FLEET_TEST_IMAGE to a pinned preinstalled build image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := docker.New(ctx, docker.Config{Host: os.Getenv("STACKD_CODEBUILD_FLEET_TEST_DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	namespace := fmt.Sprintf("fleet-test-%d", time.Now().UnixNano())
	config := DockerConfig{Namespace: namespace, FleetImage: image}
	executor, err := NewDockerExecutor(client, config)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewDockerExecutor(client, DockerConfig{Namespace: namespace + "-other", FleetImage: image})
	if err != nil {
		t.Fatal(err)
	}
	fleetARN := "arn:aws:codebuild:us-east-1:123456789012:fleet/reserved-test:11111111-2222-3333-4444-555555555555"
	buildARN := "arn:aws:codebuild:us-east-1:123456789012:build/reserved-test:first"
	secondARN := "arn:aws:codebuild:us-east-1:123456789012:build/reserved-test:second"
	fleet := FleetSpecification{ARN: fleetARN, Capacity: 1, EnvironmentType: "LINUX_CONTAINER", ComputeType: "BUILD_GENERAL1_SMALL"}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		for _, runtime := range []*DockerExecutor{executor, other} {
			for _, arn := range []string{buildARN, secondARN} {
				if err := runtime.Remove(cleanup, arn); err != nil {
					t.Errorf("cleaning owned fleet build: %v", err)
				}
			}
			if err := runtime.ReleaseFleet(cleanup, fleetARN); err != nil {
				t.Errorf("cleaning owned fleet reservation: %v", err)
			}
		}
	})
	for _, environment := range []string{"MAC_ARM", "ARM_CONTAINER", "WINDOWS_SERVER_2022_CONTAINER"} {
		unsupported := fleet
		unsupported.EnvironmentType = environment
		if _, err := executor.ReserveFleet(ctx, unsupported); err == nil {
			t.Fatalf("unsupported environment %s allocated fleet capacity", environment)
		}
	}
	unsupported := fleet
	unsupported.Image = "ami-0123456789abcdef0"
	if _, err := executor.ReserveFleet(ctx, unsupported); err == nil {
		t.Fatal("custom AMI allocated container fleet capacity")
	}
	status, err := executor.ReserveFleet(ctx, fleet)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "ACTIVE" || status.Capacity != 1 || status.Ready != 1 || status.InUse != 0 {
		t.Fatalf("initial native capacity: %+v", status)
	}
	slots, err := executor.fleetSlots(ctx, fleetARN)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 1 || slots[0].idle.ID == "" || slots[0].idle.State != "running" || slots[0].build.ID != "" {
		t.Fatalf("ACTIVE did not hold one running native reservation: %+v", slots)
	}
	if _, err := other.ReserveFleet(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	spec := Specification{
		ARN: buildARN, FleetARN: fleetARN, Image: image,
		Buildspec: "version: 0.2\nphases:\n  build:\n    commands:\n      - printf fleet-reservation-bytes > result.txt\n      - echo fleet-command-running\n      - sleep 300\nartifacts:\n  files:\n    - result.txt\n",
	}
	build, err := executor.Prepare(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := build.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFleetLog(t, ctx, build, "fleet-command-running")
	status, err = executor.InspectFleet(ctx, fleetARN)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "ACTIVE" || status.Ready != 0 || status.InUse != 1 {
		t.Fatalf("build did not consume native capacity: %+v", status)
	}
	slots, err = executor.fleetSlots(ctx, fleetARN)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 1 || slots[0].idle.State == "running" || slots[0].build.State != "running" {
		t.Fatalf("idle capacity was not transferred to the real build: %+v", slots)
	}
	spec.ARN = secondARN
	if _, err := executor.Prepare(ctx, spec); !errors.Is(err, ErrFleetCapacity) {
		t.Fatalf("saturated fleet admitted another build: %v", err)
	}
	if err := executor.ReleaseFleet(ctx, fleetARN); !errors.Is(err, ErrFleetBusy) {
		t.Fatalf("fleet release did not protect the active build: %v", err)
	}
	if err := build.Close(); err != nil {
		t.Fatal(err)
	}
	client.Close() // Detach transport without terminating its native resources.
	reopened, err := NewDockerExecutor(client, config)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := reopened.Open(ctx, buildARN)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := retained.Inspect(ctx)
	if err != nil || observed.State != "running" {
		t.Fatalf("reopen lost running fleet build: %+v, %v", observed, err)
	}
	files, err := retained.Files(ctx, "artifacts")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "result.txt" || string(files[0].Body) != "fleet-reservation-bytes" {
		t.Fatalf("real fleet command output differs: %+v", files)
	}
	if err := retained.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	observed, err = retained.Inspect(ctx)
	if err != nil || observed.State != "exited" {
		t.Fatalf("fleet cancellation did not stop its process: %+v, %v", observed, err)
	}
	if err := reopened.ReleaseFleet(ctx, fleetARN); !errors.Is(err, ErrFleetBusy) {
		t.Fatalf("completed unpublished build lost its reservation: %v", err)
	}
	if err := reopened.Remove(ctx, buildARN); err != nil {
		t.Fatal(err)
	}
	status, err = reopened.InspectFleet(ctx, fleetARN)
	if err != nil || status.Ready != 1 || status.InUse != 0 || status.State != "ACTIVE" {
		t.Fatalf("removal did not restore native reservation: %+v, %v", status, err)
	}
	// A fresh workspace must not contain bytes left by the preceding slot user.
	spec.Buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - test ! -e result.txt\n      - echo isolated-slot-workspace\n"
	next, err := reopened.Prepare(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFleetLog(t, ctx, next, "isolated-slot-workspace")
	if err := reopened.Remove(ctx, secondARN); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ReleaseFleet(ctx, fleetARN); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.InspectFleet(ctx, fleetARN); !errors.Is(err, ErrFleetNotFound) {
		t.Fatalf("deleted fleet retained native resources: %v", err)
	}
	status, err = other.InspectFleet(ctx, fleetARN)
	if err != nil || status.Ready != 1 || status.State != "ACTIVE" {
		t.Fatalf("deletion changed another stack's fleet: %+v, %v", status, err)
	}
	if err := other.ReleaseFleet(ctx, fleetARN); err != nil {
		t.Fatal(err)
	}
	if _, err := other.InspectFleet(ctx, fleetARN); !errors.Is(err, ErrFleetNotFound) {
		t.Fatalf("other namespace cleanup retained resources: %v", err)
	}
}

func waitFleetLog(t *testing.T, ctx context.Context, execution Execution, text string) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		logs, _, err := execution.Logs(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(logs), text) {
			return
		}
		state, err := execution.Inspect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state.State == "exited" {
			t.Fatalf("build exited %d before expected command output %q: %s", state.ExitCode, text, logs)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for real fleet command output: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
