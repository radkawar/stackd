package lambda

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

// A disconnected controller must not mistake its successor's resources for
// crash debris when its own deferred Close eventually runs. This uses native
// Docker stdin-close and flock behavior, not a simulated ownership receipt.
func TestDockerDisconnectedOwnerCannotSweepSuccessor(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for native ownership recovery")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	engine, err := docker.New(ctx, docker.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	config := DockerConfig{Client: engine, Namespace: "ownership-regression-" + rand.Text()}
	previous, err := NewDockerExecutor(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = previous.Close(cleanup)
	})
	if duplicate, err := NewDockerExecutor(ctx, config); err == nil {
		duplicate.Close(ctx)
		t.Fatal("second live controller acquired the same namespace")
	}
	previous.guard.Close()
	if err := engine.JSON(ctx, "POST", "/containers/"+previous.owner+"/wait?condition=not-running", nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-previous.lifetime.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	current, err := NewDockerExecutor(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := current.Close(cleanup); err != nil {
			t.Error(err)
		}
		var volumes struct{ Volumes []struct{ Name string } }
		if err := engine.JSON(cleanup, "GET", "/volumes?filters="+current.filters("lambda-owner"), nil, &volumes); err != nil {
			t.Error(err)
			return
		}
		if len(volumes.Volumes) != 0 {
			t.Errorf("unreferenced owner volumes survived Close: %+v", volumes.Volumes)
		}
	})
	volume := "stackd-lambda-successor-" + rand.Text()
	if err := engine.JSON(ctx, "POST", "/volumes/create", docker.VolumeConfig{Name: volume, Labels: current.labels(volume, "arn:aws:lambda:us-east-1:123456789012:function:successor")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := previous.Close(ctx); err == nil || !strings.Contains(err.Error(), "ownership was lost") {
		t.Fatalf("old owner Close = %v", err)
	}
	if err := engine.JSON(ctx, "GET", "/volumes/"+volume, nil, nil); err != nil {
		t.Fatalf("old owner deleted successor storage: %v", err)
	}
	// The successor acquired its native volume reference before predecessor
	// Close. Cleanup must not unlink that flock inode and admit a third owner.
	if duplicate, err := NewDockerExecutor(ctx, config); err == nil {
		duplicate.Close(ctx)
		t.Fatal("predecessor Close broke successor flock exclusivity")
	}
	if _, err := previous.Prepare(ctx, Specification{}); err == nil || !strings.Contains(err.Error(), "owner is closed") {
		t.Fatalf("old owner Prepare = %v", err)
	}
}
