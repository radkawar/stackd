package lambda

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"stackd/compute/docker"
)

// Docker completed two creates after their callers timed out during the native
// runtime checks on 2026-09-22. Cleanup had considered the containers removed,
// but later volume removals returned 409 because those containers held the mounts.
func TestDockerCleanupRetriesLateCreate(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for actual container cleanup")
	}
	engine, err := docker.New(t.Context(), docker.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	name := "stackd-lambda-cleanup-" + rand.Text()
	keeper, volume := name+"-code", name+"-volume"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, container := range []string{name, keeper} {
			if err := engine.RemoveContainer(ctx, container); err != nil {
				t.Error(err)
			}
		}
		err := engine.JSON(ctx, "DELETE", "/volumes/"+volume, nil, nil)
		var remote *docker.Error
		if err != nil && !(errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound) {
			t.Error(err)
		}
	})
	labels := map[string]string{"io.stackd.owner": name, "io.stackd.kind": "lambda-cleanup-regression"}
	if err := engine.JSON(t.Context(), "POST", "/volumes/create", docker.VolumeConfig{Name: volume, Labels: labels}, nil); err != nil {
		t.Fatal(err)
	}
	for _, container := range []string{name, keeper} {
		config := docker.ContainerConfig{Image: ProvidedAL2023X8664Image, Labels: labels, HostConfig: docker.ContainerHostConfig{NetworkMode: "none", Mounts: []docker.ContainerMount{{Type: "volume", Source: volume, Target: "/tmp", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}}}
		if err := engine.JSON(t.Context(), "POST", "/containers/create?name="+container, config, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Recreate the observed recovery state: a previous close saw absence before
	// native create completed. No customer process or telemetry owner has run.
	lifetime, stop := context.WithCancel(t.Context())
	defer stop()
	environment := &dockerEnvironment{engine: engine, container: name, staging: keeper, volume: volume, containerRemoved: true, stagingRemoved: true, lifetime: lifetime, stop: stop, done: make(chan struct{})}
	if err := environment.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/containers/" + name + "/json", "/containers/" + keeper + "/json", "/volumes/" + volume} {
		err := engine.JSON(t.Context(), "GET", path, nil, nil)
		var remote *docker.Error
		if !errors.As(err, &remote) || remote.StatusCode != http.StatusNotFound {
			t.Fatalf("owned resource remains after cleanup at %s: %v", path, err)
		}
	}
}
