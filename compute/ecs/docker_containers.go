package ecs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
)

type dockerContainerInspection struct {
	ID      string `json:"Id"`
	Image   string
	Name    string
	Created time.Time
	Config  struct {
		Labels map[string]string
		Env    []string
	}
	HostConfig struct{ CPUShares, Memory int64 }
	State      struct {
		Status                                       string
		Running, Paused, Restarting, Dead, OOMKilled bool
		ExitCode                                     int
		Error                                        string
		StartedAt, FinishedAt                        time.Time
		Health                                       *struct{ Status string }
	}
}

func (state *dockerContainerInspection) ownedBy(taskARN string) error {
	if state.Config.Labels[dockerTaskLabel] != taskARN || state.Config.Labels[dockerRoleLabel] != "container" {
		return fmt.Errorf("native Docker container %s is not an execution container of task %s", state.ID, taskARN)
	}
	return nil
}

func (e *dockerEnvironment) prepareContainers(ctx context.Context) error {
	for _, spec := range e.spec.Containers {
		name := taskContainerName(e.spec.TaskARN, spec.Name)
		container := e.containers[spec.Name]
		if container.id != "" {
			continue
		}
		image := container.image
		config := docker.ContainerConfig{
			Image: image.ID, Entrypoint: spec.Entrypoint, Cmd: spec.Command, Env: spec.Environment,
			WorkingDir: spec.WorkingDirectory, User: spec.User,
			Labels: map[string]string{dockerTaskLabel: e.spec.TaskARN, dockerRoleLabel: "container", "stackd.ecs.container": spec.Name, dockerImageDigestLabel: image.Digest},
			// ECS does not adopt a HEALTHCHECK baked into the image. Only the
			// task definition's health check contributes to task health.
			Healthcheck: &docker.ContainerHealthConfig{Test: []string{"NONE"}},
			HostConfig: docker.ContainerHostConfig{
				NetworkMode: "container:" + e.metadata.containerID(), CgroupParent: e.group,
				ReadonlyRootfs: spec.ReadonlyRootFilesystem,
				Memory:         spec.MemoryBytes, MemorySwap: spec.MemoryBytes, MemoryReservation: spec.MemoryReservationBytes,
				CPUShares: spec.CPUShares,
				LogConfig: docker.ContainerLogConfig{Type: "json-file"},
			},
		}
		if spec.ResolveEnvironment != nil {
			environment, err := spec.ResolveEnvironment(ctx)
			if err != nil {
				return fmt.Errorf("resolve ECS container %s environment: %w", spec.Name, err)
			}
			config.Env = environment
		}
		if check := spec.HealthCheck; check != nil {
			config.Healthcheck = &docker.ContainerHealthConfig{Test: check.Command, Interval: int64(check.Interval), Timeout: int64(check.Timeout), StartPeriod: int64(check.StartPeriod), Retries: check.Retries}
		}
		for _, mount := range spec.Mounts {
			if !slices.Contains(e.spec.Volumes, mount.Volume) {
				return fmt.Errorf("ECS container %s mounts undeclared task volume %q", spec.Name, mount.Volume)
			}
			config.HostConfig.Mounts = append(config.HostConfig.Mounts, docker.ContainerMount{
				Type: "volume", Source: taskVolumeName(e.spec.TaskARN, mount.Volume), Target: mount.Path, ReadOnly: mount.ReadOnly,
				VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true},
			})
		}
		trust, err := e.executor.networking.PrepareTrust(&config, image.Config.Env, "")
		if err != nil {
			return fmt.Errorf("prepare ECS container %s trust: %w", spec.Name, err)
		}
		var created struct {
			ID string `json:"Id"`
		}
		if err := e.executor.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), config, &created); err != nil {
			return fmt.Errorf("create ECS container %s: %w", spec.Name, err)
		}
		// A never-started container without its bundle is removed, not adopted.
		if err := trust.Install(ctx, e.executor.client, created.ID); err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			return errors.Join(fmt.Errorf("install ECS container %s trust: %w", spec.Name, err), e.executor.client.RemoveContainer(cleanup, created.ID))
		}
		container.id = created.ID
		e.containers[spec.Name] = container
	}
	return nil
}

func (e *dockerEnvironment) Inspect(ctx context.Context) ([]ContainerStatus, error) {
	result := make([]ContainerStatus, 0, len(e.spec.Containers))
	for _, spec := range e.spec.Containers {
		container := e.containers[spec.Name]
		var observed dockerContainerInspection
		if err := e.executor.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(container.id)+"/json", nil, &observed); err != nil {
			return nil, fmt.Errorf("inspect ECS container %s: %w", spec.Name, err)
		}
		state := observed.State
		status := ContainerStatus{
			Name: spec.Name, RuntimeID: observed.ID, ImageDigest: container.image.Digest,
			DockerName: strings.TrimPrefix(observed.Name, "/"), ImageID: observed.Image, CreatedAt: observed.Created,
			Labels: observed.Config.Labels, CPUShares: observed.HostConfig.CPUShares, MemoryBytes: observed.HostConfig.Memory,
			Health: HealthUnknown, StartedAt: state.StartedAt, FinishedAt: state.FinishedAt,
			Error: state.Error, OOMKilled: state.OOMKilled,
		}
		switch state.Status {
		case "created":
			status.State = ContainerCreated
		case "running":
			status.State = ContainerRunning
		case "exited", "dead":
			status.State = ContainerExited
			if !state.StartedAt.IsZero() {
				status.ExitCode = new(state.ExitCode)
			}
		default:
			return nil, fmt.Errorf("ECS container %s has unexpected native state %q", spec.Name, state.Status)
		}
		if spec.HealthCheck != nil && state.Health != nil {
			switch state.Health.Status {
			case "healthy":
				status.Health = HealthHealthy
			case "unhealthy":
				status.Health = HealthUnhealthy
			}
		}
		result = append(result, status)
	}
	return result, nil
}

func (e *dockerEnvironment) Start(ctx context.Context, name string) error {
	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	if !e.policyReady {
		return errors.New("ECS customer start requires an installed native network policy")
	}
	container, ok := e.containers[name]
	if !ok {
		return fmt.Errorf("unknown ECS execution container %q", name)
	}
	err := e.executor.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(container.id)+"/start", nil, nil)
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotModified {
		return nil
	}
	return err
}

func (e *dockerEnvironment) Stop(ctx context.Context, name string, timeout time.Duration) error {
	container, ok := e.containers[name]
	if !ok {
		return fmt.Errorf("unknown ECS execution container %q", name)
	}
	seconds := int64(timeout / time.Second)
	if timeout%time.Second != 0 {
		seconds++
	}
	err := e.executor.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(container.id)+"/stop?t="+strconv.FormatInt(seconds, 10), nil, nil)
	var remote *docker.Error
	if errors.As(err, &remote) && (remote.StatusCode == http.StatusNotModified || remote.StatusCode == http.StatusNotFound) {
		return nil
	}
	return err
}
