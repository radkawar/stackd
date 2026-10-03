package ecs

import (
	"context"
	"fmt"
	"net/http"

	"stackd/compute/docker"
)

func taskVolumeName(taskARN, volume string) string {
	return dockerResourceName("volume", taskARN+"/"+volume)
}

func (e *dockerEnvironment) prepareVolumes(ctx context.Context) error {
	for _, volume := range e.spec.Volumes {
		name := taskVolumeName(e.spec.TaskARN, volume)
		var result struct {
			Name   string
			Labels map[string]string
		}
		input := docker.VolumeConfig{Name: name, Labels: map[string]string{dockerTaskLabel: e.spec.TaskARN, "stackd.ecs.volume": volume}}
		if err := e.executor.client.JSON(ctx, http.MethodPost, "/volumes/create", input, &result); err != nil {
			return fmt.Errorf("prepare ECS volume %s: %w", volume, err)
		}
		// Native create returns an existing named volume without changing its
		// labels. Its returned ownership, not our submitted labels, is decisive.
		if result.Labels[dockerTaskLabel] != e.spec.TaskARN {
			return fmt.Errorf("native Docker volume %s is not owned by task %s", name, e.spec.TaskARN)
		}
	}
	return nil
}
