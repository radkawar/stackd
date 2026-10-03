package ecs

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Processes deliberately does not call Prepare: a missing image or unusable
// metadata anchor cannot prevent termination of already owned native processes.
func (d *DockerExecutor) Processes(ctx context.Context, spec Specification) (TaskProcesses, error) {
	bound := &dockerEnvironment{executor: d, spec: Specification{TaskARN: spec.TaskARN}, containers: make(map[string]dockerContainer, len(spec.Containers)), lifetime: ctx}
	for _, container := range spec.Containers {
		var observed dockerContainerInspection
		err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(taskContainerName(spec.TaskARN, container.Name))+"/json", nil, &observed)
		if dockerNotFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("attach retained ECS process %s: %w", container.Name, err)
		}
		if err := observed.ownedBy(spec.TaskARN); err != nil {
			return nil, err
		}
		bound.spec.Containers = append(bound.spec.Containers, container)
		bound.containers[container.Name] = dockerContainer{id: observed.ID, image: dockerImage{ID: observed.Image, Digest: observed.Config.Labels[dockerImageDigestLabel]}}
	}
	return bound, nil
}
