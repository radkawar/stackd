package ecs

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const dockerImageDigestLabel = "stackd.ecs.image-digest"

type dockerImage struct {
	ID, Os, Architecture string
	RepoDigests          []string
	Digest               string `json:"-"`
}

type dockerContainer struct {
	id    string
	image dockerImage
}

func taskContainerName(taskARN, container string) string {
	return dockerResourceName("container", taskARN+"/"+container)
}

func (d *DockerExecutor) resolveImages(ctx context.Context, spec Specification) (map[string]dockerContainer, error) {
	resolved := make(map[string]dockerContainer, len(spec.Containers))
	byReference := make(map[string]dockerImage)
	for _, container := range spec.Containers {
		if container.Name == "" {
			return nil, fmt.Errorf("ECS execution container name is empty")
		}
		if _, exists := resolved[container.Name]; exists {
			return nil, fmt.Errorf("duplicate ECS execution container name %q", container.Name)
		}
		var existing dockerContainerInspection
		err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(taskContainerName(spec.TaskARN, container.Name))+"/json", nil, &existing)
		if err == nil {
			if err := existing.ownedBy(spec.TaskARN); err != nil {
				return nil, err
			}
			// A mutable local tag must not retarget a surviving task on recovery.
			resolved[container.Name] = dockerContainer{id: existing.ID, image: dockerImage{ID: existing.Image, Digest: existing.Config.Labels[dockerImageDigestLabel]}}
			continue
		}
		if !dockerNotFound(err) {
			return nil, fmt.Errorf("inspect retained ECS container %s: %w", container.Name, err)
		}
		image, found := byReference[container.Image]
		if !found {
			if err := d.client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(container.Image)+"/json", nil, &image); err != nil {
				return nil, fmt.Errorf("ECS container %s requires locally installed image %q: %w", container.Name, container.Image, err)
			}
			if image.Os != "linux" || image.Architecture != spec.Architecture {
				return nil, fmt.Errorf("ECS image %q is %s/%s, task requires linux/%s", container.Image, image.Os, image.Architecture, spec.Architecture)
			}
			for _, digest := range image.RepoDigests {
				if _, value, ok := strings.Cut(digest, "@"); ok {
					image.Digest = value
					break
				}
			}
			byReference[container.Image] = image
		}
		resolved[container.Name] = dockerContainer{image: image}
	}
	return resolved, nil
}
