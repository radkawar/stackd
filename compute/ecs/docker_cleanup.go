package ecs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"stackd/compute/docker"
	"stackd/compute/network"
)

func dockerLabelFilter(key, value string) string {
	body, _ := json.Marshal(map[string][]string{"label": {key + "=" + value}})
	return url.QueryEscape(string(body))
}

// Remove uses native ownership queries even when preparation failed before an
// Environment could be returned. Customer removal is the process-lifetime
// boundary; their namespace, volumes and task slice must remain until it succeeds.
func (d *DockerExecutor) Remove(ctx context.Context, spec Specification) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if spec.TaskARN == "" {
		return errors.New("ECS backend removal requires a task ARN")
	}
	var containers []struct {
		ID              string `json:"Id"`
		Labels          map[string]string
		NetworkSettings struct{ Networks map[string]json.RawMessage }
	}
	if err := d.client.JSON(ctx, http.MethodGet, "/containers/json?all=true&filters="+dockerLabelFilter(dockerTaskLabel, spec.TaskARN), nil, &containers); err != nil {
		return fmt.Errorf("discover ECS task containers for removal: %w", err)
	}
	networkID := spec.Network.NetworkID
	if networkID == "" {
		// Retained anchors own the native network attachment even when current
		// EC2 policy or metadata readiness prevents execution reattachment.
		for _, container := range containers {
			if container.Labels[metadataHostLabel] == "" {
				continue
			}
			for name := range container.NetworkSettings.Networks {
				var attachedNetwork struct{ Labels map[string]string }
				err := d.client.JSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, &attachedNetwork)
				if dockerNotFound(err) {
					continue
				}
				if err != nil {
					return fmt.Errorf("resolve retained ECS network: %w", err)
				}
				if owned := attachedNetwork.Labels[network.BridgeLabel]; owned != "" {
					networkID = owned
					break
				}
			}
		}
	}
	// The namespace anchor is deliberately last, including partial preparation.
	for _, container := range containers {
		if container.Labels[metadataHostLabel] != "" {
			continue
		}
		if err := d.client.RemoveContainer(ctx, container.ID); err != nil {
			return fmt.Errorf("remove ECS customer container %s: %w", container.ID, err)
		}
	}
	if existing := d.tasks[spec.TaskARN]; existing != nil {
		existing.cancel()
		if err := existing.metadata.close(); err != nil {
			return fmt.Errorf("close ECS metadata listener: %w", err)
		}
		delete(d.tasks, spec.TaskARN)
	}
	if err := d.removeNetworkPolicy(ctx, spec.TaskARN); err != nil {
		return err
	}
	for _, container := range containers {
		if container.Labels[metadataHostLabel] == "" {
			continue
		}
		if err := d.client.RemoveContainer(ctx, container.ID); err != nil {
			return fmt.Errorf("remove ECS namespace anchor %s: %w", container.ID, err)
		}
	}
	group := dockerTaskSliceName(spec.TaskARN)
	var helpers []struct {
		ID string `json:"Id"`
	}
	if err := d.client.JSON(ctx, http.MethodGet, "/containers/json?all=true&filters="+dockerLabelFilter("stackd.compute.unit", group), nil, &helpers); err != nil {
		return fmt.Errorf("discover retained ECS limit helpers: %w", err)
	}
	for _, helper := range helpers {
		if err := d.client.RemoveContainer(ctx, helper.ID); err != nil {
			return fmt.Errorf("remove retained ECS limit helper: %w", err)
		}
	}
	if err := removeTaskGroup(ctx, d.client, group, docker.ToolkitImage); err != nil {
		return err
	}
	var volumes struct {
		Volumes []struct{ Name string }
	}
	if err := d.client.JSON(ctx, http.MethodGet, "/volumes?filters="+dockerLabelFilter(dockerTaskLabel, spec.TaskARN), nil, &volumes); err != nil {
		return fmt.Errorf("discover ECS task volumes: %w", err)
	}
	for _, volume := range volumes.Volumes {
		err := d.client.JSON(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(volume.Name), nil, nil)
		if err != nil && !dockerNotFound(err) {
			return fmt.Errorf("remove ECS task volume %s: %w", volume.Name, err)
		}
	}
	if networkID == "" {
		return nil
	}
	return d.networks.Release(ctx, networkID)
}
