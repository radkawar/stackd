package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"stackd/compute/docker"
)

func (d *Docker) statisticsManaged(ctx context.Context, spec Specification) (out Statistics, result error) {
	defer func() {
		if result != nil {
			result = d.managedFailure(ctx, spec, nil, result)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	m, err := d.observeManaged(ctx, spec)
	if err != nil {
		return out, err
	}
	return d.measureStatistics(ctx, m)
}
func (d *Docker) snapshotManaged(ctx context.Context, spec Specification, snapshotID string) (result error) {
	defer func() {
		if result != nil {
			result = d.managedFailure(ctx, spec, nil, result)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	m, err := d.observeManaged(ctx, spec)
	if err != nil {
		return err
	}
	return d.snapshotNative(ctx, m, func(script string) error {
		_, err := d.managedCopy(ctx, spec, snapshotID, false, script)
		return err
	})
}
func (d *Docker) restoreManaged(ctx context.Context, spec Specification, snapshotID string) (out Deployment, result error) {
	defer func() {
		if result != nil {
			result = d.managedFailure(ctx, spec, nil, result)
		}
	}()
	if snapshotID == "" || snapshotID == spec.ID {
		return out, errors.New("managed Valkey restore requires an independent snapshot incarnation")
	}
	if err := d.managedPrerequisites(spec); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if _, err := d.managedVolume(ctx, spec, "ownership", true); err != nil {
		return out, err
	}
	configuration, err := d.inspectNamed(ctx, d.name(spec.ID, "configuration"))
	if err == nil {
		if err = d.checkManagedContainer(configuration, spec, "configuration"); err != nil {
			return out, err
		}
		if _, err = d.readManifest(ctx, configuration, spec); err == nil {
			source, readErr := d.readFile(ctx, configuration.ID, "/data/restore-source")
			if readErr != nil {
				return out, readErr
			}
			if string(source) != snapshotID {
				return out, errors.New("managed Valkey restored snapshot incarnation differs from retained source")
			}
			return d.ensureManaged(ctx, spec)
		}
		if !dockerStatus(err, 404) {
			return out, err
		}
	} else if !dockerStatus(err, 404) {
		return out, err
	}
	if _, err = d.managedVolume(ctx, spec, "data", true); err != nil {
		return out, err
	}
	script := "if [ -f /target/restore-source ]; then test \"$(cat /target/restore-source)\" = \"$RESTORE_SOURCE\"; exit 0; fi\n" + restoreScript(spec) + "printf '%s' \"$RESTORE_SOURCE\" > /target/restore-source\nsync\n"
	if _, err = d.managedCopy(ctx, spec, snapshotID, true, script); err != nil {
		return out, fmt.Errorf("restore managed native Valkey data: %w", err)
	}
	return d.ensureManaged(ctx, spec)
}
func (d *Docker) managedCopy(ctx context.Context, spec Specification, snapshotID string, restore bool, script string) ([]byte, error) {
	if _, err := d.managedVolume(ctx, spec, "data", restore); err != nil {
		return nil, err
	}
	if _, err := d.volume(ctx, snapshotID, "snapshot", !restore); err != nil {
		return nil, err
	}
	source, target := d.name(spec.ID, "data"), d.name(snapshotID, "snapshot")
	if restore {
		source, target = target, source
	}
	c := docker.ContainerConfig{Image: d.image, Entrypoint: []string{"/bin/sh", "-eu", "-c"}, Cmd: []string{script}, Env: []string{"RESTORE_SOURCE=" + snapshotID}, Labels: d.managedLabels(spec, "copy-helper"), NetworkDisabled: true}
	c.User, c.WorkingDir = "0:0", "/"
	c.HostConfig.NetworkMode = "none"
	c.HostConfig.ReadonlyRootfs = true
	c.HostConfig.CapDrop = []string{"ALL"}
	// Restore seeds owned files as root, then explicitly chowns them to the
	// unprivileged server. No host paths or networking are granted to the helper.
	c.HostConfig.CapAdd = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"}
	c.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	c.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "json-file"}
	c.HostConfig.PidsLimit = 32
	c.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: source, Target: "/source", ReadOnly: true, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}, {Type: "volume", Source: target, Target: "/target", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
	return d.runManagedHelper(ctx, spec, "copy-helper", c)
}
func (d *Docker) checkManagedHelper(s containerState, spec Specification, role string, expected docker.ContainerConfig) error {
	if err := d.checkManagedOwner(s.Config.Labels, spec, role); err != nil {
		return err
	}
	image := d.image
	if expected.Image == docker.ToolkitImage {
		image = d.toolkitImage
	}
	if s.ID == "" || image == "" || s.Image != image || s.Config.Image != expected.Image || s.Config.User != expected.User || !slices.Equal(s.Config.Entrypoint, expected.Entrypoint) || !slices.Equal(s.Config.Cmd, expected.Cmd) || !d.equalImageEnvironment(s.Config.Env, expected.Env, expected.Image == docker.ToolkitImage) || s.HostConfig.NetworkMode != expected.HostConfig.NetworkMode || s.HostConfig.Privileged || len(s.HostConfig.Binds) != 0 || !sameMounts(s.HostConfig.Mounts, expected.HostConfig.Mounts) || !s.HostConfig.ReadonlyRootfs || len(s.HostConfig.PortBindings) != 0 || s.HostConfig.PublishAllPorts || !slices.Equal(s.HostConfig.CapAdd, expected.HostConfig.CapAdd) || !slices.Equal(s.HostConfig.CapDrop, expected.HostConfig.CapDrop) || !slices.Equal(s.HostConfig.SecurityOpt, expected.HostConfig.SecurityOpt) {
		return errors.New("managed Valkey helper has conflicting purpose, image or native configuration")
	}
	if s.Config.WorkingDir != expected.WorkingDir || s.Config.Labels[labelPrefix+"helper-config"] != expected.Labels[labelPrefix+"helper-config"] || s.HostConfig.Memory != expected.HostConfig.Memory || s.HostConfig.MemorySwap != expected.HostConfig.MemorySwap || s.HostConfig.PidsLimit != expected.HostConfig.PidsLimit || len(s.HostConfig.ExtraHosts) != 0 || len(s.HostConfig.DNS) != 0 || len(s.HostConfig.DNSSearch) != 0 {
		return errors.New("managed Valkey helper durable configuration differs")
	}
	return nil
}
func environmentMap(entries []string) map[string]string {
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	return values
}
func (d *Docker) equalImageEnvironment(actual, supplied []string, toolkit bool) bool {
	base := d.imageEnv
	if toolkit {
		base = d.toolkitEnv
	}
	want := environmentMap(base)
	for _, entry := range supplied {
		key, value, _ := strings.Cut(entry, "=")
		want[key] = value
	}
	return maps.Equal(environmentMap(actual), want)
}
func (d *Docker) retainedManagedHelpers(ctx context.Context, spec Specification) ([]containerState, error) {
	labels := d.managedLabels(spec, "copy-helper")
	delete(labels, labelPrefix+"role")
	filter := make([]string, 0, len(labels))
	for key, value := range labels {
		filter = append(filter, key+"="+value)
	}
	encoded, err := json.Marshal(map[string][]string{"label": filter})
	if err != nil {
		return nil, err
	}
	var listed []struct {
		ID string `json:"Id"`
	}
	if err = d.client.JSON(ctx, "GET", "/containers/json?all=true&filters="+url.QueryEscape(string(encoded)), nil, &listed); err != nil {
		return nil, err
	}
	var helpers []containerState
	for _, candidate := range listed {
		if candidate.ID == "" {
			return nil, errors.New("managed Valkey discovered resource has no container identity")
		}
		s, err := d.inspectNamed(ctx, candidate.ID)
		if err != nil {
			return nil, err
		}
		role := s.Config.Labels[labelPrefix+"role"]
		if err = d.checkManagedOwner(s.Config.Labels, spec, role); err != nil {
			return nil, err
		}
		if s.ID != candidate.ID {
			return nil, errors.New("managed Valkey discovered resource identity differs")
		}
		if role == "configuration" || strings.HasPrefix(role, "node-") {
			if role != "configuration" {
				n, err := strconv.Atoi(strings.TrimPrefix(role, "node-"))
				if err != nil || n < 1 || n > len(spec.Networks) {
					return nil, errors.New("managed Valkey discovered node index differs")
				}
			}
			if err = d.checkManagedContainer(s, spec, role); err != nil {
				return nil, err
			}
			named, err := d.inspectNamed(ctx, d.name(spec.ID, role))
			if err != nil || named.ID != s.ID {
				return nil, errors.New("managed Valkey discovered node is not its exact immutable native name")
			}
			continue // deterministic nodes were separately preflighted
		}
		if s.HostConfig.Privileged || len(s.HostConfig.Binds) != 0 || len(s.HostConfig.PortBindings) != 0 || s.HostConfig.PublishAllPorts || !s.HostConfig.ReadonlyRootfs {
			return nil, errors.New("managed Valkey discovered helper has unexpected host access")
		}
		raw := s.Config.Labels[labelPrefix+"helper-config"]
		var expected docker.ContainerConfig
		if err = json.Unmarshal([]byte(raw), &expected); err != nil {
			return nil, err
		}
		if err = d.checkManagedOwner(expected.Labels, spec, role); err != nil {
			return nil, err
		}
		expected.Labels[labelPrefix+"helper-config"] = raw
		if err = d.checkManagedHelper(s, spec, role, expected); err != nil {
			return nil, err
		}
		if role == "copy-helper" {
			if s.Image != d.image || s.Config.Image != d.image || s.HostConfig.NetworkMode != "none" || len(s.HostConfig.Mounts) != 2 {
				return nil, errors.New("managed Valkey copy helper has conflicting native purpose")
			}
			dataOwned, snapshotOwned := false, false
			for _, mount := range s.HostConfig.Mounts {
				if mount.Type != "volume" || (mount.Target != "/source" && mount.Target != "/target") || mount.ReadOnly != (mount.Target == "/source") {
					return nil, errors.New("managed Valkey copy helper has a foreign mount")
				}
				if mount.Source == d.name(spec.ID, "data") {
					dataOwned = true
					continue
				}
				// The snapshot incarnation is retained as non-secret helper env.
				snapshotID := environmentMap(s.Config.Env)["RESTORE_SOURCE"]
				if snapshotID == "" || mount.Source != d.name(snapshotID, "snapshot") {
					return nil, errors.New("managed Valkey copy helper snapshot ownership differs")
				}
				if _, err = d.volume(ctx, snapshotID, "snapshot", false); err != nil {
					return nil, err
				}
				snapshotOwned = true
			}
			if !dataOwned || !snapshotOwned {
				return nil, errors.New("managed Valkey copy helper lost exact source/destination ownership")
			}
		} else if strings.HasPrefix(role, "network-helper-") {
			node, err := strconv.Atoi(strings.TrimPrefix(role, "network-helper-"))
			if err != nil || node < 1 || node > len(spec.Networks) || s.Image != d.toolkitImage || s.Config.Image != docker.ToolkitImage || len(s.HostConfig.Mounts) != 0 {
				return nil, errors.New("managed Valkey network helper has conflicting native purpose")
			}
			mode := s.Config.Labels[labelPrefix+"target"]
			if mode != s.HostConfig.NetworkMode || (mode != "host" && (!strings.HasPrefix(mode, "container:") || strings.TrimPrefix(mode, "container:") == "")) {
				return nil, errors.New("managed Valkey network helper namespace identity differs")
			}
			if mode != "host" {
				n, err := d.inspectNamed(ctx, d.name(spec.ID, nodeRole(node-1)))
				if err != nil && !dockerStatus(err, 404) {
					return nil, err
				}
				if err == nil {
					if err = d.checkManagedContainer(n, spec, nodeRole(node-1)); err != nil {
						return nil, err
					}
					if mode != "container:"+n.ID {
						return nil, errors.New("managed Valkey network helper targets a foreign namespace")
					}
				}
			}
		} else {
			return nil, errors.New("managed Valkey discovered helper has an unknown role")
		}
		helpers = append(helpers, s)
	}
	return helpers, nil
}
