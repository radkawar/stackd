package ecs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
)

type dockerTaskLimits struct {
	CPUUnits, MemoryBytes int64
}

const (
	dockerTaskSlicePrefix       = "stackdecs"
	dockerTaskDescriptionPrefix = "stackd ECS task "
)

func dockerTaskSliceName(taskARN string) string {
	// No hyphens: systemd otherwise creates implicit intermediate slices that
	// are not owned by this task. Hash the full immutable ARN, not its display ID.
	return fmt.Sprintf("%s%x.slice", dockerTaskSlicePrefix, sha256.Sum256([]byte(taskARN)))
}

// prepareTaskGroup owns a native transient systemd slice. Admission has already
// validated the positive AWS limits. Quota is an aggregate CFS CPU ceiling, not
// a claim of Fargate CPU-share equivalence; MemoryMax does not cap aggregate swap.
// Calls for a task must be serialized with removal and container creation.
// The name is returned even on error so the caller can remove a unit whose
// creation may have committed before a transport failure or cancellation.
func prepareTaskGroup(ctx context.Context, client *docker.Client, taskARN string, limits dockerTaskLimits, helperImage string) (string, error) {
	name := dockerTaskSliceName(taskARN)
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	unit, err := docker.InspectUnit(ctx, client, name, helperImage)
	if err != nil {
		return name, err
	}
	// systemd expresses quota as CPU microseconds per second, and separately
	// sets the actual scheduling period to 100ms (1024 units = one CPU).
	properties := []string{
		"CPUQuotaPerSecUSec", "t", strconv.FormatInt(limits.CPUUnits*1_000_000/1024, 10),
		"CPUQuotaPeriodUSec", "t", "100000",
		"MemoryMax", "t", strconv.FormatInt(limits.MemoryBytes, 10),
	}
	if unit == nil {
		args := []string{"StartTransientUnit", "ssa(sv)a(sa(sv))", name, "fail", "4", "Description", "s", dockerTaskDescriptionPrefix + taskARN}
		args = append(args, properties...)
		args = append(args, "0")
		_, err = docker.SystemdCall(ctx, client, name, helperImage, args...)
	} else {
		if err = ownedDockerTaskSlice(unit, name); err != nil {
			return name, err
		}
		args := append([]string{"SetUnitProperties", "sba(sv)", name, "true", "3"}, properties...)
		_, err = docker.SystemdCall(ctx, client, name, helperImage, args...)
		if err == nil && unit.Active != "active" && unit.Active != "activating" {
			_, err = docker.SystemdCall(ctx, client, name, helperImage, "StartUnit", "ss", name, "fail")
		}
	}
	if err != nil {
		return name, fmt.Errorf("prepare ECS task slice %s: %w", name, err)
	}
	return name, docker.WaitUnit(ctx, client, name, helperImage, true, func(unit *docker.Unit) error { return ownedDockerTaskSlice(unit, name) })
}

// removeTaskGroup must run only after all child containers have been removed.
// It stops exactly the owned slice; it never stops a parent or enumerates tasks.
func removeTaskGroup(ctx context.Context, client *docker.Client, sliceName, helperImage string) error {
	if len(sliceName) != len(dockerTaskSlicePrefix)+64+len(".slice") || !strings.HasPrefix(sliceName, dockerTaskSlicePrefix) || !strings.HasSuffix(sliceName, ".slice") {
		return fmt.Errorf("refusing to remove non-task systemd slice %q", sliceName)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return docker.StopUnit(ctx, client, sliceName, helperImage, func(unit *docker.Unit) error { return ownedDockerTaskSlice(unit, sliceName) })
}

func ownedDockerTaskSlice(unit *docker.Unit, name string) error {
	arn, ok := strings.CutPrefix(unit.Description, dockerTaskDescriptionPrefix)
	if !ok || dockerTaskSliceName(arn) != name {
		return fmt.Errorf("refusing to modify systemd slice %s: native Description does not identify its ECS task owner", name)
	}
	return nil
}
