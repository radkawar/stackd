package codebuild

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"stackd/compute/docker"
)

var (
	ErrFleetNotFound = errors.New("CodeBuild fleet capacity does not exist")
	ErrFleetCapacity = errors.New("CodeBuild fleet has no available build slot")
	ErrFleetBusy     = errors.New("CodeBuild fleet still has admitted builds")
)

// FleetExecutor reserves local container capacity, not EC2 instances. Close of
// an execution or its transport detaches; only ReleaseFleet removes idle slots.
type FleetExecutor interface {
	ReserveFleet(context.Context, FleetSpecification) (FleetStatus, error)
	InspectFleet(context.Context, string) (FleetStatus, error)
	ReleaseFleet(context.Context, string) error
}

type FleetSpecification struct {
	ARN, Image, EnvironmentType, ComputeType string
	Capacity                                 int32
}

// Ready counts running idle reservations; InUse includes created and completed
// build containers until their output has been consumed and Remove is called.
type FleetStatus struct {
	State                  string
	Capacity, Ready, InUse int32
}

const (
	fleetLabel            = "stackd.codebuild.fleet"
	fleetSlotLabel        = "stackd.codebuild.fleet.slot"
	fleetReservationLabel = "stackd.codebuild.fleet.reservation"
	fleetCapacityLabel    = "stackd.codebuild.fleet.capacity"
	fleetComputeLabel     = "stackd.codebuild.fleet.compute"
	fleetEnvironmentLabel = "stackd.codebuild.fleet.environment"
	fleetImageLabel       = "stackd.codebuild.fleet.image"
	fleetNamespaceLabel   = "stackd.codebuild.namespace"
	fleetARNLabel         = "stackd.codebuild.arn"
)

type fleetContainer struct {
	ID     string
	Names  []string
	Labels map[string]string
	State  string
}

type fleetSlot struct {
	index int
	idle  fleetContainer
	build fleetContainer
}

// Predefined Linux compute budgets follow the CodeBuild compute-types table:
// https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-compute-types.html
func fleetLimits(compute string) (memory, cpu int64, err error) {
	switch compute {
	case "BUILD_GENERAL1_SMALL":
		return 4 << 30, 200000, nil
	case "BUILD_GENERAL1_MEDIUM":
		return 8 << 30, 400000, nil
	case "BUILD_GENERAL1_LARGE":
		return 16 << 30, 800000, nil
	default:
		return 0, 0, fmt.Errorf("unsupported local CodeBuild fleet compute type %q", compute)
	}
}

func (d *DockerExecutor) fleetName(arn string, slot int, kind string) string {
	sum := sha256.Sum256([]byte(d.config.Namespace + "\x00" + arn))
	return fmt.Sprintf("stackd-codebuild-fleet-%x-%s-%d", sum[:16], kind, slot)
}

func fleetHTTPStatus(err error, status int) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == status
}

// fleetSlots discovers only this executor namespace and ARN. Engine names and
// labels both have to agree before a discovered resource may be changed.
func (d *DockerExecutor) fleetSlots(ctx context.Context, arn string) ([]fleetSlot, error) {
	filters, err := json.Marshal(map[string][]string{"label": {fleetNamespaceLabel + "=" + d.config.Namespace, fleetLabel + "=" + arn}})
	if err != nil {
		return nil, err
	}
	var containers []fleetContainer
	if err := d.client.JSON(ctx, "GET", "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil, &containers); err != nil {
		return nil, err
	}
	byIndex := make(map[int]*fleetSlot)
	for _, container := range containers {
		if container.Labels[fleetNamespaceLabel] != d.config.Namespace || container.Labels[fleetLabel] != arn {
			return nil, errors.New("CodeBuild fleet container ownership does not match")
		}
		index, err := strconv.Atoi(container.Labels[fleetSlotLabel])
		if err != nil || index < 0 {
			return nil, errors.New("CodeBuild fleet has an invalid native slot label")
		}
		kind := "build"
		if container.Labels[fleetReservationLabel] == "true" {
			kind = "idle"
		}
		name := "/" + d.fleetName(arn, index, kind)
		if len(container.Names) != 1 || container.Names[0] != name {
			return nil, fmt.Errorf("CodeBuild fleet slot %d native name does not match its ownership", index)
		}
		slot := byIndex[index]
		if slot == nil {
			slot = &fleetSlot{index: index}
			byIndex[index] = slot
		}
		if kind == "idle" {
			if slot.idle.ID != "" {
				return nil, errors.New("CodeBuild fleet has duplicate idle capacity")
			}
			slot.idle = container
		} else {
			if slot.build.ID != "" || container.Labels[fleetARNLabel] == "" {
				return nil, errors.New("CodeBuild fleet has invalid build capacity ownership")
			}
			slot.build = container
		}
	}
	slots := make([]fleetSlot, 0, len(byIndex))
	for _, slot := range byIndex {
		slots = append(slots, *slot)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].index < slots[j].index })
	return slots, nil
}

func fleetObservedStatus(slots []fleetSlot) FleetStatus {
	status := FleetStatus{State: "ACTIVE"}
	for _, slot := range slots {
		if int32(slot.index+1) > status.Capacity {
			status.Capacity = int32(slot.index + 1)
		}
		for _, labels := range []map[string]string{slot.idle.Labels, slot.build.Labels} {
			capacity, _ := strconv.ParseInt(labels[fleetCapacityLabel], 10, 32)
			if int32(capacity) > status.Capacity {
				status.Capacity = int32(capacity)
			}
		}
		if slot.build.ID != "" {
			status.InUse++
			if slot.idle.State == "running" {
				status.State = "DEGRADED"
			}
		} else if slot.idle.State == "running" {
			status.Ready++
		}
	}
	if status.Ready+status.InUse != status.Capacity || status.Capacity == 0 {
		status.State = "CREATING"
	}
	return status
}

// ReserveFleet resolves a preinstalled pinned Linux image, starts actual idle
// containers, and reports ACTIVE only from observed native capacity. Cgroup hard
// limits bound each slot; MemoryReservation is Docker's soft memory reservation,
// not a claim of physically dedicated EC2 RAM or CPU. Builds transfer the same
// slot budget into a fresh container so workspaces and credentials never mix.
func (d *DockerExecutor) ReserveFleet(ctx context.Context, spec FleetSpecification) (FleetStatus, error) {
	if spec.ARN == "" || !strings.Contains(spec.ARN, ":fleet/") || spec.Capacity < 1 {
		return FleetStatus{}, errors.New("CodeBuild fleet requires an ARN and positive capacity")
	}
	if spec.EnvironmentType != "LINUX_CONTAINER" {
		return FleetStatus{}, fmt.Errorf("local CodeBuild fleets support LINUX_CONTAINER, not %q; macOS, custom AMIs and VPC hosts require a different backend", spec.EnvironmentType)
	}
	memory, cpu, err := fleetLimits(spec.ComputeType)
	if err != nil {
		return FleetStatus{}, err
	}
	if spec.Image == "" {
		spec.Image = d.config.FleetImage
	}
	if !strings.HasPrefix(spec.Image, "sha256:") && !strings.Contains(spec.Image, "@sha256:") {
		return FleetStatus{}, errors.New("CodeBuild fleet requires an explicitly pinned local container image, not an AMI or mutable image tag")
	}
	var image struct{ ID, OS, Architecture string }
	if err := d.client.JSON(ctx, "GET", "/images/"+url.PathEscape(spec.Image)+"/json", nil, &image); err != nil {
		return FleetStatus{}, fmt.Errorf("inspecting local CodeBuild fleet image: %w", err)
	}
	if image.ID == "" || image.OS != "linux" || image.Architecture != "amd64" {
		return FleetStatus{}, errors.New("CodeBuild LINUX_CONTAINER fleet requires a local Linux amd64 image")
	}
	spec.Image = image.ID
	var host struct {
		MemTotal int64
		NCPU     int64
	}
	if err := d.client.JSON(ctx, "GET", "/info", nil, &host); err != nil {
		return FleetStatus{}, err
	}
	if int64(spec.Capacity) > host.MemTotal/memory || int64(spec.Capacity) > host.NCPU/(cpu/100000) {
		return FleetStatus{}, errors.New("CodeBuild fleet capacity exceeds the Docker host CPU or memory capacity")
	}
	d.fleetMu.Lock()
	defer d.fleetMu.Unlock()
	slots, err := d.fleetSlots(ctx, spec.ARN)
	if err != nil {
		return FleetStatus{}, err
	}
	for _, slot := range slots {
		if slot.build.ID != "" && (slot.index >= int(spec.Capacity) || slot.idle.Labels[fleetComputeLabel] != spec.ComputeType || slot.idle.Labels[fleetEnvironmentLabel] != spec.EnvironmentType || slot.idle.Labels[fleetImageLabel] != spec.Image) {
			return fleetObservedStatus(slots), ErrFleetBusy
		}
	}
	byIndex := make(map[int]fleetSlot, len(slots))
	for _, slot := range slots {
		if slot.index >= int(spec.Capacity) {
			if err := d.client.RemoveContainer(ctx, slot.idle.ID); err != nil {
				return FleetStatus{}, err
			}
			continue
		}
		byIndex[slot.index] = slot
	}
	for index := range int(spec.Capacity) {
		slot := byIndex[index]
		if slot.build.ID != "" {
			if slot.idle.State == "running" {
				if err := d.stopFleetIdle(ctx, slot.idle.ID); err != nil {
					return FleetStatus{}, err
				}
			}
			continue
		}
		if slot.idle.ID != "" {
			var native struct {
				Image      string
				HostConfig docker.ContainerHostConfig
			}
			if err := d.client.JSON(ctx, "GET", "/containers/"+url.PathEscape(slot.idle.ID)+"/json", nil, &native); err != nil {
				return FleetStatus{}, err
			}
			labels := slot.idle.Labels
			if native.Image != spec.Image || native.HostConfig.Memory != memory || native.HostConfig.CPUQuota != cpu || labels[fleetCapacityLabel] != strconv.Itoa(int(spec.Capacity)) || labels[fleetComputeLabel] != spec.ComputeType || labels[fleetEnvironmentLabel] != spec.EnvironmentType {
				if err := d.client.RemoveContainer(ctx, slot.idle.ID); err != nil {
					return FleetStatus{}, err
				}
				slot.idle.ID = ""
			}
		}
		if slot.idle.ID == "" {
			labels := map[string]string{
				fleetNamespaceLabel: d.config.Namespace, fleetLabel: spec.ARN,
				fleetSlotLabel: strconv.Itoa(index), fleetReservationLabel: "true",
				fleetCapacityLabel: strconv.Itoa(int(spec.Capacity)),
				fleetComputeLabel:  spec.ComputeType, fleetEnvironmentLabel: spec.EnvironmentType,
				fleetImageLabel: spec.Image,
			}
			config := docker.ContainerConfig{
				Image: spec.Image, Entrypoint: []string{"/bin/sh", "-c"},
				Cmd:    []string{"trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"},
				Labels: labels, NetworkDisabled: true,
				HostConfig: docker.ContainerHostConfig{
					NetworkMode: "none", Memory: memory, MemorySwap: memory, MemoryReservation: memory,
					CPUPeriod: 100000, CPUQuota: cpu, PidsLimit: 64,
					CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
					LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
				},
			}
			var created struct{ ID string }
			if err := d.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(d.fleetName(spec.ARN, index, "idle")), config, &created); err != nil {
				return FleetStatus{}, err
			}
			slot.idle.ID = created.ID
		}
		if err := d.startFleetIdle(ctx, slot.idle.ID); err != nil {
			return FleetStatus{}, err
		}
	}
	slots, err = d.fleetSlots(ctx, spec.ARN)
	if err != nil {
		return FleetStatus{}, err
	}
	return fleetObservedStatus(slots), nil
}

func (d *DockerExecutor) InspectFleet(ctx context.Context, arn string) (FleetStatus, error) {
	d.fleetMu.Lock()
	defer d.fleetMu.Unlock()
	slots, err := d.fleetSlots(ctx, arn)
	if err != nil {
		return FleetStatus{}, err
	}
	if len(slots) == 0 {
		return FleetStatus{}, ErrFleetNotFound
	}
	return fleetObservedStatus(slots), nil
}

// ReleaseFleet never terminates an admitted build, including one whose output
// awaits publication. The service first stops admission and drains such builds.
func (d *DockerExecutor) ReleaseFleet(ctx context.Context, arn string) error {
	d.fleetMu.Lock()
	defer d.fleetMu.Unlock()
	slots, err := d.fleetSlots(ctx, arn)
	if err != nil {
		return err
	}
	for _, slot := range slots {
		if slot.build.ID != "" {
			return ErrFleetBusy
		}
	}
	for _, slot := range slots {
		if err := d.client.RemoveContainer(ctx, slot.idle.ID); err != nil {
			return err
		}
	}
	return nil
}

func (d *DockerExecutor) stopFleetIdle(ctx context.Context, id string) error {
	err := d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(id)+"/stop?t=5", nil, nil)
	if fleetHTTPStatus(err, http.StatusNotModified) {
		return nil
	}
	return err
}

func (d *DockerExecutor) startFleetIdle(ctx context.Context, id string) error {
	err := d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(id)+"/start", nil, nil)
	if err != nil && !fleetHTTPStatus(err, http.StatusNotModified) {
		return err
	}
	var observed struct {
		State struct {
			Running       bool
			Status, Error string
		}
	}
	if err := d.client.JSON(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, &observed); err != nil {
		return err
	}
	if !observed.State.Running || observed.State.Status != "running" {
		return fmt.Errorf("CodeBuild fleet idle container is not running: %s", observed.State.Error)
	}
	return nil
}

// reserveBuildSlot holds fleetMu until the caller finishes creating the build
// container and calls release. The fixed native build name is also an Engine
// uniqueness constraint; no second admitted build can occupy the same slot.
func (d *DockerExecutor) reserveBuildSlot(ctx context.Context, spec *Specification) (string, map[string]string, func(), error) {
	if spec.FleetARN == "" {
		return d.name(spec.ARN), nil, func() {}, nil
	}
	d.fleetMu.Lock()
	slots, err := d.fleetSlots(ctx, spec.FleetARN)
	if err != nil {
		d.fleetMu.Unlock()
		return "", nil, nil, err
	}
	if len(slots) == 0 {
		d.fleetMu.Unlock()
		return "", nil, nil, ErrFleetNotFound
	}
	for _, slot := range slots {
		if slot.build.ID != "" || slot.idle.ID == "" {
			continue
		}
		if slot.idle.State != "running" {
			if err := d.startFleetIdle(ctx, slot.idle.ID); err != nil {
				d.fleetMu.Unlock()
				return "", nil, nil, err
			}
		}
		memory, cpu, err := fleetLimits(slot.idle.Labels[fleetComputeLabel])
		if err != nil || spec.MemoryBytes > memory || spec.CPUQuota > cpu {
			d.fleetMu.Unlock()
			return "", nil, nil, errors.New("build resource requirements exceed its CodeBuild fleet slot")
		}
		if err := d.stopFleetIdle(ctx, slot.idle.ID); err != nil {
			d.fleetMu.Unlock()
			return "", nil, nil, err
		}
		spec.MemoryBytes, spec.CPUQuota = memory, cpu
		labels := map[string]string{
			fleetNamespaceLabel: d.config.Namespace, fleetARNLabel: spec.ARN,
			fleetLabel: spec.FleetARN, fleetSlotLabel: strconv.Itoa(slot.index),
			fleetCapacityLabel: slot.idle.Labels[fleetCapacityLabel],
		}
		return d.fleetName(spec.FleetARN, slot.index, "build"), labels, d.fleetMu.Unlock, nil
	}
	d.fleetMu.Unlock()
	return "", nil, nil, ErrFleetCapacity
}

// restoreBuildSlot uses the removed container's captured labels, not an
// in-memory lease table, so cancellation and retained-controller recovery agree.
func (d *DockerExecutor) restoreBuildSlot(ctx context.Context, labels map[string]string) error {
	arn := labels[fleetLabel]
	if arn == "" {
		return nil
	}
	if labels[fleetNamespaceLabel] != d.config.Namespace || labels[fleetARNLabel] == "" {
		return errors.New("CodeBuild build slot ownership does not match")
	}
	index, err := strconv.Atoi(labels[fleetSlotLabel])
	if err != nil || index < 0 {
		return errors.New("CodeBuild build slot identity is invalid")
	}
	d.fleetMu.Lock()
	defer d.fleetMu.Unlock()
	slots, err := d.fleetSlots(ctx, arn)
	if err != nil {
		return err
	}
	for _, slot := range slots {
		if slot.index != index {
			continue
		}
		if slot.build.ID != "" {
			return ErrFleetBusy
		}
		if slot.idle.ID == "" {
			return ErrFleetNotFound
		}
		return d.startFleetIdle(ctx, slot.idle.ID)
	}
	return nil // A completed deletion owns removal of an already absent slot.
}
