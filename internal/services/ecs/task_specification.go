package ecs

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	runtime "stackd/compute/ecs"
	"stackd/compute/network"
	api "stackd/internal/awsapi/ecs"
)

func (s *Service) taskSpecification(record TaskRecord, network network.Specification, metadata http.Handler, credentials TaskCredentialSource) runtime.Specification {
	architecture := "amd64"
	if record.Definition.RuntimePlatform != nil && value(record.Definition.RuntimePlatform.CpuArchitecture) == "ARM64" {
		architecture = "arm64"
	}
	spec := runtime.Specification{TaskARN: record.Key.ARN(), Architecture: architecture, CPUUnits: taskInteger(value(record.Data.Cpu)), MemoryBytes: taskInteger(value(record.Data.Memory)) << 20, Network: network, Metadata: metadata}
	for _, volume := range record.Definition.Volumes {
		spec.Volumes = append(spec.Volumes, value(volume.Name))
	}
	for _, container := range effectiveTaskContainers(record) {
		name := value(container.Name)
		resolved := runtime.ContainerSpecification{Name: name, Image: value(container.Image), Entrypoint: taskStrings(container.EntryPoint), Command: taskStrings(container.Command), Environment: taskEnvironment(container, taskServiceEnvironment(record, name, s.endpoint), nil, nil), WorkingDirectory: value(container.WorkingDirectory), User: value(container.User), CPUShares: taskCPU(container.Cpu), MemoryBytes: taskMemory(container.Memory), MemoryReservationBytes: taskMemory(container.MemoryReservation), ReadonlyRootFilesystem: container.ReadonlyRootFilesystem != nil && bool(*container.ReadonlyRootFilesystem)}
		if len(container.Secrets) != 0 || len(container.EnvironmentFiles) != 0 {
			resolved.ResolveEnvironment = s.taskParameterResolver(record, container, credentials)
		}
		if health := container.HealthCheck; health != nil {
			resolved.HealthCheck = &runtime.HealthCheck{Command: taskStrings(health.Command), Interval: time.Duration(*health.Interval) * time.Second, Timeout: time.Duration(*health.Timeout) * time.Second, Retries: int(*health.Retries)}
			if health.StartPeriod != nil {
				resolved.HealthCheck.StartPeriod = time.Duration(*health.StartPeriod) * time.Second
			}
		}
		for _, mount := range container.MountPoints {
			resolved.Mounts = append(resolved.Mounts, runtime.Mount{Volume: value(mount.SourceVolume), Path: value(mount.ContainerPath), ReadOnly: mount.ReadOnly != nil && bool(*mount.ReadOnly)})
		}
		spec.Containers = append(spec.Containers, resolved)
	}
	return spec
}

// Native preparation invokes this closure only for a new container. Reopening
// an existing task neither refetches sources nor requires fresh S3/SSM/secret/KMS access.
func (s *Service) taskParameterResolver(record TaskRecord, container api.ContainerDefinition, credentials TaskCredentialSource) func(context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		if len(container.Secrets) != 0 && s.parameters == nil {
			return nil, fmt.Errorf("task secret adapter is unavailable")
		}
		references := make([]string, 0, len(container.Secrets))
		for _, secret := range container.Secrets {
			references = append(references, value(secret.ValueFrom))
		}
		parameters := map[string]string{}
		if len(references) != 0 {
			var err error
			parameters, err = s.parameters.Read(taskOwnerContext(ctx, record), record.Key, references, credentials)
			if err != nil {
				return nil, err
			}
		}
		for _, secret := range container.Secrets {
			content, found := parameters[value(secret.ValueFrom)]
			if !found {
				return nil, fmt.Errorf("value for container secret %q was not returned", value(secret.Name))
			}
			if strings.ContainsRune(content, 0) {
				return nil, fmt.Errorf("value for container secret %q contains NUL", value(secret.Name))
			}
		}
		files := map[string]string{}
		for _, file := range container.EnvironmentFiles {
			if s.environmentFiles == nil {
				return nil, fmt.Errorf("S3 task environment-file adapter is unavailable")
			}
			body, err := s.environmentFiles.Read(taskOwnerContext(ctx, record), record.Key, value(file.Value), credentials)
			if err != nil {
				return nil, err
			}
			if err := parseTaskEnvironmentFile(body, files); err != nil {
				return nil, err
			}
		}
		return taskEnvironment(container, taskServiceEnvironment(record, value(container.Name), s.endpoint), parameters, files), nil
	}
}

func taskStrings(in api.StringList) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
