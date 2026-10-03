package ecs

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
)

func taskRoleARN(v TaskRecord) string {
	if v.Data.Overrides != nil && v.Data.Overrides.TaskRoleArn != nil {
		return value(v.Data.Overrides.TaskRoleArn)
	}
	return value(v.Definition.TaskRoleArn)
}
func taskExecutionRoleARN(v TaskRecord) string {
	if v.Data.Overrides != nil && v.Data.Overrides.ExecutionRoleArn != nil {
		return value(v.Data.Overrides.ExecutionRoleArn)
	}
	return value(v.Definition.ExecutionRoleArn)
}

func taskOverrides(definition api.TaskDefinition, input *api.TaskOverride) (api.TaskOverride, *awswire.Error) {
	out := api.TaskOverride{ContainerOverrides: api.ContainerOverrides{}, InferenceAcceleratorOverrides: api.InferenceAcceleratorOverrides{}}
	if input != nil {
		out = api.CloneTaskOverride(*input)
	}
	for _, field := range []**api.String{&out.Cpu, &out.Memory} {
		if *field != nil {
			normalized, rejected := normalizeUnits(*field, "task override")
			if rejected != nil {
				return out, rejected
			}
			*field = normalized
		}
	}
	seen := map[string]bool{}
	for _, override := range out.ContainerOverrides {
		name := value(override.Name)
		if seen[name] || !slices.ContainsFunc(definition.ContainerDefinitions, func(c api.ContainerDefinition) bool { return value(c.Name) == name }) {
			return out, failure("InvalidParameterException", "Override names must identify distinct containers in the task definition.")
		}
		seen[name] = true
		if override.Cpu != nil && *override.Cpu < 0 || override.Memory != nil && *override.Memory <= 0 || override.MemoryReservation != nil && *override.MemoryReservation <= 0 {
			return out, failure("InvalidParameterException", "Container resource overrides must have valid CPU and memory values.")
		}
	}
	for _, container := range definition.ContainerDefinitions {
		if !seen[value(container.Name)] {
			out.ContainerOverrides = append(out.ContainerOverrides, api.ContainerOverride{Name: container.Name})
		}
	}
	if out.InferenceAcceleratorOverrides == nil {
		out.InferenceAcceleratorOverrides = api.InferenceAcceleratorOverrides{}
	}
	return out, nil
}

// effectiveTaskContainers applies the admitted override once at the execution
// boundary; the immutable definition and public overrides retain their meanings.
func effectiveTaskContainers(v TaskRecord) api.ContainerDefinitions {
	out := api.CloneContainerDefinitions(v.Definition.ContainerDefinitions)
	if v.Data.Overrides == nil {
		return out
	}
	for _, override := range v.Data.Overrides.ContainerOverrides {
		for i := range out {
			c := &out[i]
			if value(c.Name) != value(override.Name) {
				continue
			}
			if override.Command != nil {
				c.Command = api.CloneStringList(override.Command)
			}
			if override.Cpu != nil {
				c.Cpu = new(api.Integer(*override.Cpu))
			}
			if override.Memory != nil {
				c.Memory = new(*override.Memory)
			}
			if override.MemoryReservation != nil {
				c.MemoryReservation = new(*override.MemoryReservation)
			}
			if override.EnvironmentFiles != nil {
				c.EnvironmentFiles = api.CloneEnvironmentFiles(override.EnvironmentFiles)
			}
			for _, variable := range override.Environment {
				at := slices.IndexFunc(c.Environment, func(old api.KeyValuePair) bool { return value(old.Name) == value(variable.Name) })
				if at < 0 {
					c.Environment = append(c.Environment, variable)
				} else {
					c.Environment[at] = variable
				}
			}
			if override.ResourceRequirements != nil {
				c.ResourceRequirements = api.CloneResourceRequirements(override.ResourceRequirements)
			}
		}
	}
	return out
}

func executableTaskDefinition(definition api.TaskDefinition, overrides api.TaskOverride) *awswire.Error {
	if definition.RuntimePlatform != nil && value(definition.RuntimePlatform.OperatingSystemFamily) != "" && value(definition.RuntimePlatform.OperatingSystemFamily) != "LINUX" {
		return unsupported("The configured task executor supports Linux containers only.")
	}
	if definition.ProxyConfiguration != nil || len(definition.InferenceAccelerators) > 0 || len(overrides.InferenceAcceleratorOverrides) > 0 || value(definition.IpcMode) != "" || value(definition.PidMode) != "" {
		return unsupported("Task proxy, accelerator and shared process namespaces require their native execution adapters.")
	}
	if definition.EphemeralStorage != nil || overrides.EphemeralStorage != nil {
		// TODO: Comeback enforce task-wide ephemeral disk quotas with a supported native storage backend.
		return unsupported("The Docker storage backend does not enforce Fargate ephemeral-storage quotas.")
	}
	volumes := map[string]bool{}
	for _, volume := range definition.Volumes {
		if volume.DockerVolumeConfiguration != nil || volume.EfsVolumeConfiguration != nil || volume.FsxWindowsFileServerVolumeConfiguration != nil || volume.S3filesVolumeConfiguration != nil || volume.ConfiguredAtLaunch != nil && bool(*volume.ConfiguredAtLaunch) || volume.Host != nil && value(volume.Host.SourcePath) != "" {
			return unsupported("Task external and configured volumes require their real storage adapters.")
		}
		name := value(volume.Name)
		if name == "" || volumes[name] {
			return failure("ClientException", "Task volume names must be nonempty and unique.")
		}
		volumes[name] = true
	}
	for _, container := range effectiveTaskContainers(TaskRecord{Definition: definition, Data: api.Task{Overrides: &overrides}}) {
		if rejected := validateTaskEnvironmentFiles(container.EnvironmentFiles); rejected != nil {
			return rejected
		}
		if container.RepositoryCredentials != nil || container.FirelensConfiguration != nil || len(container.CredentialSpecs) > 0 || len(container.ResourceRequirements) > 0 {
			// TODO: Comeback resolve registry, FireLens, credential-spec and accelerator dependencies.
			return unsupported("Task registry, FireLens, credential-spec and accelerator dependencies are not configured.")
		}
		for _, secret := range container.Secrets {
			name, reference := value(secret.Name), value(secret.ValueFrom)
			if name == "" || strings.ContainsAny(name, "=\x00") || reference == "" {
				return failure("InvalidParameterException", "Container secrets require an environment name and SSM parameter or Secrets Manager reference.")
			}
			if strings.HasPrefix(reference, "arn:") {
				resource, err := arn.Parse(reference)
				if err != nil || resource.Service != "ssm" && resource.Service != "secretsmanager" {
					return unsupported("Container secrets support SSM parameter and Secrets Manager ARNs only.")
				}
				if resource.Service == "ssm" && !strings.HasPrefix(resource.Resource, "parameter/") {
					return failure("InvalidParameterException", "Invalid SSM parameter ARN.")
				}
				if resource.Service == "secretsmanager" {
					parts := strings.Split(resource.Resource, ":")
					if resource.Region == "" || resource.AccountID == "" || len(parts) < 2 || len(parts) > 5 || parts[0] != "secret" || parts[1] == "" || len(parts) == 5 && parts[3] != "" && parts[4] != "" {
						return failure("InvalidParameterException", "Invalid Secrets Manager ARN or mutually exclusive version selectors.")
					}
				}
			}
		}
		if len(container.Links) > 0 || len(container.VolumesFrom) > 0 || len(container.DnsServers) > 0 || len(container.DnsSearchDomains) > 0 || len(container.ExtraHosts) > 0 || len(container.DockerSecurityOptions) > 0 || len(container.DockerLabels) > 0 || len(container.SystemControls) > 0 || len(container.Ulimits) > 0 || container.LinuxParameters != nil || value(container.Hostname) != "" {
			return unsupported("These container host, Linux or filesystem settings require their native Fargate execution mapping.")
		}
		if container.Privileged != nil && bool(*container.Privileged) || container.PseudoTerminal != nil && bool(*container.PseudoTerminal) || container.Interactive != nil && bool(*container.Interactive) || container.DisableNetworking != nil && bool(*container.DisableNetworking) || container.RestartPolicy != nil && container.RestartPolicy.Enabled != nil && bool(*container.RestartPolicy.Enabled) {
			return unsupported("Privileged, interactive, isolated-network and restart-policy task execution is not implemented.")
		}
		if container.Memory != nil && container.MemoryReservation != nil && *container.Memory < *container.MemoryReservation {
			return failure("InvalidParameterException", "Container memory must be at least its memory reservation.")
		}
		for _, mount := range container.MountPoints {
			if !volumes[value(mount.SourceVolume)] || !strings.HasPrefix(value(mount.ContainerPath), "/") {
				return failure("ClientException", "Mount points must refer to declared task volumes and absolute container paths.")
			}
		}
		for _, variable := range container.Environment {
			if value(variable.Name) == "" || strings.ContainsAny(value(variable.Name), "=\x00") || strings.ContainsRune(value(variable.Value), '\x00') {
				return failure("InvalidParameterException", "Container environment variables require valid names and values.")
			}
		}
	}
	return nil
}

func taskEnvironment(container api.ContainerDefinition, service []string, parameters, files map[string]string) []string {
	values := make(map[string]string, len(container.Environment)+len(container.Secrets)+len(service)+len(files))
	maps.Copy(values, files)
	for _, v := range container.Environment {
		values[value(v.Name)] = value(v.Value)
	}
	if parameters != nil {
		for _, secret := range container.Secrets {
			values[value(secret.Name)] = parameters[value(secret.ValueFrom)]
		}
	}
	for _, v := range service {
		name, content, _ := strings.Cut(v, "=")
		values[name] = content
	}
	out := make([]string, 0, len(values))
	for _, key := range slices.Sorted(maps.Keys(values)) {
		out = append(out, key+"="+values[key])
	}
	return out
}

func taskCPU(value *api.Integer) int64 {
	if *value < 2 {
		return 2
	}
	return int64(*value)
}
func taskMemory(value *api.BoxedInteger) int64 {
	if value == nil {
		return 0
	}
	return int64(*value) << 20
}
func taskInteger(value string) int64 { number, _ := strconv.ParseInt(value, 10, 64); return number }
