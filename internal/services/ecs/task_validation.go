package ecs

import (
	"fmt"
	"math"
	"slices"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
	"strconv"
	"strings"
)

// Registration admits a definition, not a claim that its requested runtime has
// executed. Runtime launch capability is checked by the executor, not inferred
// from the compatibility set returned by the ECS registration API.
func normalizeTaskDefinition(in *api.RegisterTaskDefinitionInput) (api.TaskDefinition, *awswire.Error) {
	request := api.CloneRegisterTaskDefinitionRequest(*in)
	cpu, rejected := normalizeUnits(request.Cpu, "cpu")
	if rejected != nil {
		return api.TaskDefinition{}, rejected
	}
	memory, rejected := normalizeUnits(request.Memory, "memory")
	if rejected != nil {
		return api.TaskDefinition{}, rejected
	}
	if !resourceName.MatchString(value(request.Family)) {
		return api.TaskDefinition{}, failure("ClientException", "Family contains invalid characters.")
	}
	if len(request.ContainerDefinitions) == 0 {
		return api.TaskDefinition{}, failure("ClientException", "Container list cannot be empty.")
	}
	if len(request.ContainerDefinitions) > 10 {
		return api.TaskDefinition{}, failure("ClientException", "A task definition can contain at most 10 containers.")
	}
	fargate := slices.Contains(request.RequiresCompatibilities, api.Compatibility("FARGATE"))
	essential := false
	names := map[string]int{}
	for i := range request.ContainerDefinitions {
		c := &request.ContainerDefinitions[i]
		name := value(c.Name)
		if !resourceName.MatchString(name) {
			return api.TaskDefinition{}, failure("ClientException", "Invalid container name.")
		}
		if _, exists := names[name]; exists {
			return api.TaskDefinition{}, failure("ClientException", "Container names must be unique.")
		}
		names[name] = i
		if c.Essential == nil {
			c.Essential = new(api.BoxedBoolean(true))
		}
		essential = essential || bool(*c.Essential)
		if c.Cpu == nil {
			c.Cpu = new(api.Integer(0))
		}
		if *c.Cpu < 0 {
			return api.TaskDefinition{}, failure("ClientException", "Container cpu must be non-negative.")
		}
		if c.Environment == nil {
			c.Environment = api.EnvironmentVariables{}
		}
		if c.MountPoints == nil {
			c.MountPoints = api.MountPointList{}
		}
		if c.PortMappings == nil {
			c.PortMappings = api.PortMappingList{}
		}
		if c.SystemControls == nil {
			c.SystemControls = api.SystemControls{}
		}
		if c.VolumesFrom == nil {
			c.VolumesFrom = api.VolumeFromList{}
		}
	}
	if !essential {
		return api.TaskDefinition{}, failure("ClientException", "Task definition doesn't have any essential container.")
	}
	mode := value(request.NetworkMode)
	switch mode {
	case "", "bridge", "host", "awsvpc", "none":
	default:
		return api.TaskDefinition{}, failure("ClientException", "Invalid network mode.")
	}
	if fargate && mode != "awsvpc" {
		return api.TaskDefinition{}, failure("ClientException", "Fargate only supports network mode ‘awsvpc’.")
	}
	fargateStopTimeoutExceeded := false
	for i := range request.ContainerDefinitions {
		c := &request.ContainerDefinitions[i]
		name := value(c.Name)
		if value(c.Image) == "" {
			return api.TaskDefinition{}, failure("ClientException", "Container image must not be empty.")
		}
		if memory == nil && c.Memory == nil && c.MemoryReservation == nil {
			return api.TaskDefinition{}, failure("ClientException", "Invalid setting for container '"+name+"'. At least one of 'memory' or 'memoryReservation' must be specified.")
		}
		if c.Memory != nil && c.MemoryReservation != nil && *c.Memory < *c.MemoryReservation {
			return api.TaskDefinition{}, failure("ClientException", "Invalid setting for container '"+name+"'. 'memory' must be greater than or equal to 'memoryReservation'.")
		}
		if c.Memory != nil && *c.Memory <= 0 || c.MemoryReservation != nil && *c.MemoryReservation <= 0 {
			return api.TaskDefinition{}, failure("ClientException", "Container memory must be greater than zero.")
		}
		if c.StartTimeout != nil && *c.StartTimeout < 2 {
			return api.TaskDefinition{}, failure("ClientException", "Granular start timeout on container '"+name+"' must be at least 2 seconds.")
		}
		if c.StopTimeout != nil {
			if *c.StopTimeout < 2 {
				return api.TaskDefinition{}, failure("ClientException", "Granular stop timeout on container '"+name+"' must be at least 2 seconds.")
			}
			if *c.StopTimeout > 120 {
				fargateStopTimeoutExceeded = true
				if fargate {
					return api.TaskDefinition{}, failure("ClientException", "Tasks using the Fargate launch type must have a container stop timeout of less than 120 seconds.")
				}
			}
		}
		if rejected := normalizePorts(c, mode); rejected != nil {
			return api.TaskDefinition{}, rejected
		}
		if rejected := normalizeHealth(c.HealthCheck); rejected != nil {
			return api.TaskDefinition{}, rejected
		}
		if rejected := validateLogs(c.LogConfiguration, fargate, request.ExecutionRoleArn); rejected != nil {
			return api.TaskDefinition{}, rejected
		}
		if rejected := validateTaskEnvironmentFiles(c.EnvironmentFiles); rejected != nil {
			return api.TaskDefinition{}, rejected
		}
		if len(c.EnvironmentFiles) != 0 && request.RuntimePlatform != nil && value(request.RuntimePlatform.OperatingSystemFamily) != "" && value(request.RuntimePlatform.OperatingSystemFamily) != "LINUX" {
			return api.TaskDefinition{}, unsupported("Environment files are supported for Linux containers only.")
		}
	}
	if rejected := validateDependencies(request.ContainerDefinitions, names); rejected != nil {
		return api.TaskDefinition{}, rejected
	}
	for _, compatibility := range request.RequiresCompatibilities {
		switch compatibility {
		case "EC2", "FARGATE", "EXTERNAL":
		case "MANAGED_INSTANCES":
			return api.TaskDefinition{}, unsupported("Managed instance task admission requires a configured managed instance capacity provider.")
		default:
			return api.TaskDefinition{}, failure("ClientException", "Invalid compatibility: "+string(compatibility))
		}
	}
	if fargate {
		if cpu == nil {
			return api.TaskDefinition{}, failure("ClientException", "Fargate requires that 'cpu' be defined at the task level.")
		}
		if memory == nil {
			return api.TaskDefinition{}, failure("ClientException", "Fargate requires that 'memory' be defined at the task level.")
		}
		c, _ := strconv.Atoi(value(cpu))
		m, _ := strconv.Atoi(value(memory))
		if !fargateSize(c, m) {
			return api.TaskDefinition{}, failure("ClientException", fmt.Sprintf("No Fargate configuration exists for given values: %d CPU, %d memory. See the Amazon ECS documentation for the valid values.", c, m))
		}
	}
	if request.EphemeralStorage != nil {
		if !fargate {
			return api.TaskDefinition{}, failure("ClientException", "Ephemeral storage is only supported for Fargate tasks.")
		}
		if request.EphemeralStorage.SizeInGiB == nil || *request.EphemeralStorage.SizeInGiB < 21 || *request.EphemeralStorage.SizeInGiB > 200 {
			return api.TaskDefinition{}, failure("ClientException", "Ephemeral storage size must be between 21 and 200 GiB.")
		}
	}
	if request.Volumes == nil {
		request.Volumes = api.VolumeList{}
	}
	if request.PlacementConstraints == nil {
		request.PlacementConstraints = api.TaskDefinitionPlacementConstraints{}
	}
	out := api.TaskDefinition{ContainerDefinitions: request.ContainerDefinitions, Cpu: cpu, Memory: memory, Family: request.Family, NetworkMode: request.NetworkMode, TaskRoleArn: request.TaskRoleArn, ExecutionRoleArn: request.ExecutionRoleArn, RequiresCompatibilities: request.RequiresCompatibilities, RuntimePlatform: request.RuntimePlatform, Volumes: request.Volumes, PlacementConstraints: request.PlacementConstraints, PidMode: request.PidMode, IpcMode: request.IpcMode, ProxyConfiguration: request.ProxyConfiguration, InferenceAccelerators: request.InferenceAccelerators, EphemeralStorage: request.EphemeralStorage, EnableFaultInjection: request.EnableFaultInjection, Compatibilities: api.CompatibilityList{"EXTERNAL", "EC2"}}
	for _, c := range out.ContainerDefinitions {
		if len(c.DependsOn) > 0 || c.StartTimeout != nil || c.StopTimeout != nil {
			addAttribute(&out, "ecs.capability.container-ordering")
		}
		if c.HealthCheck != nil {
			addAttribute(&out, "ecs.capability.container-health-check")
		}
		if c.LogConfiguration != nil {
			addAttribute(&out, "com.amazonaws.ecs.capability.logging-driver."+value(c.LogConfiguration.LogDriver))
			addAttribute(&out, "com.amazonaws.ecs.capability.docker-remote-api.1.19")
		}
	}
	if mode == "awsvpc" {
		out.Compatibilities = api.CompatibilityList{"EC2", "MANAGED_INSTANCES", "FARGATE"}
		if request.RuntimePlatform != nil {
			if strings.HasPrefix(value(request.RuntimePlatform.OperatingSystemFamily), "WINDOWS_") {
				out.Compatibilities = api.CompatibilityList{"EC2", "FARGATE"}
			} else if value(request.RuntimePlatform.CpuArchitecture) == "ARM64" {
				out.Compatibilities = api.CompatibilityList{"EC2", "FARGATE", "MANAGED_INSTANCES"}
			}
		}
		addAttribute(&out, "com.amazonaws.ecs.capability.docker-remote-api.1.18")
		addAttribute(&out, "ecs.capability.task-eni")
	}
	if fargateStopTimeoutExceeded {
		if i := slices.Index(out.Compatibilities, api.Compatibility("FARGATE")); i >= 0 {
			out.Compatibilities = slices.Delete(out.Compatibilities, i, i+1)
		}
	}
	return out, nil
}
func normalizeUnits(input *api.String, kind string) (*api.String, *awswire.Error) {
	if input == nil {
		return nil, nil
	}
	text := strings.TrimSpace(value(input))
	lower := strings.ToLower(text)
	scale := float64(1)
	if kind == "cpu" {
		for _, suffix := range []string{"vcpus", "vcpu"} {
			if strings.HasSuffix(lower, suffix) {
				text = strings.TrimSpace(text[:len(text)-len(suffix)])
				scale = 1024
				break
			}
		}
	} else {
		for _, unit := range []struct {
			suffix string
			scale  float64
		}{{"gib", 1024}, {"gb", 1024}, {"mib", 1}, {"mb", 1}} {
			if strings.HasSuffix(lower, unit.suffix) {
				text = strings.TrimSpace(text[:len(text)-len(unit.suffix)])
				scale = unit.scale
				break
			}
		}
	}
	n, err := strconv.ParseFloat(text, 64)
	n *= scale
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 || n > 2147483647 || n != math.Trunc(n) {
		return nil, failure("InvalidParameterException", "Invalid '"+kind+"' setting for task.")
	}
	return new(api.String(strconv.FormatInt(int64(n), 10))), nil
}
func fargateSize(cpu, memory int) bool {
	switch cpu {
	case 256:
		return memory == 512 || memory == 1024 || memory == 2048
	case 512:
		return memory >= 1024 && memory <= 4096 && memory%1024 == 0
	case 1024:
		return memory >= 2048 && memory <= 8192 && memory%1024 == 0
	case 2048:
		return memory >= 4096 && memory <= 16384 && memory%1024 == 0
	case 4096:
		return memory >= 8192 && memory <= 30720 && memory%1024 == 0
	case 8192:
		return memory >= 16384 && memory <= 61440 && memory%4096 == 0
	case 16384:
		return memory >= 32768 && memory <= 122880 && memory%8192 == 0
	}
	return false
}
func normalizePorts(c *api.ContainerDefinition, mode string) *awswire.Error {
	for i := range c.PortMappings {
		p := &c.PortMappings[i]
		if p.Protocol == nil {
			p.Protocol = new(api.TransportProtocol("tcp"))
		}
		if value(p.Protocol) != "tcp" && value(p.Protocol) != "udp" {
			return failure("ClientException", "Invalid port mapping protocol.")
		}
		if p.ContainerPortRange != nil {
			return unsupported("Container port ranges require executor port-range support.")
		}
		if p.ContainerPort == nil || *p.ContainerPort < 1 || *p.ContainerPort > 65535 {
			return failure("ClientException", "Container port must be between 1 and 65535.")
		}
		if p.HostPort == nil {
			p.HostPort = new(api.BoxedInteger(0))
			if mode == "host" || mode == "awsvpc" {
				p.HostPort = new(*p.ContainerPort)
			}
		}
		if *p.HostPort < 0 || *p.HostPort > 65535 {
			return failure("ClientException", "Host port must be between 0 and 65535.")
		}
		if (mode == "host" || mode == "awsvpc") && *p.HostPort != *p.ContainerPort {
			return failure("ClientException", "When networkMode="+mode+", the host ports and container ports in port mappings must match.")
		}
	}
	return nil
}
func normalizeHealth(h *api.HealthCheck) *awswire.Error {
	if h == nil {
		return nil
	}
	if len(h.Command) < 2 || (h.Command[0] != "CMD" && h.Command[0] != "CMD-SHELL") {
		return failure("ClientException", "Health check command must start with CMD or CMD-SHELL.")
	}
	if h.Interval == nil {
		h.Interval = new(api.BoxedInteger(30))
	}
	if h.Timeout == nil {
		h.Timeout = new(api.BoxedInteger(5))
	}
	if h.Retries == nil {
		h.Retries = new(api.BoxedInteger(3))
	}
	if *h.Interval < 5 || *h.Interval > 300 || *h.Timeout < 2 || *h.Timeout > 60 || *h.Retries < 1 || *h.Retries > 10 || h.StartPeriod != nil && (*h.StartPeriod < 0 || *h.StartPeriod > 300) {
		return failure("ClientException", "Invalid health check configuration.")
	}
	return nil
}
func validateLogs(log *api.LogConfiguration, fargate bool, role *api.String) *awswire.Error {
	if log == nil {
		return nil
	}
	driver := value(log.LogDriver)
	if fargate && !slices.Contains([]string{"awslogs", "splunk", "awsfirelens"}, driver) {
		return failure("ClientException", driver+" is not a valid log driver. Must be one of [awslogs,splunk,awsfirelens]")
	}
	if driver == "awslogs" {
		if log.Options["awslogs-region"] == "" || log.Options["awslogs-group"] == "" {
			return failure("ClientException", "Log driver awslogs requires options: awslogs-region, awslogs-group")
		}
		if fargate && value(role) == "" {
			return failure("ClientException", "Fargate requires task definition to have execution role ARN to support log driver awslogs.")
		}
	}
	return nil
}
func validateDependencies(containers api.ContainerDefinitions, names map[string]int) *awswire.Error {
	for _, c := range containers {
		for _, d := range c.DependsOn {
			target, ok := names[value(d.ContainerName)]
			if !ok {
				return failure("ClientException", "Cannot depend on container + '"+value(d.ContainerName)+"' because it does not exist")
			}
			switch value(d.Condition) {
			case "SUCCESS", "COMPLETE":
				if bool(*containers[target].Essential) {
					return failure("ClientException", "A dependency container with SUCCESS or COMPLETE condition cannot be an essential container")
				}
			case "HEALTHY":
				if containers[target].HealthCheck == nil {
					return failure("ClientException", "A dependency container with HEALTHY condition must have health check configured")
				}
			case "START":
			default:
				return failure("ClientException", "Invalid container dependency condition.")
			}
		}
	}
	marks := make([]uint8, len(containers))
	var cycle func(int) bool
	cycle = func(i int) bool {
		if marks[i] == 1 {
			return true
		}
		if marks[i] == 2 {
			return false
		}
		marks[i] = 1
		for _, d := range containers[i].DependsOn {
			if cycle(names[value(d.ContainerName)]) {
				return true
			}
		}
		marks[i] = 2
		return false
	}
	for i := range containers {
		if cycle(i) {
			return failure("ClientException", "Container dependsOn contains a cycle")
		}
	}
	return nil
}
func addAttribute(definition *api.TaskDefinition, name string) {
	for _, attribute := range definition.RequiresAttributes {
		if value(attribute.Name) == name {
			return
		}
	}
	definition.RequiresAttributes = append(definition.RequiresAttributes, api.Attribute{Name: new(api.String(name))})
}
