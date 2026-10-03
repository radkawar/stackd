package ecs

import (
	"context"
	"crypto/rand"
	"github.com/google/uuid"
	"slices"
	api "stackd/internal/awsapi/ecs"
	"strconv"
	"strings"
	"time"
)

// taskPlan is execution admission without a customer's RunTask command. The
// scheduler reuses construction while IAM and token semantics stay at APIs.
type taskPlan struct {
	cluster                         ClusterRecord
	definition                      TaskDefinitionRecord
	input                           api.RunTaskInput
	overrides                       api.TaskOverride
	placement                       TaskPlacement
	cpu, memory, platform, provider string
}

func (s *Service) prepareTask(ctx context.Context, in *api.RunTaskInput, cluster ClusterRecord, definition TaskDefinitionRecord) (taskPlan, error) {
	p := taskPlan{cluster: cluster, definition: definition, input: *in}
	launch, provider, rejected := taskLaunchType(in, cluster.Data)
	if rejected != nil {
		return p, rejected
	}
	if launch != "FARGATE" {
		return p, unsupported("ECS task execution requires a supported Fargate container backend.")
	}
	p.provider = provider
	if value(definition.Data.NetworkMode) != "awsvpc" {
		return p, failure("ClientException", "Fargate requires task definition to have execution network mode awsvpc.")
	}
	if in.NetworkConfiguration == nil || in.NetworkConfiguration.AwsvpcConfiguration == nil {
		return p, failure("InvalidParameterException", "Network Configuration must be provided when networkMode 'awsvpc' is specified.")
	}
	if len(in.PlacementConstraints) > 0 || len(in.PlacementStrategy) > 0 || len(in.VolumeConfigurations) > 0 || in.EnableExecuteCommand != nil && bool(*in.EnableExecuteCommand) {
		// TODO: Comeback implement placement, managed volumes and ExecuteCommand dependencies.
		return p, unsupported("Task placement, configured-at-launch volumes and ExecuteCommand require their execution dependencies.")
	}
	p.platform = value(in.PlatformVersion)
	if p.platform == "" || p.platform == "LATEST" {
		p.platform = "1.4.0"
	}
	if p.platform != "1.4.0" {
		return p, unsupported("Only the Linux Fargate 1.4.0 task runtime is currently configured.")
	}
	p.overrides, rejected = taskOverrides(definition.Data, in.Overrides)
	if rejected != nil {
		return p, rejected
	}
	p.cpu, p.memory = value(definition.Data.Cpu), value(definition.Data.Memory)
	if p.overrides.Cpu != nil {
		p.cpu = value(p.overrides.Cpu)
	}
	if p.overrides.Memory != nil {
		p.memory = value(p.overrides.Memory)
	}
	cpu, cpuErr := strconv.Atoi(p.cpu)
	memory, memoryErr := strconv.Atoi(p.memory)
	if cpuErr != nil || memoryErr != nil || !fargateSize(cpu, memory) {
		return p, failure("ClientException", "No Fargate configuration exists for the requested CPU and memory.")
	}
	if rejected := executableTaskDefinition(definition.Data, p.overrides); rejected != nil {
		return p, rejected
	}
	if s.executor == nil || s.networks == nil || s.taskRoles == nil {
		return p, unsupported("No complete ECS task execution dependencies are configured.")
	}
	var err error
	p.placement, err = s.networks.Select(ctx, cluster.Key.ARN(), *in.NetworkConfiguration.AwsvpcConfiguration)
	return p, err
}

func (s *Service) validateTaskRoles(ctx context.Context, p taskPlan, resourceARN string) error {
	record := TaskRecord{Definition: p.definition.Data, Data: api.Task{Overrides: &p.overrides}}
	for _, role := range []string{taskRoleARN(record), taskExecutionRoleARN(record)} {
		if role != "" {
			if err := s.taskRoles.Validate(ctx, role, resourceARN); err != nil {
				return err
			}
		}
	}
	return nil
}

func mergeTaskTags(base, requested api.Tags) api.Tags {
	tags := api.CloneTags(base)
	for _, tag := range requested {
		at := slices.IndexFunc(tags, func(old api.Tag) bool { return value(old.Key) == value(tag.Key) })
		if at < 0 {
			tags = append(tags, tag)
		} else {
			tags[at] = tag
		}
	}
	return tags
}

func (s *Service) buildTask(p taskPlan, acceptedEventID string) TaskRecord {
	in, cluster, definition := p.input, p.cluster, p.definition
	now := s.clock.Now().Truncate(time.Millisecond)
	key := TaskKey{ClusterKey: cluster.Key, ID: strings.ReplaceAll(uuid.NewString(), "-", "")}
	group := value(in.Group)
	if group == "" {
		group = "family:" + definition.Key.Family
	}
	record := TaskRecord{Key: key, Definition: definition.Data, NetworkConfiguration: api.CloneAwsVpcConfiguration(*in.NetworkConfiguration.AwsvpcConfiguration), AcceptedEventID: acceptedEventID, CredentialToken: rand.Text(), MetadataTokens: map[string]string{}, LogCursors: map[string]time.Time{}, DependencyWaitStarted: map[string]time.Time{}}
	record.Data = api.Task{TaskArn: new(api.String(key.ARN())), ClusterArn: new(api.String(cluster.Key.ARN())), TaskDefinitionArn: definition.Data.TaskDefinitionArn, CreatedAt: new(now), Cpu: new(api.String(p.cpu)), Memory: new(api.String(p.memory)), DesiredStatus: new(api.String("RUNNING")), LastStatus: new(api.String("PROVISIONING")), LaunchType: new(api.LaunchType("FARGATE")), PlatformFamily: new(api.String("Linux")), PlatformVersion: new(api.String(p.platform)), EnableExecuteCommand: new(api.Boolean(false)), Group: new(api.String(group)), StartedBy: in.StartedBy, Overrides: new(api.CloneTaskOverride(p.overrides)), Version: new(api.Long(1)), AvailabilityZone: new(api.String(p.placement.AvailabilityZone)), Containers: api.Containers{}, Attachments: api.Attachments{{Id: new(api.String(uuid.NewString())), Type: new(api.String("ElasticNetworkInterface")), Status: new(api.String("PRECREATED")), Details: api.AttachmentDetails{{Name: new(api.String("subnetId")), Value: new(api.String(p.placement.SubnetID))}}}}}
	if p.provider != "" {
		record.Data.CapacityProviderName = new(api.String(p.provider))
	}
	architecture := "x86_64"
	if definition.Data.RuntimePlatform != nil && value(definition.Data.RuntimePlatform.CpuArchitecture) == "ARM64" {
		architecture = "arm64"
	}
	record.Data.Attributes = api.Attributes{{Name: new(api.String("ecs.cpu-architecture")), Value: new(api.String(architecture))}}
	for _, container := range effectiveTaskContainers(record) {
		name := value(container.Name)
		record.MetadataTokens[name] = rand.Text()
		data := api.Container{ContainerArn: new(api.String("arn:" + key.Partition + ":ecs:" + key.Region + ":" + key.AccountID + ":container/" + key.Name + "/" + key.ID + "/" + uuid.NewString())), TaskArn: record.Data.TaskArn, Name: container.Name, Image: container.Image, LastStatus: new(api.String("PENDING")), Cpu: new(api.String(strconv.FormatInt(int64(*container.Cpu), 10))), NetworkInterfaces: api.NetworkInterfaces{}}
		if container.Memory != nil {
			data.Memory = new(api.String(strconv.FormatInt(int64(*container.Memory), 10)))
		}
		if container.MemoryReservation != nil {
			data.MemoryReservation = new(api.String(strconv.FormatInt(int64(*container.MemoryReservation), 10)))
		}
		record.Data.Containers = append(record.Data.Containers, data)
	}
	return record
}

func (s *Service) acceptTask(ctx context.Context, tx Transaction, record TaskRecord, tags api.Tags, managed bool, serviceName string) error {
	tags = api.CloneTags(tags)
	if managed {
		tags = append(tags, api.Tag{Key: new(api.TagKey("aws:ecs:clusterName")), Value: new(api.TagValue(record.Key.Name))})
		if serviceName != "" {
			tags = append(tags, api.Tag{Key: new(api.TagKey("aws:ecs:serviceName")), Value: new(api.TagValue(serviceName))})
		}
	}
	if err := tx.PutTask(record); err != nil {
		return err
	}
	if err := s.publishTaskEvent(ctx, record); err != nil {
		return err
	}
	return tx.PutTags(TagRecord{Key: TagKey{Scope: record.Key.Scope, ResourceARN: record.Key.ARN()}, Tags: tags})
}
