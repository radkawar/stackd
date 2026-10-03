package ecs

import (
	"context"
	"errors"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
)

// ServiceRevisionKey uses the native revision identity, which shares the numeric
// suffix of the ecs-svc deployment ID, not the whole deployment ID.
type ServiceRevisionKey struct {
	ServiceKey
	ID string
}

func (k ServiceRevisionKey) ARN() string {
	return "arn:" + k.Partition + ":ecs:" + k.Region + ":" + k.AccountID + ":service-revision/" + k.Name + "/" + k.ServiceName + "/" + k.ID
}

// ServiceRevisionRecord archives only revisions whose execution snapshot has
// relinquished task/rollback ownership. Active revisions use that snapshot.
type ServiceRevisionRecord struct {
	Key  ServiceRevisionKey
	Data api.ServiceRevision
}

func deploymentRevisionKey(key ServiceKey, id string) ServiceRevisionKey {
	return ServiceRevisionKey{ServiceKey: key, ID: strings.TrimPrefix(id, "ecs-svc/")}
}

func serviceRevisionKey(ctx context.Context, arn string) (ServiceRevisionKey, *awswire.Error) {
	scope, path, rejected := resourceID(ctx, arn, "service-revision")
	parts := strings.Split(path, "/")
	if rejected != nil || !strings.HasPrefix(arn, "arn:") || len(parts) != 3 || !resourceName.MatchString(parts[0]) || !resourceName.MatchString(parts[1]) {
		return ServiceRevisionKey{}, failure("InvalidParameterException", "The ServiceRevision ARN is invalid.")
	}
	if _, err := strconv.ParseUint(parts[2], 10, 64); err != nil || strings.HasPrefix(parts[2], "+") {
		return ServiceRevisionKey{}, failure("InvalidParameterException", "The ServiceRevision ARN is invalid.")
	}
	return ServiceRevisionKey{ServiceKey: ServiceKey{ClusterKey: ClusterKey{Scope: scope, Name: parts[0]}, ServiceName: parts[1]}, ID: parts[2]}, nil
}

func serviceRevision(record ServiceRecord, deployment ServiceDeployment) ServiceRevisionRecord {
	key := deploymentRevisionKey(record.Key, value(deployment.Data.Id))
	data := api.ServiceRevision{
		ServiceRevisionArn: new(api.String(key.ARN())), ServiceArn: new(api.String(record.Key.ARN())),
		ClusterArn: new(api.String(record.Key.ClusterKey.ARN())), TaskDefinition: deployment.Data.TaskDefinition,
		CreatedAt: deployment.Data.CreatedAt, LaunchType: deployment.Data.LaunchType,
		CapacityProviderStrategy: deployment.Data.CapacityProviderStrategy,
		PlatformFamily:           deployment.Data.PlatformFamily, PlatformVersion: deployment.Data.PlatformVersion,
		NetworkConfiguration:        deployment.Data.NetworkConfiguration,
		FargateEphemeralStorage:     deployment.Data.FargateEphemeralStorage,
		ServiceConnectConfiguration: deployment.Data.ServiceConnectConfiguration,
		VolumeConfigurations:        deployment.Data.VolumeConfigurations, VpcLatticeConfigurations: deployment.Data.VpcLatticeConfigurations,
		Monitoring: deployment.Monitoring, GuardDutyEnabled: new(api.Boolean(false)),
		LoadBalancers: api.CloneLoadBalancers(deployment.LoadBalancers),
	}
	data.ContainerImages = make(api.ContainerImages, len(deployment.Definition.ContainerDefinitions))
	for i, container := range deployment.Definition.ContainerDefinitions {
		image := api.ContainerImage{ContainerName: container.Name, Image: container.Image}
		// TODO: Comeback retain observed registry digests for public service revisions;
		// ResolvedImages owns engine image IDs, not registry digests.
		data.ContainerImages[i] = image
	}
	return ServiceRevisionRecord{Key: key, Data: data}
}

func (s *Service) DescribeServiceRevisions(ctx context.Context, in *api.DescribeServiceRevisionsInput) (*api.DescribeServiceRevisionsOutput, *awswire.Error) {
	return runCommand(s, ctx, "DescribeServiceRevisions", in, s.describeServiceRevisions)
}

func (s *Service) describeServiceRevisions(ctx context.Context, tx Transaction, in *api.DescribeServiceRevisionsInput) (*api.DescribeServiceRevisionsOutput, error) {
	if len(in.ServiceRevisionArns) == 0 {
		return nil, failure("InvalidParameterException", "The Service ARN provided is invalid.")
	}
	if len(in.ServiceRevisionArns) > 20 {
		return nil, failure("InvalidParameterException", "Service Revision ARN count cannot exceed 20")
	}
	keys := make([]ServiceRevisionKey, len(in.ServiceRevisionArns))
	for i, arn := range in.ServiceRevisionArns {
		key, rejected := serviceRevisionKey(ctx, string(arn))
		if rejected != nil {
			return nil, rejected
		}
		if i != 0 && key.ServiceKey != keys[0].ServiceKey {
			return nil, failure("InvalidParameterException", "Cross service requests are not allowed. All requested service revisions must be for a single service")
		}
		keys[i] = key
	}
	owner := keys[0].ServiceKey
	tags, err := tagsFor(tx, owner.Scope, owner.ARN())
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := s.authorize(ctx, "DescribeServiceRevisions", key.ARN(), tags, map[string][]string{"ecs:cluster": {owner.ClusterKey.ARN()}, "ecs:service": {owner.ARN()}}); err != nil {
			return nil, err
		}
	}
	if _, err := taskCluster(ctx, tx, owner.ClusterKey.ARN()); err != nil {
		return nil, err
	}
	record, err := tx.Service(owner)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ServiceNotFoundException", "Service not found.")
	}
	if err != nil {
		return nil, err
	}
	if value(record.Data.Status) == "INACTIVE" {
		return nil, failure("InvalidParameterException", "Cannot call DescribeServiceRevisions for a service that is INACTIVE")
	}
	out := &api.DescribeServiceRevisionsOutput{ServiceRevisions: api.ServiceRevisions{}, Failures: api.Failures{}}
	found := make(map[ServiceRevisionKey]bool, len(keys))
	for _, key := range keys {
		var revision ServiceRevisionRecord
		err := ErrNotFound
		for _, deployment := range record.Deployments {
			if deploymentRevisionKey(owner, value(deployment.Data.Id)) == key {
				revision, err = serviceRevision(record, deployment), nil
				break
			}
		}
		if errors.Is(err, ErrNotFound) {
			revision, err = tx.ServiceRevision(key)
		}
		if errors.Is(err, ErrNotFound) {
			out.Failures = append(out.Failures, api.Failure{Arn: new(api.String(key.ARN())), Reason: new(api.String("MISSING"))})
			continue
		}
		if err != nil {
			return nil, err
		}
		// Native duplicate existing revisions fail the whole batch; duplicate
		// missing revisions instead retain one MISSING result per input.
		if found[key] {
			return nil, failure("ServerException", "Service Unavailable. Please try again later.", 500)
		}
		found[key] = true
		out.ServiceRevisions = append(out.ServiceRevisions, revision.Data)
	}
	return out, nil
}

// HighResolutionReady consumes exactly the authorized and audited public read
// commands. An admitted monitoring update is not ready until its deployment has
// completed; task count zero is not a substitute for deployment completion.
func (s *Service) HighResolutionReady(ctx context.Context, in *api.DescribeServicesInput, metricName string) (bool, *awswire.Error) {
	if in == nil || len(in.Services) != 1 {
		return false, failure("InvalidParameterException", "High-resolution readiness requires one ECS service.")
	}
	if metricName != "CPUUtilization" && metricName != "MemoryUtilization" {
		return false, failure("InvalidParameterException", "Unsupported ECS service metric.")
	}
	services, rejected := s.DescribeServices(ctx, in)
	if rejected != nil {
		return false, rejected
	}
	if len(services.Services) != 1 || value(services.Services[0].Status) != "ACTIVE" {
		return false, nil
	}
	service := services.Services[0]
	for _, deployment := range service.Deployments {
		if value(deployment.Status) != "PRIMARY" {
			continue
		}
		arn := strings.Replace(value(service.ServiceArn), ":service/", ":service-revision/", 1) + "/" + strings.TrimPrefix(value(deployment.Id), "ecs-svc/")
		revisions, rejected := s.DescribeServiceRevisions(ctx, &api.DescribeServiceRevisionsInput{ServiceRevisionArns: api.StringList{api.String(arn)}})
		if rejected != nil {
			return false, rejected
		}
		return value(deployment.RolloutState) == "COMPLETED" && len(revisions.ServiceRevisions) == 1 && serviceMetricResolution(revisions.ServiceRevisions[0].Monitoring, metricName) == 20, nil
	}
	return false, nil
}
