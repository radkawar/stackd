package ecs

import (
	"context"
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
)

func serviceOutput(record ServiceRecord, tags api.Tags) api.Service {
	data := api.CloneService(record.Data)
	data.Tags = api.CloneTags(tags)
	data.Deployments = api.Deployments{}
	for _, deployment := range record.Deployments {
		if value(deployment.Data.Status) == "INACTIVE" {
			continue
		}
		data.Deployments = append(data.Deployments, api.CloneDeployment(deployment.Data))
	}
	return data
}

func (s *Service) newServiceDeployment(ctx context.Context, record ServiceRecord, definition TaskDefinitionRecord, monitoring *api.MonitoringConfiguration) ServiceDeployment {
	now := s.clock.Now().Truncate(time.Millisecond)
	id := "ecs-svc/" + strconv.FormatUint(rand.Uint64(), 10)
	input := serviceTaskInput(record)
	input.StartedBy = new(api.String(id))
	// LATEST resolves at admission, not when a replacement task is scheduled.
	if value(input.PlatformVersion) == "LATEST" || input.PlatformVersion == nil {
		input.PlatformVersion = new(api.String("1.4.0"))
	}
	data := api.Deployment{Id: new(api.String(id)), Status: new(api.String("PRIMARY")), TaskDefinition: definition.Data.TaskDefinitionArn,
		DesiredCount: record.Data.DesiredCount, PendingCount: new(api.Integer(0)), RunningCount: new(api.Integer(0)), FailedTasks: new(api.Integer(0)),
		CreatedAt: new(now), UpdatedAt: new(now), LaunchType: input.LaunchType, CapacityProviderStrategy: input.CapacityProviderStrategy,
		PlatformVersion: input.PlatformVersion, PlatformFamily: new(api.String("Linux")), NetworkConfiguration: input.NetworkConfiguration,
		RolloutState: new(api.DeploymentRolloutState("IN_PROGRESS")), RolloutStateReason: new(api.String("ECS deployment " + id + " in progress."))}
	// There is no observed native wall-clock deployment deadline. Failure counting
	// and container health govern progress; do not invent a timeout.
	return ServiceDeployment{Data: data, Definition: api.CloneTaskDefinition(definition.Data), Input: input, Monitoring: cloneServiceMonitoring(monitoring), LoadBalancers: api.CloneLoadBalancers(record.Data.LoadBalancers), AcceptedEventID: apievents.EventID(ctx), ObservedTasks: map[string]string{}}
}

func (s *Service) createService(ctx context.Context, tx Transaction, in *api.CreateServiceInput) (*api.CreateServiceOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	name := value(in.ServiceName)
	if !resourceName.MatchString(name) {
		return nil, failure("InvalidParameterException", "Invalid service name.")
	}
	key, rejected := serviceKey(ctx, cluster.Key, name)
	if rejected != nil {
		return nil, rejected
	}
	tags, conditions, rejected := admitTags(in.Tags, "InvalidParameterException")
	if rejected != nil {
		return nil, rejected
	}
	definition, err := serviceDefinition(ctx, tx, value(in.TaskDefinition))
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().Truncate(time.Millisecond)
	record := ServiceRecord{Key: key, CreateInput: api.CloneCreateServiceRequest(*in), AcceptedEventID: apievents.EventID(ctx)}
	record.Data = api.Service{ServiceArn: new(api.String(key.ARN())), ServiceName: new(api.String(name)), ClusterArn: new(api.String(cluster.Key.ARN())),
		Status: new(api.String("ACTIVE")), TaskDefinition: definition.Data.TaskDefinitionArn, CreatedAt: new(now), CreatedBy: new(api.String(awsctx.FromContext(ctx).PrincipalARN)),
		RunningCount: new(api.Integer(0)), PendingCount: new(api.Integer(0)), LaunchType: in.LaunchType, CapacityProviderStrategy: api.CloneCapacityProviderStrategy(in.CapacityProviderStrategy),
		NetworkConfiguration: in.NetworkConfiguration, PlatformVersion: in.PlatformVersion, PlatformFamily: new(api.String("Linux")),
		EnableECSManagedTags: in.EnableECSManagedTags, EnableExecuteCommand: in.EnableExecuteCommand, PropagateTags: in.PropagateTags,
		HealthCheckGracePeriodSeconds: in.HealthCheckGracePeriodSeconds, SchedulingStrategy: in.SchedulingStrategy, DeploymentController: in.DeploymentController,
		AvailabilityZoneRebalancing: in.AvailabilityZoneRebalancing, ResourceManagementType: new(api.ResourceManagementType("CUSTOMER")),
		LoadBalancers: api.CloneLoadBalancers(in.LoadBalancers), ServiceRegistries: api.ServiceRegistries{}, PlacementConstraints: api.PlacementConstraints{}, PlacementStrategy: api.PlacementStrategies{}, Events: api.ServiceEvents{},
		RoleArn: new(api.String("arn:" + key.Partition + ":iam::" + key.AccountID + ":role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"))}
	data := &record.Data
	if data.LoadBalancers == nil {
		data.LoadBalancers = api.LoadBalancers{}
	}
	if in.DesiredCount != nil {
		data.DesiredCount = new(api.Integer(*in.DesiredCount))
	}
	if data.LaunchType == nil && len(data.CapacityProviderStrategy) == 0 {
		data.CapacityProviderStrategy = api.CloneCapacityProviderStrategy(cluster.Data.DefaultCapacityProviderStrategy)
		if len(data.CapacityProviderStrategy) == 0 {
			data.LaunchType = new(api.LaunchType("FARGATE"))
		}
	}
	if data.PlatformVersion == nil {
		data.PlatformVersion = new(api.String("LATEST"))
	}
	if data.EnableECSManagedTags == nil {
		data.EnableECSManagedTags = new(api.Boolean(false))
	}
	if data.EnableExecuteCommand == nil {
		data.EnableExecuteCommand = new(api.Boolean(false))
	}
	if data.PropagateTags == nil {
		data.PropagateTags = new(api.PropagateTags("NONE"))
	}
	if data.HealthCheckGracePeriodSeconds == nil {
		data.HealthCheckGracePeriodSeconds = new(api.BoxedInteger(0))
	}
	if data.SchedulingStrategy == nil {
		data.SchedulingStrategy = new(api.SchedulingStrategy("REPLICA"))
	}
	if data.DeploymentController == nil {
		data.DeploymentController = &api.DeploymentController{Type: new(api.DeploymentControllerType("ECS"))}
	}
	if data.AvailabilityZoneRebalancing == nil {
		rebalancing := api.AvailabilityZoneRebalancing("ENABLED")
		// Native creation disables rebalancing when the requested deployment
		// cannot exceed desired capacity; an explicit ENABLED still rejects.
		if in.DeploymentConfiguration != nil && in.DeploymentConfiguration.MaximumPercent != nil && *in.DeploymentConfiguration.MaximumPercent <= 100 {
			rebalancing = "DISABLED"
		}
		data.AvailabilityZoneRebalancing = &rebalancing
	}
	for condition, values := range serviceConditions(*data) {
		conditions[condition] = values
	}
	existingTags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "CreateService", key.ARN(), existingTags, conditions); err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		conditions["ecs:CreateAction"] = []string{"CreateService"}
		if err := s.authorize(ctx, "TagResource", key.ARN(), existingTags, conditions); err != nil {
			return nil, err
		}
	}
	if len(value(in.ClientToken)) > 36 {
		return nil, failure("InvalidParameterException", "idempotency token longer than 36.")
	}
	if value(definition.Data.NetworkMode) == "awsvpc" && (in.NetworkConfiguration == nil || in.NetworkConfiguration.AwsvpcConfiguration == nil) {
		return nil, failure("InvalidParameterException", "Network Configuration must be provided when networkMode 'awsvpc' is specified.")
	}
	switch value(data.SchedulingStrategy) {
	case "REPLICA":
		if data.DesiredCount == nil {
			return nil, failure("InvalidParameterException", "DesiredCount is missing")
		}
	case "DAEMON":
		if in.DesiredCount != nil {
			return nil, failure("InvalidParameterException", "The daemon scheduling strategy does not support a desired count for services. Remove the desired count value and try again")
		}
		if value(data.LaunchType) == "FARGATE" || len(data.CapacityProviderStrategy) > 0 {
			return nil, failure("InvalidParameterException", "The daemon scheduling strategy does not support the FARGATE launch type. Change the launch type and try again")
		}
		// TODO: Comeback implement DAEMON scheduling with container-instance execution.
		return nil, unsupported("Only the REPLICA scheduling strategy has a configured service lifecycle.")
	default:
		return nil, failure("InvalidParameterException", "Scheduling strategy should be one of [REPLICA,DAEMON]")
	}
	if *data.DesiredCount < 0 {
		return nil, failure("InvalidParameterException", "DesiredCount can not be lesser than 0")
	}
	data.DeploymentConfiguration, err = mergeServiceDeploymentConfiguration(nil, in.DeploymentConfiguration)
	if err != nil {
		return nil, err
	}
	if err := validateServiceConfiguration(*data); err != nil {
		return nil, err
	}
	monitoring, err := serviceMonitoring(in.Monitoring, false)
	if err != nil {
		return nil, err
	}
	// TODO: Comeback connect discovery, service networking and volumes.
	if len(in.ServiceRegistries) > 0 || in.ServiceConnectConfiguration != nil || len(in.VolumeConfigurations) > 0 || len(in.VpcLatticeConfigurations) > 0 || len(in.PlacementConstraints) > 0 || len(in.PlacementStrategy) > 0 || in.Role != nil || cluster.Data.ServiceConnectDefaults != nil {
		return nil, unsupported("Service discovery, Service Connect, volumes, VPC Lattice, placement and custom service roles require their execution dependencies.")
	}
	if err := validateServiceCapacity(data.CapacityProviderStrategy); err != nil {
		return nil, err
	}
	if err := s.validateServiceExecution(ctx, cluster, record, definition); err != nil {
		return nil, err
	}
	old, err := tx.Service(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil && value(old.Data.Status) == "DRAINING" {
		return nil, failure("InvalidParameterException", "Unable to Start a service that is still Draining.")
	}
	if err == nil && value(old.Data.Status) == "ACTIVE" {
		previous, requested := old.CreateInput, *in
		previous.Tags, requested.Tags = nil, nil
		if value(in.ClientToken) == "" || !reflect.DeepEqual(previous, requested) {
			return nil, failure("InvalidParameterException", "Creation of service was not idempotent.")
		}
		if err := s.ensureReplicaRole(ctx); err != nil {
			return nil, err
		}
		storedTags, err := tagsFor(tx, key.Scope, key.ARN())
		if err != nil {
			return nil, err
		}
		out := serviceOutput(old, storedTags)
		return &api.CreateServiceOutput{Service: &out}, nil
	}
	if err := s.ensureReplicaRole(ctx); err != nil {
		return nil, err
	}
	if err := s.validateServiceLoadBalancers(ctx, record, definition.Data); err != nil {
		return nil, err
	}
	record.Deployments = []ServiceDeployment{s.newServiceDeployment(ctx, record, definition, monitoring)}
	deployment := record.Deployments[0].Data
	if err := s.publishServiceEvent(ctx, &record, "SERVICE_DEPLOYMENT_IN_PROGRESS", value(deployment.Id), value(deployment.RolloutStateReason)); err != nil {
		return nil, err
	}
	if err := s.putService(tx, record); err != nil {
		return nil, err
	}
	if err := tx.PutTags(TagRecord{Key: TagKey{Scope: key.Scope, ResourceARN: key.ARN()}, Tags: tags}); err != nil {
		return nil, err
	}
	out := serviceOutput(record, tags)
	return &api.CreateServiceOutput{Service: &out}, nil
}

func (s *Service) describeServices(ctx context.Context, tx Transaction, in *api.DescribeServicesInput) (*api.DescribeServicesOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	if len(in.Services) == 0 || len(in.Services) > 10 {
		return nil, failure("InvalidParameterException", "services must contain between 1 and 10 entries.")
	}
	for _, include := range in.Include {
		if include != "TAGS" {
			return nil, failure("InvalidParameterException", "include should be one of [TAGS]")
		}
	}
	out := &api.DescribeServicesOutput{Services: api.Services{}, Failures: api.Failures{}}
	seen := map[ServiceKey]bool{}
	for _, id := range in.Services {
		key, rejected := serviceKey(ctx, cluster.Key, string(id))
		if rejected != nil {
			return nil, rejected
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		tags, err := tagsFor(tx, key.Scope, key.ARN())
		if err != nil {
			return nil, err
		}
		if err := s.authorize(ctx, "DescribeServices", key.ARN(), tags, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}}); err != nil {
			return nil, err
		}
		record, err := tx.Service(key)
		if errors.Is(err, ErrNotFound) {
			out.Failures = append(out.Failures, api.Failure{Arn: new(api.String(key.ARN())), Reason: new(api.String("MISSING"))})
			continue
		}
		if err != nil {
			return nil, err
		}
		if !slices.Contains(in.Include, api.ServiceField("TAGS")) {
			tags = nil
		}
		out.Services = append(out.Services, serviceOutput(record, tags))
	}
	return out, nil
}

func (s *Service) listServices(ctx context.Context, tx Transaction, in *api.ListServicesInput) (*api.ListServicesOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ListServices", "*", nil, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}}); err != nil {
		return nil, err
	}
	switch value(in.LaunchType) {
	case "", "EC2", "FARGATE", "EXTERNAL", "FMI", "MANAGED_INSTANCES":
	default:
		return nil, failure("InvalidParameterException", "launch type should be one of [EC2,FARGATE,EXTERNAL,FMI,MANAGED_INSTANCES]")
	}
	switch value(in.SchedulingStrategy) {
	case "", "REPLICA", "DAEMON":
	default:
		return nil, failure("InvalidParameterException", "Scheduling strategy should be one of [REPLICA,DAEMON]")
	}
	switch value(in.ResourceManagementType) {
	case "", "CUSTOMER", "ECS":
	default:
		return nil, failure("InvalidParameterException", "Invalid resource management type.")
	}
	limit, rejected := pageSize(in.MaxResults)
	if rejected != nil {
		return nil, rejected
	}
	identity := collection(cluster.Key.Scope, "services", cluster.Key.Name, value(in.LaunchType), value(in.SchedulingStrategy), value(in.ResourceManagementType))
	after, rejected := page(in.NextToken, identity)
	if rejected != nil {
		return nil, rejected
	}
	out := &api.ListServicesOutput{ServiceArns: api.StringList{}}
	if value(in.ResourceManagementType) == "ECS" {
		return out, nil
	}
	rows, err := tx.Services(ServiceQuery{ClusterKey: cluster.Key, After: after, Limit: limit + 1, LaunchType: value(in.LaunchType), SchedulingStrategy: value(in.SchedulingStrategy)})
	if err != nil {
		return nil, err
	}
	if len(rows) > limit {
		rows = rows[:limit]
		out.NextToken = nextPage(identity, rows[len(rows)-1].Key.ServiceName)
	}
	for _, row := range rows {
		out.ServiceArns = append(out.ServiceArns, api.String(row.Key.ARN()))
	}
	return out, nil
}

func (s *Service) updateService(ctx context.Context, tx Transaction, in *api.UpdateServiceInput) (*api.UpdateServiceOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	key, rejected := serviceKey(ctx, cluster.Key, value(in.Service))
	if rejected != nil {
		return nil, rejected
	}
	tags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return nil, err
	}
	record, err := tx.Service(key)
	if errors.Is(err, ErrNotFound) {
		if err := s.authorize(ctx, "UpdateService", key.ARN(), tags, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}}); err != nil {
			return nil, err
		}
		return nil, failure("ServiceNotFoundException", "Service not found.")
	}
	if err != nil {
		return nil, err
	}
	data := &record.Data
	old := api.CloneService(*data)
	if in.DesiredCount != nil {
		data.DesiredCount = new(api.Integer(*in.DesiredCount))
	}
	if in.LoadBalancers != nil {
		data.LoadBalancers = api.CloneLoadBalancers(in.LoadBalancers)
	}
	if in.NetworkConfiguration != nil {
		data.NetworkConfiguration = in.NetworkConfiguration
	}
	if in.PlatformVersion != nil {
		data.PlatformVersion = in.PlatformVersion
	}
	if in.CapacityProviderStrategy != nil {
		data.CapacityProviderStrategy = api.CloneCapacityProviderStrategy(in.CapacityProviderStrategy)
		data.LaunchType = nil
		if len(data.CapacityProviderStrategy) == 0 {
			data.LaunchType = new(api.LaunchType("FARGATE"))
		}
	}
	if in.PropagateTags != nil {
		data.PropagateTags = in.PropagateTags
	}
	if in.EnableECSManagedTags != nil {
		data.EnableECSManagedTags = new(api.Boolean(*in.EnableECSManagedTags))
	}
	if in.EnableExecuteCommand != nil {
		data.EnableExecuteCommand = new(api.Boolean(*in.EnableExecuteCommand))
	}
	if in.HealthCheckGracePeriodSeconds != nil {
		data.HealthCheckGracePeriodSeconds = in.HealthCheckGracePeriodSeconds
	}
	if in.AvailabilityZoneRebalancing != nil {
		data.AvailabilityZoneRebalancing = in.AvailabilityZoneRebalancing
	}
	if in.DeploymentController != nil {
		data.DeploymentController = in.DeploymentController
	}
	var definition TaskDefinitionRecord
	if in.TaskDefinition != nil {
		definition, err = serviceDefinition(ctx, tx, value(in.TaskDefinition))
		if err != nil {
			return nil, err
		}
		data.TaskDefinition = definition.Data.TaskDefinitionArn
	} else {
		// Existing services remain scalable after task-definition deregistration.
		// Never re-resolve an unqualified family name during an update or launch.
		for _, deployment := range record.Deployments {
			if value(deployment.Data.Status) == "PRIMARY" {
				definition.Data = api.CloneTaskDefinition(deployment.Definition)
				break
			}
		}
		definition.Key, rejected = definitionKey(ctx, value(data.TaskDefinition), false)
		if rejected != nil {
			return nil, rejected
		}
	}
	if err := s.authorize(ctx, "UpdateService", key.ARN(), tags, serviceConditions(*data)); err != nil {
		return nil, err
	}
	if value(data.Status) != "ACTIVE" {
		return nil, failure("ServiceNotActiveException", "Service was not ACTIVE.")
	}
	if *data.DesiredCount < 0 {
		return nil, failure("InvalidParameterException", "Task count can not be lesser than 0")
	}
	data.DeploymentConfiguration, err = mergeServiceDeploymentConfiguration(data.DeploymentConfiguration, in.DeploymentConfiguration)
	if err != nil {
		return nil, err
	}
	if err := validateServiceConfiguration(*data); err != nil {
		return nil, err
	}
	var monitoring *api.MonitoringConfiguration
	for _, deployment := range record.Deployments {
		if value(deployment.Data.Status) == "PRIMARY" {
			monitoring = deployment.Monitoring
			break
		}
	}
	monitoringChanged := false
	if in.Monitoring != nil {
		selected, err := serviceMonitoring(in.Monitoring, true)
		if err != nil {
			return nil, err
		}
		monitoringChanged = !reflect.DeepEqual(monitoring, selected)
		monitoring = selected
	}
	// TODO: Comeback update the external service dependencies rejected at creation.
	if len(in.ServiceRegistries) > 0 || in.ServiceConnectConfiguration != nil || len(in.VolumeConfigurations) > 0 || len(in.VpcLatticeConfigurations) > 0 || len(in.PlacementConstraints) > 0 || len(in.PlacementStrategy) > 0 {
		return nil, unsupported("Service discovery, Service Connect, volumes, VPC Lattice and placement require their execution dependencies.")
	}
	if err := validateServiceCapacity(data.CapacityProviderStrategy); err != nil {
		return nil, err
	}
	if err := s.validateServiceExecution(ctx, cluster, record, definition); err != nil {
		return nil, err
	}
	if err := s.ensureReplicaRole(ctx); err != nil {
		return nil, err
	}
	if err := s.validateServiceLoadBalancers(ctx, record, definition.Data); err != nil {
		return nil, err
	}
	record.AcceptedEventID = apievents.EventID(ctx)
	newDeployment := monitoringChanged || in.ForceNewDeployment != nil && bool(*in.ForceNewDeployment) || value(old.TaskDefinition) != value(data.TaskDefinition) || !reflect.DeepEqual(old.NetworkConfiguration, data.NetworkConfiguration) || value(old.PlatformVersion) != value(data.PlatformVersion) || !reflect.DeepEqual(old.CapacityProviderStrategy, data.CapacityProviderStrategy) || value(old.LaunchType) != value(data.LaunchType) || !reflect.DeepEqual(old.LoadBalancers, data.LoadBalancers)
	if newDeployment {
		now := s.clock.Now().Truncate(time.Millisecond)
		for i := range record.Deployments {
			if value(record.Deployments[i].Data.Status) == "PRIMARY" {
				record.Deployments[i].Data.Status = new(api.String("ACTIVE"))
				record.Deployments[i].Data.UpdatedAt = new(now)
			}
		}
		deployment := s.newServiceDeployment(ctx, record, definition, monitoring)
		record.Deployments = append([]ServiceDeployment{deployment}, record.Deployments...)
		if err := s.publishServiceEvent(ctx, &record, "SERVICE_DEPLOYMENT_IN_PROGRESS", value(deployment.Data.Id), value(deployment.Data.RolloutStateReason)); err != nil {
			return nil, err
		}
	} else {
		for i := range record.Deployments {
			if value(record.Deployments[i].Data.Status) == "PRIMARY" {
				record.Deployments[i].Data.DesiredCount = data.DesiredCount
				record.Deployments[i].AcceptedEventID = record.AcceptedEventID
			}
		}
	}
	if err := s.putService(tx, record); err != nil {
		return nil, err
	}
	out := serviceOutput(record, nil)
	return &api.UpdateServiceOutput{Service: &out}, nil
}

func (s *Service) deleteService(ctx context.Context, tx Transaction, in *api.DeleteServiceInput) (*api.DeleteServiceOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	key, rejected := serviceKey(ctx, cluster.Key, value(in.Service))
	if rejected != nil {
		return nil, rejected
	}
	tags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteService", key.ARN(), tags, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}}); err != nil {
		return nil, err
	}
	record, err := tx.Service(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ServiceNotFoundException", "")
	}
	if err != nil {
		return nil, err
	}
	if value(record.Data.Status) == "ACTIVE" {
		if record.Data.DesiredCount != nil && *record.Data.DesiredCount > 0 && (in.Force == nil || !bool(*in.Force)) {
			return nil, failure("InvalidParameterException", "The service cannot be stopped while it is scaled above 0.")
		}
		record.Data.Status = new(api.String("DRAINING"))
		record.Data.DesiredCount = new(api.Integer(0))
		record.AcceptedEventID = apievents.EventID(ctx)
		// Native capture proves asynchronous DRAINING, not its terminal duration.
		// One service-clock tick exposes that state before local reconciliation;
		// actual task shutdown must also finish before the service is INACTIVE.
		record.DrainAfter = s.clock.Now().Add(time.Second)
		for i := range record.Deployments {
			record.Deployments[i].Data.DesiredCount = new(api.Integer(0))
		}
		if err := s.putService(tx, record); err != nil {
			return nil, err
		}
	}
	out := serviceOutput(record, nil)
	return &api.DeleteServiceOutput{Service: &out}, nil
}
