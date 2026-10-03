package ecs

import (
	"context"
	"errors"
	"reflect"
	"slices"
	api "stackd/internal/awsapi/ecs"
	"strconv"
)

func (s *Service) createCluster(ctx context.Context, tx Transaction, in *api.CreateClusterInput) (*api.CreateClusterOutput, error) {
	key, rejected := clusterKey(ctx, value(in.ClusterName))
	if rejected != nil {
		return nil, rejected
	}
	tags, conditions, rejected := admitTags(in.Tags, "InvalidParameterException")
	if rejected != nil {
		return nil, rejected
	}
	for _, provider := range in.CapacityProviders {
		conditions["ecs:capacity-provider"] = append(conditions["ecs:capacity-provider"], string(provider))
	}
	if err := s.authorize(ctx, "CreateCluster", key.ARN(), nil, conditions); err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		conditions["ecs:CreateAction"] = []string{"CreateCluster"}
		if err := s.authorize(ctx, "TagResource", key.ARN(), nil, conditions); err != nil {
			return nil, err
		}
	}
	admitted := api.CloneCreateClusterRequest(*in)
	admitted.ClusterName = new(api.String(key.Name))
	admitted.Tags = tags
	if err := validateClusterConfiguration(admitted.Configuration, admitted.ServiceConnectDefaults); err != nil {
		return nil, err
	}
	if err := validateSettings(admitted.Settings); err != nil {
		return nil, err
	}
	if len(admitted.Settings) == 0 {
		admitted.Settings = api.ClusterSettings{{Name: new(api.ClusterSettingName("containerInsights")), Value: new(api.String("disabled"))}}
	}
	if admitted.DefaultCapacityProviderStrategy == nil {
		admitted.DefaultCapacityProviderStrategy = api.CapacityProviderStrategy{}
	}
	if err := normalizeCapacityProviders(&admitted); err != nil {
		return nil, err
	}
	old, err := tx.Cluster(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil && value(old.Data.Status) == "ACTIVE" {
		original := old.CreateInput
		mismatch := in.Settings != nil && !reflect.DeepEqual(admitted.Settings, original.Settings) || in.Tags != nil && !equalTags(admitted.Tags, original.Tags) || in.Configuration != nil && !reflect.DeepEqual(admitted.Configuration, original.Configuration) || in.CapacityProviders != nil && !slices.Equal(admitted.CapacityProviders, original.CapacityProviders) || in.DefaultCapacityProviderStrategy != nil && !reflect.DeepEqual(admitted.DefaultCapacityProviderStrategy, original.DefaultCapacityProviderStrategy)
		if mismatch {
			return nil, failure("InvalidParameterException", "Arguments on this idempotent request are inconsistent with arguments used in previous request(s).")
		}
	}
	if err := s.ensureClusterRole(ctx); err != nil {
		return nil, err
	}
	if err == nil && value(old.Data.Status) == "ACTIVE" {
		// Create echoes the admitted creation arguments, not subsequently updated tags.
		data := newCluster(key, admitted)
		if err := projectActiveServices(tx, key, &data); err != nil {
			return nil, err
		}
		return &api.CreateClusterOutput{Cluster: &data, ClusterCount: new(api.Integer(1))}, nil
	}
	data := newCluster(key, admitted)
	data.Tags = nil
	now := s.clock.Now()
	if err := tx.PutCluster(ClusterRecord{Key: key, Data: data, CreateInput: admitted, Created: now, Updated: now}); err != nil {
		return nil, err
	}
	if err := tx.PutTags(TagRecord{TagKey{key.Scope, key.ARN()}, tags}); err != nil {
		return nil, err
	}
	data.Tags = api.CloneTags(tags)
	return &api.CreateClusterOutput{Cluster: &data, ClusterCount: new(api.Integer(1))}, nil
}
func newCluster(key ClusterKey, in api.CreateClusterInput) api.Cluster {
	settings := api.CloneClusterSettings(in.Settings)
	if len(settings) == 0 {
		settings = api.ClusterSettings{{Name: new(api.ClusterSettingName("containerInsights")), Value: new(api.String("disabled"))}}
	}
	providers := api.CloneStringList(in.CapacityProviders)
	if providers == nil {
		providers = api.StringList{}
	}
	strategy := api.CloneCapacityProviderStrategy(in.DefaultCapacityProviderStrategy)
	if strategy == nil {
		strategy = api.CapacityProviderStrategy{}
	}
	tags := api.CloneTags(in.Tags)
	if tags == nil {
		tags = api.Tags{}
	}
	return api.Cluster{ClusterArn: new(api.String(key.ARN())), ClusterName: new(api.String(key.Name)), Status: new(api.String("ACTIVE")), ActiveServicesCount: new(api.Integer(0)), PendingTasksCount: new(api.Integer(0)), RunningTasksCount: new(api.Integer(0)), RegisteredContainerInstancesCount: new(api.Integer(0)), Settings: settings, Statistics: api.Statistics{}, CapacityProviders: providers, DefaultCapacityProviderStrategy: strategy, Configuration: in.Configuration, Tags: tags}
}
func validateSettings(settings api.ClusterSettings) error {
	for _, setting := range settings {
		if value(setting.Name) != "containerInsights" {
			return failure("InvalidParameterException", "Invalid setting 'name'")
		}
		switch value(setting.Value) {
		case "enabled", "disabled", "enhanced":
		default:
			return failure("InvalidParameterException", "Invalid setting 'value'")
		}
	}
	return nil
}
func validateClusterConfiguration(config *api.ClusterConfiguration, connect *api.ClusterServiceConnectDefaultsRequest) error {
	if connect != nil {
		return unsupported("Service Connect requires a configured Cloud Map namespace dependency.")
	}
	if config == nil {
		return nil
	}
	if config.ManagedStorageConfiguration != nil {
		return unsupported("Managed cluster storage requires a configured KMS and volume dependency.")
	}
	if command := config.ExecuteCommandConfiguration; command != nil {
		switch value(command.Logging) {
		case "", "NONE", "DEFAULT", "OVERRIDE":
		default:
			return failure("InvalidParameterException", "Invalid execute command logging configuration.")
		}
		if command.KmsKeyId != nil {
			return unsupported("Execute command encryption requires a configured KMS dependency.")
		}
		if command.LogConfiguration != nil || value(command.Logging) == "OVERRIDE" {
			return unsupported("Execute command log destinations require configured Logs or S3 dependencies.")
		}
	}
	return nil
}
func normalizeCapacityProviders(in *api.CreateClusterInput) error {
	for _, provider := range in.CapacityProviders {
		if provider != "FARGATE" && provider != "FARGATE_SPOT" {
			return unsupported("Custom capacity providers require a configured Auto Scaling dependency.")
		}
	}
	var bases int
	for i := range in.DefaultCapacityProviderStrategy {
		item := &in.DefaultCapacityProviderStrategy[i]
		if !slices.Contains(in.CapacityProviders, api.String(value(item.CapacityProvider))) {
			return failure("InvalidParameterException", "The specified capacity provider is not associated with the cluster.")
		}
		if item.Base == nil {
			item.Base = new(api.CapacityProviderStrategyItemBase(0))
		}
		if item.Weight == nil {
			item.Weight = new(api.CapacityProviderStrategyItemWeight(0))
		}
		if *item.Base > 0 {
			bases++
		}
	}
	if bases > 1 {
		return failure("InvalidParameterException", "Only one capacity provider in a strategy can have a base defined.")
	}
	return nil
}
func (s *Service) describeClusters(ctx context.Context, tx Transaction, in *api.DescribeClustersInput) (*api.DescribeClustersOutput, error) {
	ids := in.Clusters
	if len(ids) == 0 {
		ids = api.StringList{"default"}
	}
	if len(ids) > 100 {
		return nil, failure("InvalidParameterException", "clusters can have at most 100 entries.")
	}
	out := &api.DescribeClustersOutput{Clusters: api.Clusters{}, Failures: api.Failures{}}
	seen := map[ClusterKey]bool{}
	for _, id := range ids {
		key, rejected := clusterKey(ctx, string(id))
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
		if err := s.authorize(ctx, "DescribeClusters", key.ARN(), tags, nil); err != nil {
			return nil, err
		}
		record, err := tx.Cluster(key)
		if errors.Is(err, ErrNotFound) {
			out.Failures = append(out.Failures, api.Failure{Arn: new(api.String(key.ARN())), Reason: new(api.String("MISSING"))})
			continue
		}
		if err != nil {
			return nil, err
		}
		data := record.Data
		if err := projectActiveServices(tx, key, &data); err != nil {
			return nil, err
		}
		data.Settings = api.ClusterSettings{}
		data.Tags = api.Tags{}
		data.Statistics = api.Statistics{}
		data.Configuration = nil
		data.Attachments = nil
		for _, include := range in.Include {
			switch include {
			case "SETTINGS":
				data.Settings = record.Data.Settings
			case "TAGS":
				data.Tags = tags
			case "CONFIGURATIONS":
				data.Configuration = record.Data.Configuration
			case "ATTACHMENTS":
				data.Attachments = api.Attachments{}
			case "STATISTICS":
				data.Statistics = clusterStatistics(record.Data)
			default:
				return nil, failure("InvalidParameterException", "include should be one of [ATTACHMENTS,CONFIGURATIONS,SETTINGS,STATISTICS,TAGS]")
			}
		}
		out.Clusters = append(out.Clusters, data)
	}
	return out, nil
}
func clusterStatistics(cluster api.Cluster) api.Statistics {
	out := api.Statistics{}
	for _, name := range []string{"runningEC2TasksCount", "runningFargateTasksCount", "pendingEC2TasksCount", "pendingFargateTasksCount", "runningExternalTasksCount", "pendingExternalTasksCount", "runningManagedInstancesTasksCount", "pendingManagedInstancesTasksCount", "activeEC2ServiceCount", "activeFargateServiceCount", "drainingEC2ServiceCount", "drainingFargateServiceCount", "activeExternalServiceCount", "drainingExternalServiceCount", "activeManagedInstancesServiceCount", "drainingManagedInstancesServiceCount"} {
		count := 0
		switch name {
		case "runningFargateTasksCount":
			count = int(*cluster.RunningTasksCount)
		case "pendingFargateTasksCount":
			count = int(*cluster.PendingTasksCount)
		}
		out = append(out, api.KeyValuePair{Name: new(api.String(name)), Value: new(api.String(strconv.Itoa(count)))})
	}
	return out
}
func (s *Service) listClusters(ctx context.Context, tx Transaction, in *api.ListClustersInput) (*api.ListClustersOutput, error) {
	if err := s.authorize(ctx, "ListClusters", "*", nil, nil); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	identity := collection(scope, "clusters")
	after, rejected := page(in.NextToken, identity)
	if rejected != nil {
		return nil, rejected
	}
	limit, rejected := pageSize(in.MaxResults)
	if rejected != nil {
		return nil, rejected
	}
	rows, err := tx.Clusters(ClusterQuery{Scope: scope, After: after, Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListClustersOutput{ClusterArns: api.StringList{}}
	if len(rows) > limit {
		rows = rows[:limit]
		out.NextToken = nextPage(identity, rows[len(rows)-1].Key.Name)
	}
	for _, row := range rows {
		out.ClusterArns = append(out.ClusterArns, api.String(row.Key.ARN()))
	}
	return out, nil
}
func projectActiveServices(r Reader, key ClusterKey, data *api.Cluster) error {
	services, err := r.Services(ServiceQuery{ClusterKey: key})
	if err != nil {
		return err
	}
	data.ActiveServicesCount = new(api.Integer(len(services)))
	return nil
}
func (s *Service) activeCluster(ctx context.Context, tx Transaction, id, action string) (ClusterRecord, error) {
	key, rejected := clusterKey(ctx, id)
	if rejected != nil {
		return ClusterRecord{}, rejected
	}
	tags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return ClusterRecord{}, err
	}
	if err := s.authorize(ctx, action, key.ARN(), tags, nil); err != nil {
		return ClusterRecord{}, err
	}
	record, err := tx.Cluster(key)
	if errors.Is(err, ErrNotFound) {
		return record, failure("ClusterNotFoundException", "Cluster not found.")
	}
	if err != nil {
		return record, err
	}
	if value(record.Data.Status) != "ACTIVE" {
		return record, failure("ClientException", "Cluster was not ACTIVE.")
	}
	if err := projectActiveServices(tx, key, &record.Data); err != nil {
		return record, err
	}
	return record, nil
}
func (s *Service) updateCluster(ctx context.Context, tx Transaction, in *api.UpdateClusterInput) (*api.UpdateClusterOutput, error) {
	record, err := s.activeCluster(ctx, tx, value(in.Cluster), "UpdateCluster")
	if err != nil {
		return nil, err
	}
	if err := validateClusterConfiguration(in.Configuration, in.ServiceConnectDefaults); err != nil {
		return nil, err
	}
	if err := validateSettings(in.Settings); err != nil {
		return nil, err
	}
	if in.Configuration != nil {
		record.Data.Configuration = new(api.CloneClusterConfiguration(*in.Configuration))
	}
	if in.Settings != nil {
		record.Data.Settings = api.CloneClusterSettings(in.Settings)
	}
	record.Updated = s.clock.Now()
	if err := tx.PutCluster(record); err != nil {
		return nil, err
	}
	record.Data.Tags = api.Tags{}
	record.Data.Attachments = api.Attachments{}
	return &api.UpdateClusterOutput{Cluster: &record.Data}, nil
}
func (s *Service) updateClusterSettings(ctx context.Context, tx Transaction, in *api.UpdateClusterSettingsInput) (*api.UpdateClusterSettingsOutput, error) {
	record, err := s.activeCluster(ctx, tx, value(in.Cluster), "UpdateClusterSettings")
	if err != nil {
		return nil, err
	}
	if err := validateSettings(in.Settings); err != nil {
		return nil, err
	}
	if len(in.Settings) > 0 {
		record.Data.Settings = api.CloneClusterSettings(in.Settings)
	}
	record.Updated = s.clock.Now()
	if err := tx.PutCluster(record); err != nil {
		return nil, err
	}
	record.Data.Tags = api.Tags{}
	record.Data.Attachments = api.Attachments{}
	return &api.UpdateClusterSettingsOutput{Cluster: &record.Data}, nil
}
func (s *Service) deleteCluster(ctx context.Context, tx Transaction, in *api.DeleteClusterInput) (*api.DeleteClusterOutput, error) {
	key, rejected := clusterKey(ctx, value(in.Cluster))
	if rejected != nil {
		return nil, rejected
	}
	tags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteCluster", key.ARN(), tags, nil); err != nil {
		return nil, err
	}
	record, err := tx.Cluster(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ClusterNotFoundException", "Cluster not found.")
	}
	if err != nil {
		return nil, err
	}
	if record.Data.RunningTasksCount != nil && *record.Data.RunningTasksCount > 0 || record.Data.PendingTasksCount != nil && *record.Data.PendingTasksCount > 0 {
		return nil, failure("ClusterContainsTasksException", "The Cluster cannot be deleted while Tasks are active.")
	}
	// Tasks remain active through provisioning and deprovisioning, even when
	// neither the RUNNING nor PENDING statistic includes them.
	tasks, err := tx.Tasks(TaskQuery{ClusterKey: key})
	if err != nil {
		return nil, err
	}
	for _, task := range tasks {
		if value(task.Data.LastStatus) != "STOPPED" {
			return nil, failure("ClusterContainsTasksException", "The Cluster cannot be deleted while Tasks are active.")
		}
	}
	services, err := tx.Services(ServiceQuery{ClusterKey: key, IncludeInactive: true})
	if err != nil {
		return nil, err
	}
	for _, service := range services {
		if status := value(service.Data.Status); status == "ACTIVE" || status == "DRAINING" {
			return nil, failure("ClusterContainsServicesException", "The Cluster cannot be deleted while Services are active.")
		}
	}
	if record.Data.RegisteredContainerInstancesCount != nil && *record.Data.RegisteredContainerInstancesCount > 0 {
		return nil, failure("ClusterContainsContainerInstancesException", "The Cluster cannot be deleted while Container Instances are active.")
	}
	inactive := value(record.Data.Status) == "INACTIVE"
	record.Data.Status = new(api.String("INACTIVE"))
	record.Data.ActiveServicesCount = new(api.Integer(0))
	record.Updated = s.clock.Now()
	if err := tx.PutCluster(record); err != nil {
		return nil, err
	}
	record.Data.Tags = api.Tags{}
	if inactive {
		record.Data.Attachments = api.Attachments{}
	}
	return &api.DeleteClusterOutput{Cluster: &record.Data, ClusterCount: new(api.Integer(0))}, nil
}
