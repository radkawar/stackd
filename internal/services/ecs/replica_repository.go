package ecs

import (
	api "stackd/internal/awsapi/ecs"
	"time"
)

type ServiceKey struct {
	ClusterKey
	ServiceName string
}

func (k ServiceKey) ARN() string {
	return "arn:" + k.Partition + ":ecs:" + k.Region + ":" + k.AccountID + ":service/" + k.Name + "/" + k.ServiceName
}

// ServiceRecord retains admitted requests, not caller credentials. Deployments own
// their immutable task definitions and execution settings across rolling updates.
type ServiceRecord struct {
	Key                  ServiceKey
	Ownership            string
	Data                 api.Service
	CreateInput          api.CreateServiceInput
	Deployments          []ServiceDeployment
	AcceptedEventID      string
	DrainAfter           time.Time
	NextMetricCollection time.Time
}

// EffectiveLaunchType exposes launch filtering without adding a launchType member
// to capacity-provider-backed API responses.
func (v ServiceRecord) EffectiveLaunchType() string {
	if launch := value(v.Data.LaunchType); launch != "" {
		return launch
	}
	for _, provider := range v.Data.CapacityProviderStrategy {
		switch value(provider.CapacityProvider) {
		case "FARGATE", "FARGATE_SPOT":
			return "FARGATE"
		}
	}
	if len(v.Data.CapacityProviderStrategy) != 0 {
		return "EC2"
	}
	return ""
}

type ServiceDeployment struct {
	Data            api.Deployment
	Definition      api.TaskDefinition
	Input           api.RunTaskInput
	Monitoring      *api.MonitoringConfiguration
	LoadBalancers   api.LoadBalancers
	AcceptedEventID string
	Failures        int32
	ObservedTasks   map[string]string
	// ResolvedImages pins container names to runtime-resolved image references
	// independently of the immutable admitted task definition.
	ResolvedImages map[string]string
	RetryAfter     time.Time
	Deadline       time.Time
	Completed      bool
}
type ServiceQuery struct {
	ClusterKey
	After              string
	Limit              int
	IncludeInactive    bool
	LaunchType         string
	SchedulingStrategy string
}
