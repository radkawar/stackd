package ecs

import api "stackd/internal/awsapi/ecs"

const (
	metricCPUUtilization    = "CPUUtilization"
	metricMemoryUtilization = "MemoryUtilization"
)

// Monitoring replaces a deployment's complete selection; omission preserves it
// on update. Native empty-object updates fail without allocating a deployment.
func serviceMonitoring(input *api.MonitoringConfiguration, update bool) (*api.MonitoringConfiguration, error) {
	if input == nil {
		return nil, nil
	}
	if input.MetricConfigurations == nil {
		if update {
			return nil, failure("ServerException", "Service Unavailable. Please try again later.", 500)
		}
		return nil, nil
	}
	seen := map[api.MetricName]bool{}
	for _, configuration := range input.MetricConfigurations {
		if *configuration.ResolutionSeconds != 20 && *configuration.ResolutionSeconds != 60 {
			return nil, failure("InvalidParameterException", "Monitoring configuration resolution must be one of [20, 60] seconds.")
		}
		for _, name := range configuration.MetricNames {
			switch name {
			case metricCPUUtilization, metricMemoryUtilization:
			default:
				return nil, failure("InvalidParameterException", "Metric name must be one of [CPUUtilization, MemoryUtilization].")
			}
			if seen[name] {
				return nil, failure("InvalidParameterException", "Duplicate metric names are not allowed across monitoring configuration.")
			}
			seen[name] = true
		}
	}
	return input, nil
}

func cloneServiceMonitoring(input *api.MonitoringConfiguration) *api.MonitoringConfiguration {
	if input == nil {
		return nil
	}
	out := api.CloneMonitoringConfiguration(*input)
	return &out
}

func serviceMetricResolution(monitoring *api.MonitoringConfiguration, name string) int32 {
	if monitoring != nil {
		for _, configuration := range monitoring.MetricConfigurations {
			for _, metric := range configuration.MetricNames {
				if string(metric) == name {
					return int32(*configuration.ResolutionSeconds)
				}
			}
		}
	}
	return 60
}
