package guardduty

import (
	"slices"
	"time"

	api "stackd/internal/awsapi/guardduty"
)

func defaultFeatures(now time.Time) []Feature {
	var out []Feature
	for _, name := range []string{"CLOUD_TRAIL", "DNS_LOGS", "FLOW_LOGS", "S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "EKS_RUNTIME_MONITORING", "RUNTIME_MONITORING", "AI_PROTECTION", "AI_ANALYST"} {
		status := "ENABLED"
		switch name {
		case "EKS_RUNTIME_MONITORING", "RUNTIME_MONITORING", "AI_PROTECTION", "AI_ANALYST":
			status = "DISABLED"
		}
		f := Feature{Name: name, Status: status, Updated: now}
		switch name {
		case "EKS_RUNTIME_MONITORING":
			f.Additional = []AdditionalFeature{{Name: "EKS_ADDON_MANAGEMENT", Status: "DISABLED", Updated: now}}
		case "RUNTIME_MONITORING":
			for _, n := range []string{"EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT"} {
				f.Additional = append(f.Additional, AdditionalFeature{Name: n, Status: "DISABLED", Updated: now})
			}
		}
		out = append(out, f)
	}
	return out
}
func applyFeatures(d *Detector, features api.DetectorFeatureConfigurations, sources *api.DataSourceConfigurations, now time.Time) error {
	if features != nil && sources != nil {
		return invalid("features and dataSources cannot be specified together")
	}
	requested := map[string]bool{}
	for _, input := range features {
		name, status := value(input.Name), value(input.Status)
		if requested[name] {
			return invalid("Duplicate feature configuration")
		}
		requested[name] = true
		i := slices.IndexFunc(d.Features, func(v Feature) bool { return v.Name == name })
		if i < 0 || name == "CLOUD_TRAIL" || name == "DNS_LOGS" || name == "FLOW_LOGS" {
			return invalid("Invalid feature name")
		}
		if status != "ENABLED" && status != "DISABLED" {
			return invalid("Invalid feature status")
		}
		f := &d.Features[i]
		f.Status, f.Updated = status, now
		seen := map[string]bool{}
		for _, additional := range input.AdditionalConfiguration {
			name, status := value(additional.Name), value(additional.Status)
			if seen[name] {
				return invalid("Duplicate additional feature configuration")
			}
			seen[name] = true
			j := slices.IndexFunc(f.Additional, func(v AdditionalFeature) bool { return v.Name == name })
			if j < 0 || status != "ENABLED" && status != "DISABLED" {
				return invalid("Invalid additional feature configuration")
			}
			f.Additional[j].Status, f.Additional[j].Updated = status, now
		}
	}
	if requested["EKS_RUNTIME_MONITORING"] && requested["RUNTIME_MONITORING"] {
		return invalid("EKS_RUNTIME_MONITORING and RUNTIME_MONITORING cannot both be specified")
	}
	if sources != nil {
		set := func(name string, enable *api.Boolean) {
			if enable == nil {
				return
			}
			i := slices.IndexFunc(d.Features, func(v Feature) bool { return v.Name == name })
			d.Features[i].Status = "DISABLED"
			if bool(*enable) {
				d.Features[i].Status = "ENABLED"
			}
			d.Features[i].Updated = now
		}
		if sources.S3Logs != nil {
			set("S3_DATA_EVENTS", sources.S3Logs.Enable)
		}
		if sources.Kubernetes != nil && sources.Kubernetes.AuditLogs != nil {
			set("EKS_AUDIT_LOGS", sources.Kubernetes.AuditLogs.Enable)
		}
		if sources.MalwareProtection != nil && sources.MalwareProtection.ScanEc2InstanceWithFindings != nil {
			set("EBS_MALWARE_PROTECTION", sources.MalwareProtection.ScanEc2InstanceWithFindings.EbsVolumes)
		}
	}
	// TODO: Comeback acquire remaining optional-source/agent and malware scanner
	// owners before accepting activation. S3 outcomes and native EKS audit
	// admission already feed their respective feature-gated detection rules.
	for _, f := range d.Features {
		if f.Name != "CLOUD_TRAIL" && f.Name != "DNS_LOGS" && f.Name != "FLOW_LOGS" && f.Name != "S3_DATA_EVENTS" && f.Name != "EKS_AUDIT_LOGS" && f.Status == "ENABLED" {
			return invalid("Optional GuardDuty protection requires an implemented monitoring owner; explicitly disable " + f.Name)
		}
		for _, a := range f.Additional {
			if a.Status == "ENABLED" {
				return invalid("GuardDuty automated agent management is not implemented")
			}
		}
	}
	return nil
}
func detectorDataSources(d Detector) *api.DataSourceConfigurationsResult {
	status := func(name string) *api.DataSourceStatus {
		v := api.DataSourceStatusDISABLED
		for _, f := range d.Features {
			if f.Name == name {
				v = api.DataSourceStatus(f.Status)
				break
			}
		}
		return &v
	}
	return &api.DataSourceConfigurationsResult{
		CloudTrail: &api.CloudTrailConfigurationResult{Status: status("CLOUD_TRAIL")}, DNSLogs: &api.DNSLogsConfigurationResult{Status: status("DNS_LOGS")}, FlowLogs: &api.FlowLogsConfigurationResult{Status: status("FLOW_LOGS")},
		S3Logs:            &api.S3LogsConfigurationResult{Status: status("S3_DATA_EVENTS")},
		Kubernetes:        &api.KubernetesConfigurationResult{AuditLogs: &api.KubernetesAuditLogsConfigurationResult{Status: status("EKS_AUDIT_LOGS")}},
		MalwareProtection: &api.MalwareProtectionConfigurationResult{ScanEc2InstanceWithFindings: &api.ScanEc2InstanceWithFindingsResult{EbsVolumes: &api.EbsVolumesResult{Status: status("EBS_MALWARE_PROTECTION")}}},
	}
}
