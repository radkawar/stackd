package guardduty

import (
	"slices"

	"stackd/journal"
)

func detectKubernetesAuditWithLists(r Reader, detector Detector, event journal.KubernetesAuditObserved) ([]Observation, error) {
	if !kubernetesAuditEligible(detector, event) {
		return nil, nil
	}
	var names []string
	if address, ok := listSourceIPv4(event.SourceIP); ok {
		matches, err := r.MatchingIPLists(detector.Scope, detector.ID, address)
		if err != nil {
			return nil, err
		}
		for _, list := range matches {
			if list.Kind == TrustedIPList {
				return nil, nil
			}
			if list.Kind == ThreatIPList {
				names = append(names, list.Name)
			}
		}
	}
	observed := detectKubernetesAudit(detector, event)
	if len(names) == 0 {
		return observed, nil
	}
	custom, ok := customKubernetesIPObservation(event)
	if !ok {
		return observed, nil
	}
	slices.Sort(names)
	custom.ThreatListNames = slices.Compact(names)
	return append(observed, custom), nil
}

// Custom-list findings describe API invocation, not successful completion.
// Preserve denied outcomes. Only directly observable credential reads, discovery
// and deletion operations are classified; no private tactic/anomaly model is inferred.
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html
func customKubernetesIPObservation(event journal.KubernetesAuditObserved) (Observation, bool) {
	var findingType, title, description string
	severity := 8.0
	switch {
	case event.Resource == "secrets" && event.Subresource == "" && kubernetesReadVerb(event.Verb):
		findingType, title = "CredentialAccess:Kubernetes/MaliciousIPCaller.Custom", "Kubernetes credentials accessed from a custom threat IP"
		description = "A Kubernetes secrets read API was invoked from an IP address in an active custom threat list."
	case kubernetesDiscovery(event):
		findingType, title = "Discovery:Kubernetes/MaliciousIPCaller.Custom", "Kubernetes discovery from a custom threat IP"
		description = "A Kubernetes resource discovery API was invoked from an IP address in an active custom threat list."
		severity = 5
	case event.Subresource == "" && (event.Verb == "delete" || event.Verb == "deletecollection") && kubernetesImpactResource(event.Resource):
		findingType, title = "Impact:Kubernetes/MaliciousIPCaller.Custom", "Kubernetes deletion API invoked from a custom threat IP"
		description = "A Kubernetes resource deletion API was invoked from an IP address in an active custom threat list."
	default:
		return Observation{}, false
	}
	event = journal.CloneKubernetesAudit(event)
	return Observation{
		Type: findingType, Title: title, Description: description, Severity: severity,
		EventID: event.AuditID, PrincipalID: event.UserUID, UserName: event.UserName,
		SourceIP: event.SourceIP, ResourceType: "EKSCluster", ResourceName: event.ClusterName,
		ResourceARN: event.ClusterARN, FeatureName: "KubernetesAuditLogs", Kubernetes: &event,
	}, true
}
