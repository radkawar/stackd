package guardduty

import (
	"net/url"
	"slices"
	"strings"

	"stackd/journal"
)

// These predicates implement observable operations from the public EKS finding
// descriptions, not AWS's private tactic inventory or anomaly models:
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html
// TODO: Comeback implement remaining Kubernetes predicates with real audit
// object/policy context, reputation feeds and remaining custom-list tactics;
// admitted RBAC bindings establish anonymous grants, but metadata alone cannot
// establish workload privilege or AWS's private anomaly classifications.
func detectKubernetesAudit(detector Detector, event journal.KubernetesAuditObserved) []Observation {
	if !kubernetesAuditEligible(detector, event) {
		return nil
	}

	var findingType, title, description string
	var severity float64
	success := event.ResponseCode >= 200 && event.ResponseCode < 300
	// Exec upgrades can complete with 101 rather than an ordinary 2xx status.
	// ResponseStarted alone does not establish the final outcome of the stream.
	if event.Resource == "pods" && event.Subresource == "exec" && event.Namespace == "kube-system" && event.Name != "" &&
		(event.Verb == "create" || event.Verb == "get") && (success || event.ResponseCode == 101) {
		findingType = "Execution:Kubernetes/ExecInKubeSystemPod"
		title = "Command executed in a kube-system pod"
		description = "The Kubernetes exec API successfully accessed a pod in the kube-system namespace."
		severity = 5
	} else if success && kubernetesAnonymousAccessGranted(event) {
		findingType = "Policy:Kubernetes/AnonymousAccessGranted"
		title = "Anonymous Kubernetes access granted"
		description = "A Kubernetes RBAC binding was successfully created granting access to an anonymous subject."
		severity = 8
	} else if success && event.UserName == "system:anonymous" && !slices.Contains(event.Groups, "system:authenticated") {
		switch {
		case event.Resource == "secrets" && event.Subresource == "" && kubernetesReadVerb(event.Verb):
			findingType = "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess"
			title = "Kubernetes secrets accessed anonymously"
			description = "The system:anonymous user successfully read Kubernetes secrets."
			severity = 8
		case kubernetesDiscovery(event):
			findingType = "Discovery:Kubernetes/SuccessfulAnonymousAccess"
			title = "Kubernetes resources discovered anonymously"
			description = "The system:anonymous user successfully accessed Kubernetes resource discovery information."
			severity = 5
		case event.Subresource == "" && (event.Verb == "delete" || event.Verb == "deletecollection") && kubernetesImpactResource(event.Resource):
			// AWS documents successful API access, not completed deletion.
			// TODO: Comeback calibrate native GuardDuty dry-run eligibility;
			// preserve effective options without inventing an exclusion rule.
			findingType = "Impact:Kubernetes/SuccessfulAnonymousAccess"
			title = "Anonymous Kubernetes deletion API access"
			description = "The system:anonymous user successfully invoked a Kubernetes resource deletion API."
			severity = 8
		}
	}
	if findingType == "" {
		return nil
	}
	// Retain an independent snapshot: later caller mutations must not change a
	// finding's identity, groups, or projected evidence.
	event = journal.CloneKubernetesAudit(event)
	return []Observation{{
		Type: findingType, Title: title, Description: description, Severity: severity,
		EventID: event.AuditID, PrincipalID: event.UserUID, UserName: event.UserName,
		SourceIP: event.SourceIP, ResourceType: "EKSCluster", ResourceName: event.ClusterName,
		ResourceARN: event.ClusterARN, FeatureName: "KubernetesAuditLogs", Kubernetes: &event,
	}}
}

func kubernetesAuditEligible(detector Detector, event journal.KubernetesAuditObserved) bool {
	return detector.Status == "ENABLED" && detectionFeatureEnabled(detector, "EKS_AUDIT_LOGS") &&
		event.Stage == "ResponseComplete" && (event.Resource == "" || kubernetesBuiltinResource(event))
}

func kubernetesAnonymousAccessGranted(event journal.KubernetesAuditObserved) bool {
	const rbacGroup = "rbac.authorization.k8s.io"
	if event.Verb != "create" || event.Subresource != "" || event.APIVersion != "v1" || event.Name == "" ||
		event.RoleRefAPIGroup != rbacGroup || event.RoleRefName == "" {
		return false
	}
	path, rawQuery, _ := strings.Cut(event.RequestURI, "?")
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return false
	}
	for _, dryRun := range query["dryRun"] {
		if dryRun != "" {
			return false
		}
	}
	switch event.Resource {
	case "rolebindings":
		if event.Namespace == "" || path != "/apis/"+rbacGroup+"/v1/namespaces/"+event.Namespace+"/rolebindings" ||
			(event.RoleRefKind != "Role" && event.RoleRefKind != "ClusterRole") {
			return false
		}
	case "clusterrolebindings":
		if event.Namespace != "" || path != "/apis/"+rbacGroup+"/v1/clusterrolebindings" || event.RoleRefKind != "ClusterRole" {
			return false
		}
	default:
		return false
	}
	for _, subject := range event.Subjects {
		if subject.APIGroup == rbacGroup &&
			((subject.Kind == "User" && subject.Name == "system:anonymous") ||
				(subject.Kind == "Group" && subject.Name == "system:unauthenticated")) {
			return true
		}
	}
	return false
}

func kubernetesReadVerb(verb string) bool {
	return verb == "get" || verb == "list" || verb == "watch"
}

func kubernetesDiscovery(event journal.KubernetesAuditObserved) bool {
	if !kubernetesReadVerb(event.Verb) || event.Subresource != "" {
		return false
	}
	path, _, _ := strings.Cut(event.RequestURI, "?")
	for _, excluded := range []string{"/healthz", "/livez", "/readyz", "/version"} {
		if path == excluded || strings.HasPrefix(path, excluded+"/") {
			return false
		}
	}
	// An explicit inventory prevents arbitrary custom resources, credentials,
	// proxy requests, logs, and exec operations being labelled discovery.
	switch event.Resource {
	case "pods", "nodes", "namespaces", "services", "endpoints", "endpointslices",
		"deployments", "replicasets", "replicationcontrollers", "daemonsets", "statefulsets",
		"jobs", "cronjobs", "configmaps", "serviceaccounts", "roles", "rolebindings",
		"clusterroles", "clusterrolebindings", "persistentvolumes", "persistentvolumeclaims",
		"storageclasses", "ingresses", "networkpolicies", "events":
		return true
	case "":
		// Non-resource API discovery is limited to the discovery roots. Do not
		// treat every successful anonymous GET as reconnaissance.
		return event.Verb == "get" && (path == "/api" || path == "/api/" || path == "/apis" || path == "/apis/")
	default:
		return false
	}
}

func kubernetesImpactResource(resource string) bool {
	// Deletion is directly observable impact. Patch/update/create alone cannot
	// establish disruption, persistence, or defense evasion from metadata alone.
	switch resource {
	case "pods", "nodes", "namespaces", "services", "endpoints", "endpointslices",
		"deployments", "replicasets", "replicationcontrollers", "daemonsets", "statefulsets",
		"jobs", "cronjobs", "configmaps", "secrets", "persistentvolumes", "persistentvolumeclaims",
		"ingresses", "networkpolicies":
		return true
	default:
		return false
	}
}

// ObjectRef.Resource is only a plural name, not an API group identity. Custom
// resources may reuse built-in names, so the native request path must identify
// the resource's official API group before any tactic predicate can match.
func kubernetesBuiltinResource(event journal.KubernetesAuditObserved) bool {
	path, _, _ := strings.Cut(event.RequestURI, "?")
	group := ""
	if !strings.HasPrefix(path, "/api/v1/") {
		groupPath, ok := strings.CutPrefix(path, "/apis/")
		if !ok {
			return false
		}
		var versionPath string
		group, versionPath, ok = strings.Cut(groupPath, "/")
		if !ok || group == "" {
			return false
		}
		version, resourcePath, ok := strings.Cut(versionPath, "/")
		if !ok || version == "" || resourcePath == "" {
			return false
		}
	}
	switch event.Resource {
	case "pods", "nodes", "namespaces", "services", "endpoints", "replicationcontrollers",
		"configmaps", "secrets", "serviceaccounts", "persistentvolumes", "persistentvolumeclaims":
		return group == ""
	case "deployments", "replicasets", "daemonsets", "statefulsets":
		return group == "apps"
	case "jobs", "cronjobs":
		return group == "batch"
	case "roles", "rolebindings", "clusterroles", "clusterrolebindings":
		return group == "rbac.authorization.k8s.io"
	case "ingresses", "networkpolicies":
		return group == "networking.k8s.io"
	case "storageclasses":
		return group == "storage.k8s.io"
	case "endpointslices":
		return group == "discovery.k8s.io"
	case "events":
		return group == "" || group == "events.k8s.io"
	default:
		return false
	}
}
