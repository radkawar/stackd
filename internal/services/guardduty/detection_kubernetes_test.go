package guardduty

import (
	"encoding/json"
	"reflect"
	"testing"

	"stackd/journal"
)

func kubernetesRulesDetector() Detector {
	return Detector{Status: "ENABLED", Features: []Feature{{Name: "EKS_AUDIT_LOGS", Status: "ENABLED"}}}
}

func TestKubernetesExecRequiresCompletedSuccessfulPodExec(t *testing.T) {
	for _, tc := range []struct {
		name, stage, resource, subresource, namespace, pod, verb string
		status                                                   int32
		want                                                     bool
	}{
		{"SPDY upgrade", "ResponseComplete", "pods", "exec", "kube-system", "dns", "create", 101, true},
		{"WebSocket upgrade", "ResponseComplete", "pods", "exec", "kube-system", "dns", "get", 101, true},
		{"successful completion", "ResponseComplete", "pods", "exec", "kube-system", "dns", "create", 200, true},
		{"forbidden", "ResponseComplete", "pods", "exec", "kube-system", "dns", "create", 403, false},
		{"unauthorized", "ResponseComplete", "pods", "exec", "kube-system", "dns", "create", 401, false},
		{"missing status", "ResponseComplete", "pods", "exec", "kube-system", "dns", "create", 0, false},
		{"redirect", "ResponseComplete", "pods", "exec", "kube-system", "dns", "create", 302, false},
		{"failed stream", "ResponseComplete", "pods", "exec", "kube-system", "dns", "create", 500, false},
		{"stream not complete", "ResponseStarted", "pods", "exec", "kube-system", "dns", "create", 101, false},
		{"request only", "RequestReceived", "pods", "exec", "kube-system", "dns", "create", 200, false},
		{"missing stage", "", "pods", "exec", "kube-system", "dns", "create", 200, false},
		{"panic", "Panic", "pods", "exec", "kube-system", "dns", "create", 200, false},
		{"other namespace", "ResponseComplete", "pods", "exec", "default", "dns", "create", 101, false},
		{"namespace prefix", "ResponseComplete", "pods", "exec", "kube-system-extra", "dns", "create", 101, false},
		{"attach not exec", "ResponseComplete", "pods", "attach", "kube-system", "dns", "create", 101, false},
		{"ordinary pod get", "ResponseComplete", "pods", "", "kube-system", "dns", "get", 200, false},
		{"wrong resource", "ResponseComplete", "deployments", "exec", "kube-system", "dns", "create", 101, false},
		{"no named pod", "ResponseComplete", "pods", "exec", "kube-system", "", "create", 101, false},
		{"wrong verb", "ResponseComplete", "pods", "exec", "kube-system", "dns", "delete", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := journal.KubernetesAuditObserved{Stage: tc.stage, Resource: tc.resource, Subresource: tc.subresource,
				Namespace: tc.namespace, Name: tc.pod, Verb: tc.verb, ResponseCode: tc.status, UserName: "operator",
				RequestURI: "/api/v1/namespaces/" + tc.namespace + "/pods/" + tc.pod + "/exec"}
			got := detectKubernetesAudit(kubernetesRulesDetector(), event)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("non-execution produced finding: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Type != "Execution:Kubernetes/ExecInKubeSystemPod" {
				t.Fatalf("completed kube-system exec produced %+v", got)
			}
			for _, uri := range []string{
				"/apis/evil.example/v1/namespaces/kube-system/pods/dns/exec",
				"/apis/apps/v1/namespaces/kube-system/pods/dns/exec",
			} {
				event.RequestURI = uri
				if got := detectKubernetesAudit(kubernetesRulesDetector(), event); len(got) != 0 {
					t.Fatalf("non-core pods/exec produced finding: %+v", got)
				}
			}
		})
	}
}

func TestKubernetesAnonymousOperationClassification(t *testing.T) {
	for _, tc := range []struct {
		name, verb, resource, subresource, uri, tactic string
	}{
		{"read secret", "get", "secrets", "", "/api/v1/namespaces/default/secrets/password", "CredentialAccess"},
		{"list secrets", "list", "secrets", "", "/api/v1/namespaces/default/secrets", "CredentialAccess"},
		{"watch secrets", "watch", "secrets", "", "/api/v1/namespaces/default/secrets?watch=true", "CredentialAccess"},
		{"list pods", "list", "pods", "", "/api/v1/pods", "Discovery"},
		{"get node", "get", "nodes", "", "/api/v1/nodes/worker", "Discovery"},
		{"API discovery root", "get", "", "", "/apis", "Discovery"},
		{"core API discovery root", "get", "", "", "/api", "Discovery"},
		{"apps discovery", "list", "deployments", "", "/apis/apps/v1/deployments", "Discovery"},
		{"batch discovery", "list", "cronjobs", "", "/apis/batch/v1/cronjobs", "Discovery"},
		{"RBAC discovery", "get", "clusterroles", "", "/apis/rbac.authorization.k8s.io/v1/clusterroles/admin", "Discovery"},
		{"networking discovery", "list", "networkpolicies", "", "/apis/networking.k8s.io/v1/networkpolicies", "Discovery"},
		{"storage discovery", "list", "storageclasses", "", "/apis/storage.k8s.io/v1/storageclasses", "Discovery"},
		{"endpoint discovery", "list", "endpointslices", "", "/apis/discovery.k8s.io/v1/endpointslices", "Discovery"},
		{"grouped event discovery", "list", "events", "", "/apis/events.k8s.io/v1/events", "Discovery"},
		{"delete pod", "delete", "pods", "", "/api/v1/namespaces/default/pods/worker", "Impact"},
		{"delete secrets", "deletecollection", "secrets", "", "/api/v1/namespaces/default/secrets", "Impact"},
		{"apps impact", "delete", "deployments", "", "/apis/apps/v1/namespaces/default/deployments/app", "Impact"},
		{"batch impact", "deletecollection", "jobs", "", "/apis/batch/v1/namespaces/default/jobs", "Impact"},
		{"networking impact", "delete", "ingresses", "", "/apis/networking.k8s.io/v1/namespaces/default/ingresses/app", "Impact"},
		{"custom pods discovery", "list", "pods", "", "/apis/evil.example/v1/pods", ""},
		{"custom secrets read", "get", "secrets", "", "/apis/evil.example/v1/namespaces/default/secrets/password", ""},
		{"custom pods deletion", "delete", "pods", "", "/apis/evil.example/v1/namespaces/default/pods/worker", ""},
		{"custom deployments", "list", "deployments", "", "/apis/evil.example/v1/deployments", ""},
		{"wrong official group", "list", "deployments", "", "/apis/batch/v1/deployments", ""},
		{"grouped resource without group", "list", "deployments", "", "/api/v1/deployments", ""},
		{"group lookalike", "list", "deployments", "", "/apis/apps.evil.example/v1/deployments", ""},
		{"missing resource API version", "list", "deployments", "", "/apis/apps//deployments", ""},
		{"missing source URI", "get", "secrets", "", "", ""},
		{"health", "get", "", "", "/healthz", ""},
		{"health subcheck", "get", "", "", "/healthz/ping", ""},
		{"liveness", "get", "", "", "/livez?verbose=true", ""},
		{"readiness", "get", "", "", "/readyz/etcd", ""},
		{"version", "get", "", "", "/version", ""},
		{"health is excluded even with resource", "get", "pods", "", "/healthz", ""},
		{"pod proxy", "get", "pods", "proxy", "/api/v1/namespaces/default/pods/worker/proxy", ""},
		{"pod logs", "get", "pods", "log", "/api/v1/namespaces/default/pods/worker/log", ""},
		{"unknown resource", "get", "widgets", "", "/apis/example.test/v1/widgets", ""},
		{"unknown non-resource", "get", "", "", "/metrics", ""},
		{"unknown impact", "delete", "widgets", "", "/apis/example.test/v1/widgets/a", ""},
		{"creation is not persistence proof", "create", "deployments", "", "/apis/apps/v1/namespaces/default/deployments", ""},
		{"patch is not impact proof", "patch", "pods", "", "/api/v1/namespaces/default/pods/worker", ""},
		{"policy edit is not defense evasion proof", "update", "roles", "", "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles/a", ""},
		{"write secret is not credential read", "create", "secrets", "", "/api/v1/namespaces/default/secrets", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := journal.KubernetesAuditObserved{Stage: "ResponseComplete", UserName: "system:anonymous", Groups: []string{"system:unauthenticated"},
				Verb: tc.verb, Resource: tc.resource, Subresource: tc.subresource, RequestURI: tc.uri, ResponseCode: 200}
			got := detectKubernetesAudit(kubernetesRulesDetector(), event)
			if tc.tactic == "" {
				if len(got) != 0 {
					t.Fatalf("unsupported operation produced %+v", got)
				}
				return
			}
			want := tc.tactic + ":Kubernetes/SuccessfulAnonymousAccess"
			if len(got) != 1 || got[0].Type != want {
				t.Fatalf("got %+v, want only %s", got, want)
			}
			for name, mutate := range map[string]func(*journal.KubernetesAuditObserved){
				"authenticated":               func(e *journal.KubernetesAuditObserved) { e.UserName = "operator" },
				"authenticated group":         func(e *journal.KubernetesAuditObserved) { e.Groups = []string{"system:authenticated"} },
				"missing user":                func(e *journal.KubernetesAuditObserved) { e.UserName = "" },
				"denied":                      func(e *journal.KubernetesAuditObserved) { e.ResponseCode = 403 },
				"upgrade is not read success": func(e *journal.KubernetesAuditObserved) { e.ResponseCode = 101 },
				"missing status":              func(e *journal.KubernetesAuditObserved) { e.ResponseCode = 0 },
				"missing stage":               func(e *journal.KubernetesAuditObserved) { e.Stage = "" },
				"not completed":               func(e *journal.KubernetesAuditObserved) { e.Stage = "ResponseStarted" },
			} {
				t.Run(name, func(t *testing.T) {
					changed := event
					mutate(&changed)
					if got := detectKubernetesAudit(kubernetesRulesDetector(), changed); len(got) != 0 {
						t.Fatalf("ineligible anonymous operation produced %+v", got)
					}
				})
			}
		})
	}
}

func TestKubernetesDetectionGates(t *testing.T) {
	for _, event := range []journal.KubernetesAuditObserved{
		{Stage: "ResponseComplete", Resource: "pods", Subresource: "exec", Namespace: "kube-system", Name: "dns", Verb: "create", ResponseCode: 101, RequestURI: "/api/v1/namespaces/kube-system/pods/dns/exec"},
		{Stage: "ResponseComplete", Resource: "secrets", Verb: "get", UserName: "system:anonymous", ResponseCode: 200, RequestURI: "/api/v1/secrets"},
		kubernetesAnonymousGrantEvent(),
	} {
		for _, detector := range []Detector{
			{Status: "DISABLED", Features: []Feature{{Name: "EKS_AUDIT_LOGS", Status: "ENABLED"}}},
			{Status: "ENABLED", Features: []Feature{{Name: "EKS_AUDIT_LOGS", Status: "DISABLED"}}},
			{Status: "ENABLED", Features: []Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}}},
			{Features: []Feature{{Name: "EKS_AUDIT_LOGS", Status: "ENABLED"}}},
		} {
			if got := detectKubernetesAudit(detector, event); len(got) != 0 {
				t.Fatalf("inactive detector %+v produced %+v", detector, got)
			}
		}
	}
}

func kubernetesAnonymousGrantEvent() journal.KubernetesAuditObserved {
	return journal.KubernetesAuditObserved{
		Stage: "ResponseComplete", Verb: "create", ResponseCode: 201,
		Resource: "rolebindings", Namespace: "default", Name: "reader",
		APIVersion: "v1", RequestURI: "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings",
		UserName: "administrator", Groups: []string{"system:authenticated"},
		RoleRefAPIGroup: "rbac.authorization.k8s.io", RoleRefKind: "Role", RoleRefName: "reader",
		Subjects: []journal.KubernetesSubject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "system:anonymous"}},
	}
}

func TestKubernetesAnonymousAccessGranted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*journal.KubernetesAuditObserved)
		want   bool
	}{
		{"anonymous user", func(e *journal.KubernetesAuditObserved) {}, true},
		{"unauthenticated group", func(e *journal.KubernetesAuditObserved) {
			e.Subjects[0].Kind = "Group"
			e.Subjects[0].Name = "system:unauthenticated"
		}, true},
		{"cluster role in namespace", func(e *journal.KubernetesAuditObserved) { e.RoleRefKind = "ClusterRole" }, true},
		{"cluster binding", func(e *journal.KubernetesAuditObserved) {
			e.Resource = "clusterrolebindings"
			e.Namespace = ""
			e.RoleRefKind = "ClusterRole"
			e.RequestURI = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
		}, true},
		{"query parameters", func(e *journal.KubernetesAuditObserved) { e.RequestURI += "?fieldManager=fixture" }, true},
		{"empty dry run", func(e *journal.KubernetesAuditObserved) { e.RequestURI += "?dryRun=" }, true},
		{"dry run", func(e *journal.KubernetesAuditObserved) { e.RequestURI += "?dryRun=All" }, false},
		{"repeated dry run", func(e *journal.KubernetesAuditObserved) { e.RequestURI += "?dryRun=&dryRun=All" }, false},
		{"encoded dry run", func(e *journal.KubernetesAuditObserved) { e.RequestURI += "?dry%52un=%41ll" }, false},
		{"later subject", func(e *journal.KubernetesAuditObserved) {
			e.Subjects = append([]journal.KubernetesSubject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "alice"}}, e.Subjects...)
		}, true},
		{"failed create", func(e *journal.KubernetesAuditObserved) { e.ResponseCode = 403 }, false},
		{"missing outcome", func(e *journal.KubernetesAuditObserved) { e.ResponseCode = 0 }, false},
		{"unfinished create", func(e *journal.KubernetesAuditObserved) { e.Stage = "ResponseStarted" }, false},
		{"request only", func(e *journal.KubernetesAuditObserved) { e.Stage = "RequestReceived" }, false},
		{"patch", func(e *journal.KubernetesAuditObserved) { e.Verb = "patch" }, false},
		{"update", func(e *journal.KubernetesAuditObserved) { e.Verb = "update" }, false},
		{"delete", func(e *journal.KubernetesAuditObserved) { e.Verb = "delete" }, false},
		{"subresource", func(e *journal.KubernetesAuditObserved) { e.Subresource = "status" }, false},
		{"custom API group", func(e *journal.KubernetesAuditObserved) {
			e.RequestURI = "/apis/custom.example/v1/namespaces/default/rolebindings"
		}, false},
		{"old API version", func(e *journal.KubernetesAuditObserved) { e.APIVersion = "v1beta1" }, false},
		{"old request version", func(e *journal.KubernetesAuditObserved) {
			e.RequestURI = "/apis/rbac.authorization.k8s.io/v1beta1/namespaces/default/rolebindings"
		}, false},
		{"wrong request resource", func(e *journal.KubernetesAuditObserved) {
			e.RequestURI = "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles"
		}, false},
		{"missing role reference", func(e *journal.KubernetesAuditObserved) { e.RoleRefName = "" }, false},
		{"custom role group", func(e *journal.KubernetesAuditObserved) { e.RoleRefAPIGroup = "custom.example" }, false},
		{"invalid role kind", func(e *journal.KubernetesAuditObserved) { e.RoleRefKind = "User" }, false},
		{"namespaced role at cluster scope", func(e *journal.KubernetesAuditObserved) {
			e.Resource = "clusterrolebindings"
			e.Namespace = ""
			e.RequestURI = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
		}, false},
		{"missing subjects", func(e *journal.KubernetesAuditObserved) { e.Subjects = nil }, false},
		{"ordinary user", func(e *journal.KubernetesAuditObserved) { e.Subjects[0].Name = "alice" }, false},
		{"anonymous named binding only", func(e *journal.KubernetesAuditObserved) { e.Name = "system:anonymous"; e.Subjects[0].Name = "alice" }, false},
		{"service account collision", func(e *journal.KubernetesAuditObserved) {
			e.Subjects[0].Kind = "ServiceAccount"
			e.Subjects[0].APIGroup = ""
			e.Subjects[0].Namespace = "default"
		}, false},
		{"custom subject group", func(e *journal.KubernetesAuditObserved) { e.Subjects[0].APIGroup = "custom.example" }, false},
		{"missing subject group", func(e *journal.KubernetesAuditObserved) { e.Subjects[0].APIGroup = "" }, false},
		{"anonymous group collision", func(e *journal.KubernetesAuditObserved) { e.Subjects[0].Kind = "Group" }, false},
		{"unauthenticated user collision", func(e *journal.KubernetesAuditObserved) { e.Subjects[0].Name = "system:unauthenticated" }, false},
		{"anonymous name prefix", func(e *journal.KubernetesAuditObserved) { e.Subjects[0].Name += ":extra" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := kubernetesAnonymousGrantEvent()
			tc.change(&event)
			got := detectKubernetesAudit(kubernetesRulesDetector(), event)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("unexpected finding: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Type != "Policy:Kubernetes/AnonymousAccessGranted" || got[0].Severity != 8 {
				t.Fatalf("expected high severity anonymous grant, got %+v", got)
			}
		})
	}
}

func TestKubernetesAnonymousGrantRetainsIndependentProjectedEvidence(t *testing.T) {
	event := kubernetesAnonymousGrantEvent()
	event.Subjects = append(event.Subjects, journal.KubernetesSubject{Kind: "ServiceAccount", Name: "worker", Namespace: "jobs"})
	want := journal.CloneKubernetesAudit(event)
	observations := detectKubernetesAudit(kubernetesRulesDetector(), event)
	if len(observations) != 1 {
		t.Fatalf("expected grant observation, got %+v", observations)
	}
	event.Groups[0] = "changed"
	event.Subjects[0].Name = "changed"
	event.Subjects[1].Namespace = "changed"
	event.RoleRefName = "changed"
	if !reflect.DeepEqual(*observations[0].Kubernetes, want) {
		t.Fatalf("retained audit evidence changed: %+v", observations[0].Kubernetes)
	}
	out, err := kubernetesFindingOutput(Finding{Observation: observations[0]})
	if err != nil {
		t.Fatal(err)
	}
	if out.Resource == nil || out.Resource.ResourceType == nil || string(*out.Resource.ResourceType) != "EKSCluster" ||
		out.Service == nil || out.Service.Action == nil || out.Service.Action.ActionType == nil ||
		string(*out.Service.Action.ActionType) != "KUBERNETES_API_CALL" {
		t.Fatalf("incorrect finding resource or action: %+v", out)
	}
	action := out.Service.Action.KubernetesApiCallAction
	if action == nil || action.ResourceName == nil || string(*action.ResourceName) != want.Name ||
		action.RequestUri == nil || string(*action.RequestUri) != want.RequestURI {
		t.Fatalf("native action metadata not retained: %+v", action)
	}
	if out.Service.AdditionalInfo == nil || out.Service.AdditionalInfo.Value == nil {
		t.Fatal("missing retained evidence")
	}
	var additional struct {
		RoleRef struct {
			APIGroup string `json:"apiGroup"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
		} `json:"roleRef"`
		Subjects []struct {
			APIGroup  string `json:"apiGroup"`
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"subjects"`
	}
	if err := json.Unmarshal([]byte(*out.Service.AdditionalInfo.Value), &additional); err != nil {
		t.Fatal(err)
	}
	if additional.RoleRef.APIGroup != want.RoleRefAPIGroup || additional.RoleRef.Kind != want.RoleRefKind || additional.RoleRef.Name != want.RoleRefName {
		t.Fatalf("role reference not retained: %+v", additional.RoleRef)
	}
	gotSubjects := make([]journal.KubernetesSubject, len(additional.Subjects))
	for i, subject := range additional.Subjects {
		gotSubjects[i] = journal.KubernetesSubject{APIGroup: subject.APIGroup, Kind: subject.Kind, Name: subject.Name, Namespace: subject.Namespace}
	}
	if !reflect.DeepEqual(gotSubjects, want.Subjects) {
		t.Fatalf("ordered subjects not retained: got %+v, want %+v", gotSubjects, want.Subjects)
	}
}
