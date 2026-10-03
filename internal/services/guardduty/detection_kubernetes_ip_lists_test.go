package guardduty

import (
	"reflect"
	"testing"

	"stackd/journal"
)

func TestKubernetesCustomThreatLists(t *testing.T) {
	s, ctx, detector, _ := filterFixture(t)
	detector.Status = "ENABLED"
	detector.Features = []Feature{{Name: "EKS_AUDIT_LOGS", Status: "ENABLED"}}
	address, _ := listSourceIPv4("8.8.8.8")
	threat := IPList{Scope: detector.Scope, DetectorID: detector.ID, Kind: ThreatIPList, ID: "threat", Name: "owned-threat", Status: "ACTIVE"}
	trusted := IPList{Scope: detector.Scope, DetectorID: detector.ID, Kind: TrustedIPList, ID: "trusted", Name: "owned-trusted", Status: "INACTIVE"}
	store := func(list IPList) {
		t.Helper()
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			if err := tx.PutIPList(list); err != nil {
				return err
			}
			return tx.ReplaceIPRanges(list.Scope, list.DetectorID, list.Kind, list.ID, []IPRange{{First: address, Last: address}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	store(threat)
	store(trusted)
	base := journal.KubernetesAuditObserved{Stage: "ResponseComplete", Verb: "get", Resource: "secrets", Name: "owned",
		RequestURI: "/api/v1/namespaces/default/secrets/owned", ResponseCode: 403, UserName: "operator", Groups: []string{"system:authenticated"}, SourceIP: "8.8.8.8"}
	detect := func(d Detector, e journal.KubernetesAuditObserved) []Observation {
		t.Helper()
		var observed []Observation
		if err := s.repository.View(ctx, func(r Reader) error {
			var err error
			observed, err = detectKubernetesAuditWithLists(r, d, e)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return observed
	}
	for _, tc := range []struct {
		name, verb, resource, subresource, uri, tactic string
		status                                         int32
	}{
		{"denied secrets", "get", "secrets", "", base.RequestURI, "CredentialAccess", 403},
		{"successful secrets", "list", "secrets", "", "/api/v1/namespaces/default/secrets", "CredentialAccess", 200},
		{"discovery", "list", "pods", "", "/api/v1/namespaces/default/pods", "Discovery", 200},
		{"denied discovery", "get", "", "", "/apis", "Discovery", 403},
		{"denied deletion", "delete", "configmaps", "", "/api/v1/namespaces/default/configmaps/owned", "Impact", 403},
		{"bulk deletion", "deletecollection", "jobs", "", "/apis/batch/v1/namespaces/default/jobs", "Impact", 200},
		{"custom group", "get", "secrets", "", "/apis/example.test/v1/secrets/owned", "", 200},
		{"logs subresource", "get", "pods", "log", "/api/v1/namespaces/default/pods/owned/log", "", 200},
		{"health", "get", "", "", "/readyz", "", 200},
		{"unclassified mutation", "patch", "pods", "", "/api/v1/namespaces/default/pods/owned", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			e.Verb, e.Resource, e.Subresource, e.RequestURI, e.ResponseCode = tc.verb, tc.resource, tc.subresource, tc.uri, tc.status
			got := detect(detector, e)
			if tc.tactic == "" {
				if len(got) != 0 {
					t.Fatalf("unclassified API produced %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Type != tc.tactic+":Kubernetes/MaliciousIPCaller.Custom" || !reflect.DeepEqual(got[0].Kubernetes, &e) {
				t.Fatalf("missing native outcome: %+v", got)
			}
			out, err := kubernetesFindingOutput(Finding{Observation: got[0]})
			if err != nil {
				t.Fatal(err)
			}
			if out.Service.Evidence == nil || len(out.Service.Evidence.ThreatIntelligenceDetails) != 1 || value(out.Service.Evidence.ThreatIntelligenceDetails[0].ThreatListName) != threat.Name {
				t.Fatalf("missing public threat provenance: %+v", out.Service.Evidence)
			}
		})
	}
	for _, source := range []string{"1.1.1.1", "127.0.0.1", "10.0.0.1", "192.0.2.1", "::ffff:8.8.8.8", "2001:4860:4860::8888"} {
		e := base
		e.SourceIP = source
		if got := detect(detector, e); len(got) != 0 {
			t.Fatalf("unmatched origin %s produced %+v", source, got)
		}
	}
	for _, stage := range []string{"RequestReceived", "ResponseStarted", "Panic"} {
		e := base
		e.Stage = stage
		if got := detect(detector, e); len(got) != 0 {
			t.Fatalf("nonfinal stage produced %+v", got)
		}
	}
	for _, mutate := range []func(*Detector){
		func(d *Detector) { d.Status = "DISABLED" },
		func(d *Detector) { d.Features = nil },
		func(d *Detector) { d.AccountID = "other" },
		func(d *Detector) { d.Region = "other" },
		func(d *Detector) { d.ID = "other" },
	} {
		d := detector
		mutate(&d)
		if got := detect(d, base); len(got) != 0 {
			t.Fatalf("ineligible detector produced %+v", got)
		}
	}
	trusted.Status = "ACTIVE"
	store(trusted)
	anonymous := base
	anonymous.UserName, anonymous.Groups, anonymous.ResponseCode = "system:anonymous", []string{"system:unauthenticated"}, 200
	if got := detect(detector, anonymous); len(got) != 0 {
		t.Fatalf("trusted origin produced %+v", got)
	}
	trusted.Status = "INACTIVE"
	store(trusted)
	if got := detect(detector, anonymous); len(got) != 2 {
		t.Fatalf("expected independent anonymous and threat findings: %+v", got)
	}
	for _, status := range []string{"INACTIVE", "ACTIVATING", "ERROR", "DELETED"} {
		threat.Status = status
		store(threat)
		if got := detect(detector, base); len(got) != 0 {
			t.Fatalf("%s list produced %+v", status, got)
		}
	}
}
