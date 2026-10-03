package integrations

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/services/guardduty"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlguard "stackd/storage/sqlite/guardduty"
	sqljournal "stackd/storage/sqlite/journal"
)

func TestGuardDutyKubernetesSourceTransactionAndDurableAdmission(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, sourceKind := range []string{"credentials", "binding", "custom-threat"} {
			t.Run(backend+"/"+sourceKind, func(t *testing.T) {
				domain := memory.NewDomain()
				var findings guardduty.Repository = guardduty.NewMemoryRepository(domain)
				events := journal.NewMemory(domain)
				reopen := func() {}
				if backend == "sqlite" {
					path := filepath.Join(t.TempDir(), "kubernetes.db")
					db, err := sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = db.Close() })
					findings, events = sqlguard.New(db), sqljournal.New(db)
					reopen = func() {
						if err := db.Close(); err != nil {
							t.Fatal(err)
						}
						db, err = sqlite.Open(t.Context(), path)
						if err != nil {
							t.Fatal(err)
						}
						findings, events = sqlguard.New(db), sqljournal.New(db)
					}
				}
				now := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
				sourceClock := clock.NewManual(now)
				newService := func() *guardduty.Service {
					return guardduty.New(guardduty.Config{Repository: findings, AuditJournal: events, Clock: sourceClock})
				}
				service := newService()
				t.Cleanup(func() { _ = service.Close() })
				restart := func() {
					if err := service.Close(); err != nil {
						t.Fatal(err)
					}
					reopen()
					service = newService()
				}
				scopes := []guardduty.Scope{
					{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"},
					{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"},
					{Partition: "aws", AccountID: "123456789012", Region: "us-west-2"},
					{Partition: "aws-cn", AccountID: "123456789012", Region: "us-east-1"},
				}
				if err := findings.Update(t.Context(), func(tx guardduty.Transaction) error {
					for _, sc := range scopes {
						if err := tx.PutDetector(guardduty.Detector{Scope: sc, ID: "detector", Status: "ENABLED", Created: now, Updated: now,
							ARN:      "arn:" + sc.Partition + ":guardduty:" + sc.Region + ":" + sc.AccountID + ":detector/detector",
							Features: []guardduty.Feature{{Name: "EKS_AUDIT_LOGS", Status: "ENABLED"}}}); err != nil {
							return err
						}
					}
					if sourceKind == "custom-threat" {
						list := guardduty.IPList{Scope: scopes[0], DetectorID: "detector", Kind: guardduty.ThreatIPList, ID: "threat", Name: "owned-native-threat", Status: "ACTIVE"}
						if err := tx.PutIPList(list); err != nil {
							return err
						}
						return tx.ReplaceIPRanges(list.Scope, list.DetectorID, list.Kind, list.ID, []guardduty.IPRange{{First: 0x08080808, Last: 0x08080808}})
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				envelope := journal.Envelope{At: now, Partition: scopes[0].Partition, AccountID: scopes[0].AccountID, Region: scopes[0].Region}
				a := journal.KubernetesAuditObserved{
					ClusterARN: "arn:aws:eks:us-east-1:123456789012:cluster/audit-source", ClusterID: "cluster-incarnation", ClusterName: "audit-source",
					AuditID: "audit-A", Stage: "ResponseComplete", Verb: "get", RequestURI: "/api/v1/namespaces/default/secrets/dummy",
					UserName: "system:anonymous", UserUID: "native-user-id", ActorUserName: "operator", Groups: []string{"system:unauthenticated", "audit-readers"},
					SourceIP: "192.0.2.23", Namespace: "default", Resource: "secrets", Name: "dummy", UserAgent: "audit-fixture/1", APIVersion: "v1",
					ResponseCode: 200, NativeAt: now.Add(-time.Second),
				}
				findingType := "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess"
				if sourceKind == "binding" {
					a.Verb, a.Resource, a.Name = "create", "rolebindings", "anonymous-proof"
					a.RequestURI = "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings"
					a.UserName, a.Groups, a.ResponseCode = "operator", []string{"system:authenticated", "audit-writers"}, 201
					a.RoleRefAPIGroup, a.RoleRefKind, a.RoleRefName = "rbac.authorization.k8s.io", "Role", "read-pods"
					a.Subjects = []journal.KubernetesSubject{
						{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "system:anonymous"},
						{APIGroup: "rbac.authorization.k8s.io", Kind: "Group", Name: "system:unauthenticated"},
						{Kind: "ServiceAccount", Name: "reader", Namespace: "default"},
					}
					findingType = "Policy:Kubernetes/AnonymousAccessGranted"
				}
				if sourceKind == "custom-threat" {
					a.UserName, a.Groups, a.SourceIP, a.ResponseCode = "operator", []string{"system:authenticated"}, "8.8.8.8", 403
					findingType = "CredentialAccess:Kubernetes/MaliciousIPCaller.Custom"
				}
				checkFindings := func(wantPrimary, wantOther int64, latest journal.KubernetesAuditObserved) {
					t.Helper()
					if err := findings.View(t.Context(), func(r guardduty.Reader) error {
						for i, sc := range scopes {
							rows, err := r.Findings(sc, "detector")
							if err != nil {
								return err
							}
							var want int64
							if i == 0 {
								want = wantPrimary
							} else if i == 1 {
								want = wantOther
							}
							if want == 0 {
								if len(rows) != 0 {
									t.Fatalf("scope %+v unexpectedly retained findings: %+v", sc, rows)
								}
								continue
							}
							if len(rows) != 1 || rows[0].Count != want || rows[0].Observation.Type != findingType {
								t.Fatalf("scope %+v: got %+v, want %s with count %d", sc, rows, findingType, want)
							}
							if i == 0 && !reflect.DeepEqual(rows[0].Observation.Kubernetes, &latest) {
								t.Fatalf("retained native finding evidence=%+v, want %+v", rows[0].Observation.Kubernetes, latest)
							}
							if sourceKind == "custom-threat" && !slices.Equal(rows[0].Observation.ThreatListNames, []string{"owned-native-threat"}) {
								t.Fatalf("lost threat-list evidence: %+v", rows[0].Observation)
							}
							if rows[0].Observation.Kubernetes == nil || !slices.Equal(rows[0].Observation.Kubernetes.Groups, a.Groups) {
								t.Fatalf("native finding lost groups: %+v", rows[0].Observation.Kubernetes)
							}
							// Repository reads must not expose mutable stored group slices.
							rows[0].Observation.Kubernetes.Groups[0] = "mutated-reader-group"
							if len(rows[0].Observation.Kubernetes.Subjects) > 0 {
								rows[0].Observation.Kubernetes.Subjects[0].Name = "mutated-reader-subject"
							}
							single, err := r.Finding(sc, "detector", rows[0].ID)
							if err != nil {
								return err
							}
							if i == 0 && !reflect.DeepEqual(single.Observation.Kubernetes, &latest) {
								t.Fatalf("single read lost or aliased native evidence: %+v", single.Observation.Kubernetes)
							}
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				checkJournal := func(want ...journal.KubernetesAuditObserved) {
					t.Helper()
					rows, err := events.Read(t.Context(), 0, 100)
					if err != nil {
						t.Fatal(err)
					}
					if len(rows) != len(want) {
						t.Fatalf("native journal has %d rows, want %d: %+v", len(rows), len(want), rows)
					}
					for i, row := range rows {
						if !reflect.DeepEqual(row.KubernetesAuditObserved, &want[i]) {
							t.Fatalf("native journal row %d=%+v, want %+v", i, row.KubernetesAuditObserved, want[i])
						}
						row.KubernetesAuditObserved.Groups[0] = "mutated-journal-reader-group"
						if len(row.KubernetesAuditObserved.Subjects) > 0 {
							row.KubernetesAuditObserved.Subjects[0].Name = "mutated-journal-reader-subject"
						}
					}
				}
				rejected := errors.New("reject owning transaction")
				err := findings.Update(t.Context(), func(tx guardduty.Transaction) error {
					if err := service.ObserveKubernetesAudit(tx.Context(), envelope, []journal.KubernetesAuditObserved{a}); err != nil {
						return err
					}
					return rejected
				})
				if !errors.Is(err, rejected) {
					t.Fatal(err)
				}
				checkFindings(0, 0, a)
				checkJournal()
				observe := func(e journal.Envelope, audit journal.KubernetesAuditObserved) {
					t.Helper()
					if err := service.ObserveKubernetesAudit(t.Context(), e, []journal.KubernetesAuditObserved{audit}); err != nil {
						t.Fatal(err)
					}
				}
				// Rollback must also release source admission, allowing A to commit.
				observe(envelope, a)
				b := a
				b.AuditID, b.NativeAt = "audit-B", now
				observe(envelope, b)
				checkFindings(2, 0, b)
				checkJournal(a, b)
				restart()
				// A/B/A defeats dedup that retains only a finding's latest event ID.
				observe(envelope, a)
				checkFindings(2, 0, b)
				checkJournal(a, b)
				setEnabled := func(detectorStatus, featureStatus string) {
					t.Helper()
					if err := findings.Update(t.Context(), func(tx guardduty.Transaction) error {
						d, err := tx.Detector(scopes[0], "detector")
						if err != nil {
							return err
						}
						d.Status = detectorStatus
						d.Features = []guardduty.Feature{{Name: "EKS_AUDIT_LOGS", Status: featureStatus}}
						return tx.PutDetector(d)
					}); err != nil {
						t.Fatal(err)
					}
				}
				c, d := a, a
				c.AuditID, d.AuditID = "disabled-detector", "disabled-feature"
				setEnabled("DISABLED", "ENABLED")
				observe(envelope, c)
				setEnabled("ENABLED", "DISABLED")
				observe(envelope, d)
				setEnabled("ENABLED", "ENABLED")
				restart()
				observe(envelope, c)
				observe(envelope, d)
				checkFindings(2, 0, b)
				checkJournal(a, b, c, d)
				// Identical native IDs in another account are a distinct admission and
				// must neither update the first account nor be swallowed by its dedup.
				otherEnvelope, other := envelope, a
				otherEnvelope.AccountID = scopes[1].AccountID
				other.ClusterARN = "arn:aws:eks:us-east-1:222222222222:cluster/audit-source"
				observe(otherEnvelope, other)
				var otherCount int64 = 1
				if sourceKind == "custom-threat" {
					otherCount = 0 // The other account has no active threat list.
				}
				checkFindings(2, otherCount, b)
				checkJournal(a, b, c, d, other)
				// Repeated reads prove mutations of previous read results are detached.
				checkFindings(2, otherCount, b)
				checkJournal(a, b, c, d, other)
			})
		}
	}
}
