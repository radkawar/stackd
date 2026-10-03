package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	eks "stackd/internal/services/eks"
	"stackd/internal/services/iam"
	"stackd/internal/services/sts"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqleks "stackd/storage/sqlite/eks"
	sqliam "stackd/storage/sqlite/iam"
	sqljournal "stackd/storage/sqlite/journal"
)

// These retained IAM/association models exercise the documented trust contract,
// not native credential observations: https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html
// The six transitive attributes are documented in pod-id-abac.html.
type podIdentityRoleFixture struct {
	commands   eks.Repository
	events     journal.Storage
	clock      *clock.Manual
	repository iam.Repository
	owner      *iam.Service
	adapter    EKSPodIdentityRoles
	ctx        context.Context
	request    eks.PodIdentitySession
	role       iam.Role
	tags       map[string]string
}

func newPodIdentityRoleFixture(t *testing.T, backend string) *podIdentityRoleFixture {
	t.Helper()
	f := &podIdentityRoleFixture{clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))}
	key := eks.Key{Scope: eks.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "pod-trust"}
	f.request = eks.PodIdentitySession{Association: eks.PodIdentityAssociation{Key: key, ID: "a-pod-trust", ClusterID: "cluster-incarnation", Namespace: "payments", ServiceAccount: "processor", RoleARN: "arn:aws:iam::123456789012:role/pod", RoleID: "AROAPODTRUST", Tags: map[string]string{"not-a-session-tag": "association-only"}}, PodName: "processor-0", PodUID: "pod-incarnation"}
	f.tags = map[string]string{"eks-cluster-arn": key.ARN(), "eks-cluster-name": "pod-trust", "kubernetes-namespace": "payments", "kubernetes-service-account": "processor", "kubernetes-pod-name": "processor-0", "kubernetes-pod-uid": "pod-incarnation"}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
	switch backend {
	case "memory":
		domain := memory.NewDomain()
		f.repository, f.commands, f.events = iam.NewMemoryRepository(domain), eks.NewMemoryRepository(domain), journal.NewMemory(domain)
	case "sqlite":
		db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "pod-identity.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Error(err)
			}
		})
		f.repository, f.commands, f.events = sqliam.New(db), sqleks.New(db), sqljournal.New(db)
	default:
		t.Fatalf("unknown backend %q", backend)
	}
	store := identity.NewWithConfig(identity.Config{AccountID: key.AccountID, Repository: iam.NewCredentialRepository(f.repository, nil), Clock: f.clock})
	f.owner = iam.NewWithConfig(iam.Config{Repository: f.repository, Credentials: store, Clock: f.clock})
	authorizer := authorization.NewWithClock(f.owner, nil, f.clock)
	authority := podIdentitySTSAuthority{Service: f.owner, credentials: store}
	stsService := sts.NewWithDependencies(sts.Dependencies{Credentials: store, Roles: authority, Sessions: authority, Authorizer: authorizer, Clock: f.clock, APIEvents: apievents.New(f.events)})
	f.adapter = EKSPodIdentityRoles{Roles: ServiceRoles{IAM: f.owner, Credentials: store, Authorizer: authorizer, STS: stsService}, STS: stsService}
	f.role = iam.Role{Arn: f.request.Association.RoleARN, RoleId: f.request.Association.RoleID, RoleName: "pod", MaxSessionDuration: 3600, AssumeRolePolicyDocument: podIdentityTrustPolicy(t, "Service", "pods.eks.amazonaws.com", []string{"sts:AssumeRole", "sts:TagSession"}, nil)}
	f.putRole(t, f.role)
	t.Cleanup(func() { _ = f.owner.Close() })
	return f
}

func (f *podIdentityRoleFixture) putRole(t *testing.T, role iam.Role) {
	t.Helper()
	account := strings.Split(role.Arn, ":")[4]
	if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error {
		return tx.PutRole(iam.Scope{Partition: "aws", AccountID: account}, role)
	}); err != nil {
		t.Fatal(err)
	}
}

func podIdentityTrustPolicy(t *testing.T, kind, principal string, actions []string, conditions map[string]any) string {
	t.Helper()
	statement := map[string]any{"Effect": "Allow", "Principal": map[string]string{kind: principal}, "Action": actions}
	if conditions != nil {
		statement["Condition"] = conditions
	}
	data, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{statement}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f *podIdentityRoleFixture) tagConditions() map[string]any {
	values := map[string]string{}
	for key, value := range f.tags {
		values["aws:RequestTag/"+key] = value
	}
	keys := slices.Sorted(maps.Keys(f.tags))
	return map[string]any{"StringEquals": values, "ForAllValues:StringEquals": map[string][]string{"aws:TagKeys": keys, "sts:TransitiveTagKeys": keys}, "Null": map[string]string{"aws:TagKeys": "false", "sts:TransitiveTagKeys": "false"}}
}

func TestEKSPodIdentityTaggedTrust(t *testing.T) {
	for _, scenario := range []string{"missing TagSession", "explicit TagSession deny", "documented request tags", "wrong namespace", "restricted tag keys", "disabled tags", "disabled conditional tags"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPodIdentityRoleFixture(t, "memory")
			actions := []string{"sts:AssumeRole", "sts:TagSession"}
			var conditions map[string]any
			denied := false
			switch scenario {
			case "missing TagSession":
				actions, denied = []string{"sts:AssumeRole"}, true
			case "explicit TagSession deny":
				denied = true
			case "documented request tags":
				conditions = f.tagConditions()
			case "wrong namespace":
				conditions, denied = f.tagConditions(), true
				f.request.Association.Namespace = "untrusted"
			case "restricted tag keys":
				conditions, denied = f.tagConditions(), true
				conditions["ForAllValues:StringEquals"] = map[string][]string{"aws:TagKeys": {"eks-cluster-name"}}
			case "disabled tags":
				f.request.Association.DisableSessionTags = true
				actions = []string{"sts:AssumeRole"}
				absent := map[string]string{"aws:TagKeys": "true", "sts:TransitiveTagKeys": "true"}
				for key := range f.tags {
					absent["aws:RequestTag/"+key] = "true"
				}
				conditions = map[string]any{"Null": absent}
			case "disabled conditional tags":
				f.request.Association.DisableSessionTags = true
				conditions, denied = f.tagConditions(), true
			}
			f.role.AssumeRolePolicyDocument = podIdentityTrustPolicy(t, "Service", "pods.eks.amazonaws.com", actions, conditions)
			if scenario == "explicit TagSession deny" {
				f.role.AssumeRolePolicyDocument = `{"Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]},{"Effect":"Deny","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":"sts:TagSession"}]}`
			}
			f.putRole(t, f.role)
			issued, err := f.adapter.AssumePodIdentity(f.ctx, f.request)
			if denied {
				requirePodIdentityAccessDenied(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.requireCredential(t, issued, f.role, f.request.Association.DisableSessionTags)
		})
	}
}

func requirePodIdentityAccessDenied(t *testing.T, err error) {
	t.Helper()
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.Code != "AccessDenied" {
		t.Fatalf("expected trust denial, got %v", err)
	}
}

func (f *podIdentityRoleFixture) requireCredential(t *testing.T, issued identity.Credential, role iam.Role, disabled bool) {
	t.Helper()
	retained, err := f.adapter.Roles.Credentials.Resolve(f.ctx, issued.AccessKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.IssuerARN != role.Arn || retained.IssuerID != role.RoleId || retained.SecretAccessKey != issued.SecretAccessKey || retained.SessionToken != issued.SessionToken {
		t.Fatal("returned credentials do not resolve to the current workload role")
	}
	if disabled {
		if len(retained.SessionTags) != 0 || len(retained.TransitiveTagKeys) != 0 {
			t.Fatalf("disabled association leaked session tags: %+v", retained.SessionTags)
		}
		return
	}
	if !maps.Equal(retained.SessionTags, f.tags) || !slices.Equal(retained.TransitiveTagKeys, slices.Sorted(maps.Keys(f.tags))) {
		t.Fatalf("workload credentials lost the documented six transitive tags: %v %v", retained.SessionTags, retained.TransitiveTagKeys)
	}
}

func TestEKSPodIdentityTargetRoleTrust(t *testing.T) {
	for _, scenario := range []string{"transitive tags", "missing target TagSession", "target request tag mismatch", "disabled tags"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPodIdentityRoleFixture(t, "memory")
			f.request.Association.TargetRoleARN = "arn:aws:iam::999999999999:role/target"
			f.request.Association.TargetRoleID = "AROAPODTARGET"
			f.request.Association.ExternalID = "association-external-id"
			f.role.IdentityPolicies.Inline = map[string]string{"chain": `{"Statement":{"Effect":"Allow","Action":["sts:AssumeRole","sts:TagSession"],"Resource":"arn:aws:iam::999999999999:role/target"}}`}
			f.putRole(t, f.role)
			conditions := f.tagConditions()
			conditions["StringEquals"].(map[string]string)["sts:ExternalId"] = f.request.Association.ExternalID
			actions := []string{"sts:AssumeRole", "sts:TagSession"}
			switch scenario {
			case "missing target TagSession":
				actions = []string{"sts:AssumeRole"}
			case "target request tag mismatch":
				conditions["StringEquals"].(map[string]string)["aws:RequestTag/kubernetes-namespace"] = "untrusted"
			case "disabled tags":
				f.request.Association.DisableSessionTags = true
				actions = []string{"sts:AssumeRole"}
				conditions = map[string]any{"StringEquals": map[string]string{"sts:ExternalId": f.request.Association.ExternalID}, "Null": map[string]string{"aws:TagKeys": "true", "sts:TransitiveTagKeys": "true"}}
			}
			target := iam.Role{Arn: f.request.Association.TargetRoleARN, RoleId: f.request.Association.TargetRoleID, RoleName: "target", MaxSessionDuration: 3600, AssumeRolePolicyDocument: podIdentityTrustPolicy(t, "AWS", f.role.Arn, actions, conditions), TrustPrincipalIDs: map[string]string{f.role.Arn: f.role.RoleId}}
			// The final role's ABAC policy consumes the inherited pod identity.
			target.IdentityPolicies.Inline = map[string]string{"read": `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::pod-data/*","Condition":{"StringEquals":{"aws:PrincipalTag/kubernetes-namespace":"payments","aws:PrincipalTag/kubernetes-service-account":"processor"}}}}`}
			f.putRole(t, target)
			issued, err := f.adapter.AssumePodIdentity(f.ctx, f.request)
			if scenario == "missing target TagSession" || scenario == "target request tag mismatch" {
				requirePodIdentityAccessDenied(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.requireCredential(t, issued, target, f.request.Association.DisableSessionTags)
			metadata, err := identity.RequestMetadata(issued, issued.AccessKeyID, f.request.Association.Key.Region, "pod-consumer")
			if err != nil {
				t.Fatal(err)
			}
			rejected := f.adapter.Roles.Authorizer.Authorize(awsctx.WithMetadata(f.ctx, metadata), authorization.Request{Action: "s3:GetObject", ResourceARN: "arn:aws:s3:::pod-data/item"})
			if f.request.Association.DisableSessionTags {
				if rejected == nil || rejected.Code != "AccessDenied" {
					t.Fatalf("untagged session obtained tagged resource access: %v", rejected)
				}
			} else if rejected != nil {
				t.Fatalf("chained pod credentials lost ABAC access: %v", rejected)
			}
		})
	}
}

func TestEKSPodIdentityTargetOutcomeBoundary(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, scenario := range []string{"target denial after exchange rollback", "successful exchange"} {
				t.Run(scenario, func(t *testing.T) {
					f := newPodIdentityRoleFixture(t, backend)
					association := &f.request.Association
					association.TargetRoleARN = "arn:aws:iam::123456789012:role/target"
					association.TargetRoleID = "AROAPODTARGET"
					association.ExternalID = "association-external-id"
					f.role.IdentityPolicies.Inline = map[string]string{"chain": `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::123456789012:role/target"}}`}
					f.putRole(t, f.role)
					actions := []string{"sts:AssumeRole"}
					if scenario == "successful exchange" {
						actions = append(actions, "sts:TagSession")
					}
					target := iam.Role{Arn: association.TargetRoleARN, RoleId: association.TargetRoleID, RoleName: "target", MaxSessionDuration: 3600, AssumeRolePolicyDocument: podIdentityTrustPolicy(t, "AWS", f.role.Arn, actions, map[string]any{"StringEquals": map[string]string{"sts:ExternalId": association.ExternalID}}), TrustPrincipalIDs: map[string]string{f.role.Arn: f.role.RoleId}}
					f.putRole(t, target)
					ctx, outcomes := apievents.RetainOutcomes(f.ctx)
					var issued identity.Credential
					err := f.commands.Attempt(ctx, func(tx eks.Transaction) error {
						var rejection error
						issued, rejection = f.adapter.AssumePodIdentity(tx.Context(), f.request)
						return rejection
					})
					if scenario == "target denial after exchange rollback" {
						requirePodIdentityAccessDenied(t, err)
						if issued.AccessKeyID != "" {
							t.Fatal("rejected target assumption returned credentials")
						}
						if err := f.repository.View(f.ctx, func(tx iam.ReadTx) error {
							for _, role := range []iam.Role{f.role, target} {
								records, err := tx.PrincipalCredentials(association.Key.AccountID, role.RoleId)
								if err != nil {
									return err
								}
								if len(records) != 0 {
									t.Fatalf("failed exchange retained credentials for %s", role.Arn)
								}
							}
							return nil
						}); err != nil {
							t.Fatal(err)
						}
						before, err := f.events.Read(f.ctx, 0, 100)
						if err != nil {
							t.Fatal(err)
						}
						if len(before) != 0 {
							t.Fatal("failed exchange committed an issuance or outcome before rollback completion")
						}
						completion, cancel := apievents.CompletionContext(ctx)
						defer cancel()
						if err := outcomes.Record(completion); err != nil {
							t.Fatal(err)
						}
						recorded, err := f.events.Read(f.ctx, 0, 100)
						if err != nil {
							t.Fatal(err)
						}
						if len(recorded) != 1 {
							t.Fatalf("expected only the retained STS denial, got %d events", len(recorded))
						}
						call := recorded[0].APICallCompleted
						if call == nil || call.EventSource != "sts.amazonaws.com" || call.EventName != "AssumeRole" || call.ErrorCode != "AccessDenied" {
							t.Fatalf("target denial was lost or changed: %+v", call)
						}
						var input struct {
							RoleARN string `json:"roleArn"`
						}
						if err := json.Unmarshal(call.RequestParameters, &input); err != nil {
							t.Fatal(err)
						}
						if input.RoleARN != target.Arn || !strings.HasPrefix(recorded[0].ActorARN, "arn:aws:sts::123456789012:assumed-role/pod/") {
							t.Fatalf("retained rejection lost its target or caller: %+v", recorded[0])
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					f.requireCredential(t, issued, target, false)
					recorded, err := f.events.Read(f.ctx, 0, 100)
					if err != nil {
						t.Fatal(err)
					}
					if len(recorded) != 2 {
						t.Fatalf("expected both committed role assumptions, got %d events", len(recorded))
					}
					roles := map[string]bool{}
					for _, event := range recorded {
						call := event.APICallCompleted
						if call == nil || call.EventSource != "sts.amazonaws.com" || call.EventName != "AssumeRole" || call.ErrorCode != "" {
							t.Fatalf("successful exchange did not commit its STS outcomes: %+v", call)
						}
						var input struct {
							RoleARN string `json:"roleArn"`
						}
						if err := json.Unmarshal(call.RequestParameters, &input); err != nil {
							t.Fatal(err)
						}
						roles[input.RoleARN] = true
					}
					if !roles[f.role.Arn] || !roles[target.Arn] {
						t.Fatalf("successful exchange omitted an assumption: %v", roles)
					}
				})
			}
		})
	}
}

// Bridge the existing consumer-defined IAM and STS contracts without replacing
// role lookup, trust evaluation, transaction ownership or credential issuance.
type podIdentitySTSAuthority struct {
	*iam.Service
	credentials *identity.Store
}

func (a podIdentitySTSAuthority) RoleForAssumption(ctx context.Context, arn string) (sts.RoleSnapshot, error) {
	role, err := a.Service.RoleForAssumption(ctx, arn)
	return sts.RoleSnapshot{ARN: role.ARN, ID: role.ID, Name: role.Name, TrustPolicy: role.TrustPolicy, TrustPrincipalIDs: role.TrustPrincipalIDs, MaxSessionDuration: role.MaxSessionDuration, Tags: role.Tags, ServiceLinkedRole: role.ServiceLinkedRole}, err
}

func (a podIdentitySTSAuthority) WithSession(ctx context.Context, _ string, fn func(context.Context, sts.CredentialStore, time.Time) error) error {
	return a.Service.WithSession(ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
		return fn(ctx, a.credentials.WithRepositoryAt(repository, now), now)
	})
}
