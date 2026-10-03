package organizations_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	provider "stackd/internal/services/organizations"
)

type accessReportGraph struct {
	service                              *provider.Service
	storage                              provider.Storage
	client                               *sdk.Client
	ctx                                  context.Context
	root, unit, nested                   string
	rootPath, unitPath, nestedPath       string
	rootAccount, unitAccount, subAccount string
}

func newAccessReportGraph(t *testing.T) accessReportGraph {
	t.Helper()
	storage := provider.NewMemoryStorage(nil)
	s := organizationsOnly(storage)
	client := fixedClient(t, s, orgRoot(managementID, "aws"))
	root := createOrg(t, client)
	org, err := client.DescribeOrganization(t.Context(), &sdk.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	unit, err := client.CreateOrganizationalUnit(t.Context(), &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(root), Name: aws.String("report-parent")})
	if err != nil {
		t.Fatal(err)
	}
	nested, err := client.CreateOrganizationalUnit(t.Context(), &sdk.CreateOrganizationalUnitInput{ParentId: unit.OrganizationalUnit.Id, Name: aws.String("report-child")})
	if err != nil {
		t.Fatal(err)
	}
	g := accessReportGraph{service: s, storage: storage, client: client,
		ctx:  awsctx.WithMetadata(t.Context(), orgRoot(managementID, "aws")),
		root: root, unit: *unit.OrganizationalUnit.Id, nested: *nested.OrganizationalUnit.Id,
		rootPath:    *org.Organization.Id + "/" + root,
		rootAccount: createAccount(t, client, "report-root"), unitAccount: createAccount(t, client, "report-unit"), subAccount: createAccount(t, client, "report-nested"),
	}
	g.unitPath = g.rootPath + "/" + g.unit
	g.nestedPath = g.unitPath + "/" + g.nested
	for _, move := range []struct{ account, parent string }{{g.unitAccount, g.unit}, {g.subAccount, g.nested}} {
		if _, err := client.MoveAccount(t.Context(), &sdk.MoveAccountInput{AccountId: aws.String(move.account), SourceParentId: aws.String(root), DestinationParentId: aws.String(move.parent)}); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func (g accessReportGraph) policy(t *testing.T, name, document string, targets ...string) string {
	t.Helper()
	p, err := g.client.CreatePolicy(t.Context(), &sdk.CreatePolicyInput{Name: aws.String(name), Description: aws.String("access report test"), Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(document)})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if _, err := g.client.AttachPolicy(t.Context(), &sdk.AttachPolicyInput{PolicyId: p.Policy.PolicySummary.Id, TargetId: aws.String(target)}); err != nil {
			t.Fatal(err)
		}
	}
	return *p.Policy.PolicySummary.Id
}

func TestAccessReportSnapshotEntityHierarchy(t *testing.T) {
	g := newAccessReportGraph(t)
	unitDoc := allowAction("s3:*", "*")
	nestedDoc := allowAction("sqs:*", "*")
	accountDoc := allowAction("iam:*", "*")
	g.policy(t, "unit-report", unitDoc, g.unit)
	g.policy(t, "nested-report", nestedDoc, g.nested)
	g.policy(t, "account-report", accountDoc, g.subAccount)
	cases := []struct {
		name, path string
		targets    []string
		accounts   []provider.AccessReportAccount
	}{
		{"root", g.rootPath, []string{g.root}, []provider.AccessReportAccount{
			{AccountID: g.rootAccount, EntityPath: g.rootPath + "/" + g.rootAccount},
			{AccountID: g.unitAccount, EntityPath: g.unitPath + "/" + g.unitAccount},
			{AccountID: g.subAccount, EntityPath: g.nestedPath + "/" + g.subAccount},
		}},
		{"unit", g.unitPath, []string{g.root, g.unit}, []provider.AccessReportAccount{
			{AccountID: g.unitAccount, EntityPath: g.unitPath + "/" + g.unitAccount},
			{AccountID: g.subAccount, EntityPath: g.nestedPath + "/" + g.subAccount},
		}},
		{"nested", g.nestedPath, []string{g.root, g.unit, g.nested}, []provider.AccessReportAccount{
			{AccountID: g.subAccount, EntityPath: g.nestedPath + "/" + g.subAccount},
		}},
		{"account", g.nestedPath + "/" + g.subAccount, []string{g.root, g.unit, g.nested, g.subAccount}, []provider.AccessReportAccount{
			{AccountID: g.subAccount, EntityPath: g.nestedPath + "/" + g.subAccount},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, err := g.service.AccessReportSnapshot(g.ctx, tc.path, "")
			if err != nil {
				t.Fatal(err)
			}
			var targets []string
			for _, level := range snapshot.PolicyLevels {
				targets = append(targets, level.TargetID)
			}
			if !reflect.DeepEqual(targets, tc.targets) {
				t.Fatalf("unexpected entity selection: %+v", snapshot)
			}
			if !reflect.DeepEqual(snapshot.Accounts, tc.accounts) {
				t.Fatalf("accounts=%+v, want %+v", snapshot.Accounts, tc.accounts)
			}
			for _, entry := range []struct{ target, doc string }{{g.unit, unitDoc}, {g.nested, nestedDoc}, {g.subAccount, accountDoc}} {
				found := false
				for _, level := range snapshot.PolicyLevels {
					found = found || slices.ContainsFunc(level.Documents, func(p iampolicy.Policy) bool { return p.Document == entry.doc })
				}
				if found != slices.Contains(tc.targets, entry.target) {
					t.Fatalf("report includes policy from outside selected hierarchy: %s %+v", entry.target, snapshot.PolicyLevels)
				}
			}
		})
	}
	managementPath := g.rootPath + "/" + managementID
	management, err := g.service.AccessReportSnapshot(g.ctx, managementPath, "p-notfound123")
	if err != nil || len(management.PolicyLevels) != 0 || !reflect.DeepEqual(management.Accounts, []provider.AccessReportAccount{{AccountID: managementID, EntityPath: managementPath}}) {
		t.Fatalf("management account should ignore policy and select only itself: %+v %v", management, err)
	}
}

func TestAccessReportSnapshotOptionalPolicySelection(t *testing.T) {
	g := newAccessReportGraph(t)
	document := allowAction("s3:GetObject", "*")
	unattached := g.policy(t, "unattached", document)
	atRoot := g.policy(t, "at-root", document, g.root)
	atUnit := g.policy(t, "at-unit", document, g.unit)
	atAccount := g.policy(t, "at-account", document, g.subAccount)
	cases := []struct {
		name, path, policy string
		accounts           []string
	}{
		{"unattached", g.rootPath, unattached, nil},
		{"root all members", g.rootPath, atRoot, []string{g.rootAccount, g.unitAccount, g.subAccount}},
		{"root only unit members", g.rootPath, atUnit, []string{g.unitAccount, g.subAccount}},
		{"unit includes descendants", g.unitPath, atUnit, []string{g.unitAccount, g.subAccount}},
		{"unit only attached child", g.unitPath, atAccount, []string{g.subAccount}},
		{"unit excludes above-root attachment", g.unitPath, atRoot, nil},
		{"account direct attachment", g.nestedPath + "/" + g.subAccount, atAccount, []string{g.subAccount}},
		{"account excludes inherited attachment", g.nestedPath + "/" + g.subAccount, atUnit, nil},
		{"outside unit", g.rootPath + "/" + g.rootAccount, atUnit, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, err := g.service.AccessReportSnapshot(g.ctx, tc.path, tc.policy)
			if err != nil {
				t.Fatal(err)
			}
			var accounts []string
			for _, a := range snapshot.Accounts {
				accounts = append(accounts, a.AccountID)
			}
			if !reflect.DeepEqual(accounts, tc.accounts) || len(snapshot.PolicyLevels) != 1 || len(snapshot.PolicyLevels[0].Documents) != 1 || snapshot.PolicyLevels[0].Documents[0].Document != document {
				t.Fatalf("policy selection: %+v, expected accounts %v", snapshot, tc.accounts)
			}
		})
	}
}

func TestAccessReportSnapshotRejectsForeignAndInvalidSelections(t *testing.T) {
	g := newAccessReportGraph(t)
	for _, path := range []string{
		"", g.rootPath + "/", g.rootPath + "//", g.rootPath + "/" + g.nested,
		g.unitPath + "/" + g.rootAccount, g.rootPath + "/" + g.subAccount, g.rootPath + "/ou-missing123",
		g.nestedPath + "/" + g.subAccount + "/" + g.unit,
	} {
		if _, err := g.service.AccessReportSnapshot(g.ctx, path, ""); !errors.Is(err, provider.ErrAccessReportEntityNotFound) {
			t.Errorf("path %q: %v", path, err)
		}
	}
	if _, err := g.service.AccessReportSnapshot(g.ctx, strings.Replace(g.rootPath, "o-", "o-x", 1), ""); !errors.Is(err, provider.ErrAccessReportWrongOrganization) {
		t.Fatalf("foreign organization path: %v", err)
	}
	for _, meta := range []awsctx.Metadata{{}, orgRoot(g.unitAccount, "aws"), orgRoot("999999999999", "aws"), orgRoot(managementID, "aws-us-gov")} {
		ctx := awsctx.WithMetadata(t.Context(), meta)
		if _, err := g.service.AccessReportSnapshot(ctx, g.rootPath, ""); !errors.Is(err, provider.ErrAccessReportManagementRequired) {
			t.Errorf("caller %+v: %v", meta, err)
		}
		if err := g.service.CheckAccessReportAccess(ctx); !errors.Is(err, provider.ErrAccessReportManagementRequired) {
			t.Errorf("current caller eligibility %+v: %v", meta, err)
		}
	}
	// A separate partition can have its own organization for the same caller.
	gov := fixedClient(t, g.service, orgRoot(managementID, "aws-us-gov"))
	createOrg(t, gov)
	if _, err := g.service.AccessReportSnapshot(awsctx.WithMetadata(t.Context(), orgRoot(managementID, "aws-us-gov")), g.rootPath, ""); !errors.Is(err, provider.ErrAccessReportWrongOrganization) {
		t.Fatalf("path escaped partition: %v", err)
	}
	if _, err := g.service.AccessReportSnapshot(g.ctx, g.rootPath, "p-missing123"); !errors.Is(err, provider.ErrAccessReportPolicyNotFound) {
		t.Fatalf("missing policy: %v", err)
	}
	if _, err := g.client.EnablePolicyType(t.Context(), &sdk.EnablePolicyTypeInput{RootId: aws.String(g.root), PolicyType: types.PolicyTypeTagPolicy}); err != nil {
		t.Fatal(err)
	}
	otherPolicy, err := g.client.CreatePolicy(t.Context(), &sdk.CreatePolicyInput{Name: aws.String("tag-policy"), Description: aws.String("not an SCP"), Type: types.PolicyTypeTagPolicy, Content: aws.String(`{"tags":{}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.service.AccessReportSnapshot(g.ctx, g.rootPath, *otherPolicy.Policy.PolicySummary.Id); !errors.Is(err, provider.ErrAccessReportPolicyNotFound) {
		t.Fatalf("non-SCP policy: %v", err)
	}
	if _, err := g.client.DisablePolicyType(t.Context(), &sdk.DisablePolicyTypeInput{RootId: aws.String(g.root), PolicyType: types.PolicyTypeServiceControlPolicy}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.service.AccessReportSnapshot(g.ctx, g.rootPath, ""); !errors.Is(err, provider.ErrAccessReportSCPDisabled) {
		t.Fatalf("SCP disabled: %v", err)
	}
	if err := g.service.CheckAccessReportAccess(g.ctx); !errors.Is(err, provider.ErrAccessReportSCPDisabled) {
		t.Fatalf("current SCP eligibility: %v", err)
	}
}

func TestAccessReportSnapshotDetachedReadAndCurrentHierarchy(t *testing.T) {
	g := newAccessReportGraph(t)
	document := allowAction("s3:*", "*")
	policyID := g.policy(t, "snapshot-policy", document, g.unit)
	_, before, err := g.storage.Load(g.ctx, "aws")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := g.service.AccessReportSnapshot(g.ctx, g.unitPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.service.CheckAccessReportAccess(g.ctx); err != nil {
		t.Fatal(err)
	}
	_, after, err := g.storage.Load(g.ctx, "aws")
	if err != nil || before != after {
		t.Fatalf("report read changed Organizations revision: before=%d after=%d err=%v", before, after, err)
	}
	if _, err := g.client.MoveAccount(t.Context(), &sdk.MoveAccountInput{AccountId: aws.String(g.subAccount), SourceParentId: aws.String(g.nested), DestinationParentId: aws.String(g.root)}); err != nil {
		t.Fatal(err)
	}
	replacement := allowAction("sqs:*", "*")
	if _, err := g.client.UpdatePolicy(t.Context(), &sdk.UpdatePolicyInput{PolicyId: aws.String(policyID), Content: aws.String(replacement)}); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Accounts) != 2 || !slices.ContainsFunc(snapshot.PolicyLevels[1].Documents, func(p iampolicy.Policy) bool { return p.Document == document }) {
		t.Fatalf("returned snapshot changed after mutation: %+v", snapshot)
	}
	current, err := g.service.AccessReportSnapshot(g.ctx, g.unitPath, "")
	if err != nil || len(current.Accounts) != 1 || !slices.ContainsFunc(current.PolicyLevels[1].Documents, func(p iampolicy.Policy) bool { return p.Document == replacement }) {
		t.Fatalf("next report did not read current state: %+v %v", current, err)
	}
	current.PolicyLevels[1].Documents[0].Document = "caller mutation"
	current.Accounts[0].EntityPath = "caller mutation"
	again, err := g.service.AccessReportSnapshot(g.ctx, g.unitPath, "")
	if err != nil || !slices.ContainsFunc(again.PolicyLevels[1].Documents, func(p iampolicy.Policy) bool { return p.Document == replacement }) || again.Accounts[0].EntityPath != g.unitPath+"/"+g.unitAccount {
		t.Fatalf("snapshot mutation reached storage: %+v %v", again, err)
	}
	if _, err := g.service.AccessReportSnapshot(g.ctx, g.nestedPath+"/"+g.subAccount, ""); !errors.Is(err, provider.ErrAccessReportEntityNotFound) {
		t.Fatalf("stale account path accepted after move: %v", err)
	}
}

type accessReportReadStorage struct {
	provider.Storage
	err    error
	cancel context.CancelFunc
}

func (s accessReportReadStorage) Load(ctx context.Context, partition string) (provider.PartitionRecord, uint64, error) {
	if s.err != nil {
		return provider.PartitionRecord{}, 0, s.err
	}
	record, revision, err := s.Storage.Load(ctx, partition)
	if s.cancel != nil {
		s.cancel()
	}
	return record, revision, err
}

func TestAccessReportSnapshotCancellationAndStorageFailure(t *testing.T) {
	g := newAccessReportGraph(t)
	failure := errors.New("read unavailable")
	s := provider.NewWithStorage(accessReportReadStorage{Storage: g.storage, err: failure})
	if _, err := s.AccessReportSnapshot(g.ctx, g.rootPath, ""); !errors.Is(err, failure) {
		t.Fatalf("storage failure: %v", err)
	}
	for _, during := range []bool{false, true} {
		ctx, cancel := context.WithCancel(g.ctx)
		store := accessReportReadStorage{Storage: g.storage}
		if during {
			store.cancel = cancel
		} else {
			cancel()
		}
		s := provider.NewWithStorage(store)
		out, err := s.AccessReportSnapshot(ctx, g.rootPath, "")
		cancel()
		if !errors.Is(err, context.Canceled) || len(out.PolicyLevels) != 0 || len(out.Accounts) != 0 {
			t.Fatalf("canceled snapshot leaked partial selection: %+v %v", out, err)
		}
		if err := s.CheckAccessReportAccess(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled eligibility read: %v", err)
		}
	}
}

func TestAccessReportSnapshotDependencyPermissions(t *testing.T) {
	g := newAccessReportGraph(t)
	policyID := g.policy(t, "permission-policy", allowAction("s3:*", "*"), g.unit)
	identities := &identityPolicies{}
	g.service.SetAuthorizer(authorization.New(identities, orgControlSource{g.service}))
	m := orgRoot(managementID, "aws")
	m.PrincipalARN = "arn:aws:iam::" + managementID + ":user/report-reader"
	m.PrincipalID = "AIDAREPORTREADER00001"
	ctx := awsctx.WithMetadata(t.Context(), m)
	allow, err := json.Marshal(map[string]any{"Statement": []any{
		map[string]any{"Effect": "Allow", "Action": "organizations:ListRoots", "Resource": "*"},
		map[string]any{"Effect": "Allow", "Action": []string{"organizations:DescribePolicy", "organizations:ListParents", "organizations:ListPoliciesForTarget", "organizations:ListChildren", "organizations:ListTargetsForPolicy"}, "Resource": []string{"arn:aws:organizations::" + managementID + ":*", "arn:aws:organizations::aws:policy/*"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action                  string
		selected, withoutPolicy bool
	}{
		{"DescribePolicy", false, false},
		{"ListParents", false, false},
		{"ListPoliciesForTarget", false, false},
		{"ListRoots", false, false},
		{"ListChildren", true, false},
		{"ListTargetsForPolicy", false, true},
	} {
		t.Run(tc.action, func(t *testing.T) {
			deny, err := json.Marshal(map[string]any{"Statement": map[string]any{"Effect": "Deny", "Action": "organizations:" + tc.action, "Resource": "*"}})
			if err != nil {
				t.Fatal(err)
			}
			identities.set(string(allow), string(deny))
			for _, selection := range []struct {
				policy string
				allow  bool
			}{{policyID, tc.selected}, {"", tc.withoutPolicy}} {
				_, err := g.service.AccessReportSnapshot(ctx, g.unitPath, selection.policy)
				if selection.allow && err != nil || !selection.allow && !errors.Is(err, provider.ErrAccessReportReadDenied) {
					t.Fatalf("denied action=%s, selected=%t, error=%v", tc.action, selection.policy != "", err)
				}
			}
		})
	}
	identities.set(string(allow))
	for _, selection := range []string{"", policyID} {
		if _, err := g.service.AccessReportSnapshot(ctx, g.unitPath, selection); err != nil {
			t.Fatalf("scoped resource permissions rejected: %v", err)
		}
	}
	// The captured root and management controls omit reads that the selected
	// entity does not need, even when the caller explicitly denies those reads.
	for _, tc := range []struct{ path, policy, denied string }{
		{g.rootPath, "", "ListParents"},
		{g.rootPath + "/" + managementID, policyID, "ListTargetsForPolicy"},
	} {
		deny, err := json.Marshal(map[string]any{"Statement": map[string]any{"Effect": "Deny", "Action": "organizations:" + tc.denied, "Resource": "*"}})
		if err != nil {
			t.Fatal(err)
		}
		identities.set(string(allow), string(deny))
		if _, err := g.service.AccessReportSnapshot(ctx, tc.path, tc.policy); err != nil {
			t.Fatalf("unneeded %s permission required for %s: %v", tc.denied, tc.path, err)
		}
	}
	identities.set(strings.ReplaceAll(string(allow), managementID, "999999999999"))
	if _, err := g.service.AccessReportSnapshot(ctx, g.unitPath, policyID); !errors.Is(err, provider.ErrAccessReportReadDenied) {
		t.Fatalf("foreign resource grant authorized selected organization: %v", err)
	}
	identities.set(`{"Statement":{"Effect":"Deny","Action":"organizations:*","Resource":"*"}}`)
	if err := g.service.CheckAccessReportAccess(ctx); err != nil {
		t.Fatalf("retrieval eligibility incorrectly requires Organizations reads: %v", err)
	}
}

type accessReportAuthorizer func(context.Context, authorization.Request) *awswire.Error

func (f accessReportAuthorizer) Authorize(ctx context.Context, request authorization.Request) *awswire.Error {
	return f(ctx, request)
}

func TestAccessReportSnapshotDependencyTimeAndFailures(t *testing.T) {
	g := newAccessReportGraph(t)
	clock := clock.NewManual(time.Time{})
	s := provider.NewWithConfig(provider.Config{Storage: g.storage, Clock: clock})
	permissions := 0
	s.SetAuthorizer(accessReportAuthorizer(func(ctx context.Context, request authorization.Request) *awswire.Error {
		permissions++
		if request.EvaluationTime == nil || !request.EvaluationTime.IsZero() {
			t.Fatalf("permission did not preserve one evaluation instant: %+v", request)
		}
		if err := clock.Advance(time.Minute); err != nil {
			t.Fatal(err)
		}
		// The snapshot keeps its source-scoped management SCP exemption without
		// acquiring the Organizations storage again during IAM authorization.
		levels, err := s.ServiceControlPolicies(ctx, managementID)
		if err != nil || len(levels) != 0 {
			t.Fatalf("management SCP context: %+v %v", levels, err)
		}
		return nil
	}))
	if _, err := s.AccessReportSnapshot(g.ctx, g.unitPath, ""); err != nil || permissions < 2 {
		t.Fatalf("dependency evaluation: checks=%d error=%v", permissions, err)
	}
	failure := &awswire.Error{Code: "ServiceFailure", Message: "identity storage unavailable", StatusCode: 500}
	s.SetAuthorizer(accessReportAuthorizer(func(context.Context, authorization.Request) *awswire.Error { return failure }))
	if out, err := s.AccessReportSnapshot(g.ctx, g.unitPath, ""); !errors.Is(err, failure) || len(out.Accounts) != 0 {
		t.Fatalf("infrastructure failure converted to denial or leaked snapshot: %+v %v", out, err)
	}
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	s.SetAuthorizer(accessReportAuthorizer(func(context.Context, authorization.Request) *awswire.Error { cancel(); return nil }))
	if out, err := s.AccessReportSnapshot(ctx, g.unitPath, ""); !errors.Is(err, context.Canceled) || len(out.Accounts) != 0 {
		t.Fatalf("cancellation during authorization leaked snapshot: %+v %v", out, err)
	}
}
