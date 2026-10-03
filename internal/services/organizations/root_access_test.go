package organizations_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	provider "stackd/internal/services/organizations"
)

const rootAuditPolicyARN = "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials"

func enableRootTrust(t *testing.T, client *sdk.Client, enabled bool) {
	t.Helper()
	var err error
	if enabled {
		_, err = client.EnableAWSServiceAccess(t.Context(), &sdk.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")})
	} else {
		_, err = client.DisableAWSServiceAccess(t.Context(), &sdk.DisableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")})
	}
	if err != nil {
		t.Fatal(err)
	}
}

func requireRootCode(t *testing.T, err error, code string, status int) {
	t.Helper()
	var apiErr *awswire.Error
	if !errors.As(err, &apiErr) || apiErr.Code != code || apiErr.StatusCode != status {
		t.Fatalf("error=%v, want %s HTTP%d", err, code, status)
	}
}

func TestRootAccessFeaturesLifecycleAndStorage(t *testing.T) {
	g := newAccessReportGraph(t)
	_, _, err := g.service.RootAccessFeatures(g.ctx)
	requireRootCode(t, err, "ServiceAccessNotEnabledException", 400)
	enableRootTrust(t, g.client, true)
	id, flags, err := g.service.RootAccessFeatures(g.ctx)
	if err != nil || id == "" || flags != (provider.RootAccessFeatures{}) {
		t.Fatalf("initial features: %s %+v %v", id, flags, err)
	}
	for _, step := range []struct {
		feature provider.RootAccessFeature
		enabled bool
		want    provider.RootAccessFeatures
	}{
		{provider.RootCredentialsManagement, true, provider.RootAccessFeatures{CredentialsManagement: true}},
		{provider.RootSessions, true, provider.RootAccessFeatures{CredentialsManagement: true, Sessions: true}},
		{provider.RootCredentialsManagement, false, provider.RootAccessFeatures{Sessions: true}},
		{provider.RootSessions, false, provider.RootAccessFeatures{}},
		{provider.RootSessions, true, provider.RootAccessFeatures{Sessions: true}},
	} {
		gotID, got, err := g.service.SetRootAccessFeature(g.ctx, step.feature, step.enabled)
		if err != nil || gotID != id || got != step.want {
			t.Fatalf("set %s=%t: %s %+v %v", step.feature, step.enabled, gotID, got, err)
		}
	}
	_, before, err := g.storage.Load(g.ctx, "aws")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.service.SetRootAccessFeature(g.ctx, provider.RootSessions, true); err != nil {
		t.Fatal(err)
	}
	_, after, err := g.storage.Load(g.ctx, "aws")
	if err != nil || before != after {
		t.Fatalf("idempotent enable changed storage: %d %d %v", before, after, err)
	}
	// The ordinary Organizations codec must preserve settings on unrelated writes.
	if _, err := g.client.CreateOrganizationalUnit(t.Context(), &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(g.root), Name: aws.String("preserve-features")}); err != nil {
		t.Fatal(err)
	}
	enableRootTrust(t, g.client, false)
	_, _, err = g.service.RootAccessFeatures(g.ctx)
	requireRootCode(t, err, "ServiceAccessNotEnabledException", 400)
	_, _, err = g.service.SetRootAccessFeature(g.ctx, provider.RootSessions, false)
	requireRootCode(t, err, "ServiceAccessNotEnabledException", 400)
	enableRootTrust(t, g.client, true)
	restored := provider.NewWithStorage(g.storage)
	gotID, got, err := restored.RootAccessFeatures(g.ctx)
	if err != nil || gotID != id || got != (provider.RootAccessFeatures{Sessions: true}) {
		t.Fatalf("trust/reconstruction lost feature state: %s %+v %v", gotID, got, err)
	}
	record, _, err := g.storage.Load(g.ctx, "aws")
	if err != nil || record.Organizations[0].RootAccess != got {
		t.Fatalf("typed stored state: %+v %v", record, err)
	}
	record.Organizations[0].RootAccess.Sessions = false
	_, got, err = restored.RootAccessFeatures(g.ctx)
	if err != nil || !got.Sessions {
		t.Fatalf("detached storage value mutated provider: %+v %v", got, err)
	}
}

func TestRootAccessFeaturesIAMDelegationAndCurrentMembership(t *testing.T) {
	g := newAccessReportGraph(t)
	enableRootTrust(t, g.client, true)
	delegate := awsctx.WithMetadata(t.Context(), orgRoot(g.unitAccount, "aws"))
	_, _, err := g.service.RootAccessFeatures(delegate)
	requireRootCode(t, err, "AccountNotManagementOrDelegatedAdministratorException", 400)
	if _, err := g.client.EnableAWSServiceAccess(t.Context(), &sdk.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("config.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.client.RegisterDelegatedAdministrator(t.Context(), &sdk.RegisterDelegatedAdministratorInput{AccountId: aws.String(g.unitAccount), ServicePrincipal: aws.String("config.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	_, _, err = g.service.RootAccessFeatures(delegate)
	requireRootCode(t, err, "AccountNotManagementOrDelegatedAdministratorException", 400)
	if _, err := g.client.RegisterDelegatedAdministrator(t.Context(), &sdk.RegisterDelegatedAdministratorInput{AccountId: aws.String(g.unitAccount), ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.service.RootAccessFeatures(delegate); err != nil {
		t.Fatal(err)
	}
	for _, feature := range []provider.RootAccessFeature{provider.RootCredentialsManagement, provider.RootSessions} {
		_, _, err := g.service.SetRootAccessFeature(delegate, feature, true)
		requireRootCode(t, err, "CallerIsNotManagementAccountException", 400)
		if _, _, err := g.service.SetRootAccessFeature(g.ctx, feature, true); err != nil {
			t.Fatal(err)
		}
		if _, _, err := g.service.SetRootAccessFeature(delegate, feature, false); err != nil {
			t.Fatalf("IAM delegate cannot disable %s: %v", feature, err)
		}
	}
	if _, err := g.client.DeregisterDelegatedAdministrator(t.Context(), &sdk.DeregisterDelegatedAdministratorInput{AccountId: aws.String(g.unitAccount), ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	_, _, err = g.service.RootAccessFeatures(delegate)
	requireRootCode(t, err, "AccountNotManagementOrDelegatedAdministratorException", 400)
	// Removing an ordinary member prevents future root sessions in that account.
	if _, _, err := g.service.SetRootAccessFeature(g.ctx, provider.RootCredentialsManagement, true); err != nil {
		t.Fatal(err)
	}
	if err := g.service.CheckRootSession(g.ctx, g.rootAccount, rootAuditPolicyARN); err != nil {
		t.Fatal(err)
	}
	if _, err := g.client.RemoveAccountFromOrganization(t.Context(), &sdk.RemoveAccountFromOrganizationInput{AccountId: aws.String(g.rootAccount)}); err != nil {
		t.Fatal(err)
	}
	requireRootCode(t, g.service.CheckRootSession(g.ctx, g.rootAccount, rootAuditPolicyARN), "AccessDenied", 403)
}

func TestRootSessionEligibilityScopeAndTransitions(t *testing.T) {
	g := newAccessReportGraph(t)
	enableRootTrust(t, g.client, true)
	requireRootCode(t, g.service.CheckRootSession(g.ctx, g.unitAccount, rootAuditPolicyARN), "AccessDenied", 403)
	if _, _, err := g.service.SetRootAccessFeature(g.ctx, provider.RootCredentialsManagement, true); err != nil {
		t.Fatal(err)
	}
	if err := g.service.CheckRootSession(g.ctx, g.unitAccount, rootAuditPolicyARN); err != nil {
		t.Fatal("CredentialsManagement permits root credential audit:", err)
	}
	for _, target := range []string{managementID, "999999999999", "", "arn:aws:iam::" + g.unitAccount + ":root"} {
		requireRootCode(t, g.service.CheckRootSession(g.ctx, target, rootAuditPolicyARN), "AccessDenied", 403)
	}
	member := awsctx.WithMetadata(t.Context(), orgRoot(g.subAccount, "aws"))
	requireRootCode(t, g.service.CheckRootSession(member, g.unitAccount, rootAuditPolicyARN), "AccessDenied", 403)
	if _, err := g.client.RegisterDelegatedAdministrator(t.Context(), &sdk.RegisterDelegatedAdministratorInput{AccountId: aws.String(g.subAccount), ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	if err := g.service.CheckRootSession(member, g.unitAccount, rootAuditPolicyARN); err != nil {
		t.Fatal(err)
	}
	if err := g.service.CheckRootSession(member, g.subAccount, rootAuditPolicyARN); err != nil {
		t.Fatal("delegated account is still a member target:", err)
	}
	if _, err := g.client.CloseAccount(t.Context(), &sdk.CloseAccountInput{AccountId: aws.String(g.subAccount)}); err != nil {
		t.Fatal(err)
	}
	requireRootCode(t, g.service.CheckRootSession(member, g.unitAccount, rootAuditPolicyARN), "AccessDenied", 403)
	requireRootCode(t, g.service.CheckRootSession(g.ctx, g.subAccount, rootAuditPolicyARN), "AccessDenied", 403)
	if _, err := g.client.DeregisterDelegatedAdministrator(t.Context(), &sdk.DeregisterDelegatedAdministratorInput{AccountId: aws.String(g.subAccount), ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	enableRootTrust(t, g.client, false)
	requireRootCode(t, g.service.CheckRootSession(g.ctx, g.unitAccount, rootAuditPolicyARN), "AccessDenied", 403)
	enableRootTrust(t, g.client, true)
	if _, _, err := g.service.SetRootAccessFeature(g.ctx, provider.RootCredentialsManagement, false); err != nil {
		t.Fatal(err)
	}
	requireRootCode(t, g.service.CheckRootSession(g.ctx, g.unitAccount, rootAuditPolicyARN), "AccessDenied", 403)
}

func TestRootAccessFeaturesPartitionAndOrganizationLifetime(t *testing.T) {
	storage := provider.NewMemoryStorage(nil)
	s := organizationsOnly(storage)
	awsClient := fixedClient(t, s, orgRoot(managementID, "aws"))
	govClient := fixedClient(t, s, orgRoot(managementID, "aws-us-gov"))
	createOrg(t, awsClient)
	createOrg(t, govClient)
	enableRootTrust(t, awsClient, true)
	enableRootTrust(t, govClient, true)
	ctx := awsctx.WithMetadata(t.Context(), orgRoot(managementID, "aws"))
	oldID, _, err := s.SetRootAccessFeature(ctx, provider.RootSessions, true)
	if err != nil {
		t.Fatal(err)
	}
	govCtx := awsctx.WithMetadata(t.Context(), orgRoot(managementID, "aws-us-gov"))
	govID, govFlags, err := s.RootAccessFeatures(govCtx)
	if err != nil || govID == oldID || govFlags.Sessions {
		t.Fatalf("partition state leaked: %s %+v %v", govID, govFlags, err)
	}
	otherRegion := orgRoot(managementID, "aws")
	otherRegion.Region = "eu-west-2"
	_, flags, err := s.RootAccessFeatures(awsctx.WithMetadata(t.Context(), otherRegion))
	if err != nil || !flags.Sessions {
		t.Fatalf("global features depended on region: %+v %v", flags, err)
	}
	if _, err := awsClient.DeleteOrganization(t.Context(), &sdk.DeleteOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.RootAccessFeatures(ctx)
	requireRootCode(t, err, "OrganizationNotFoundException", 400)
	createOrg(t, awsClient)
	enableRootTrust(t, awsClient, true)
	id, flags, err := s.RootAccessFeatures(ctx)
	if err != nil || id == oldID || flags.Sessions {
		t.Fatalf("new organization inherited deleted state: %s %+v %v", id, flags, err)
	}
}

func TestRootAccessFeaturesIAMPolicyAndSCPAuthorization(t *testing.T) {
	g := newAccessReportGraph(t)
	enableRootTrust(t, g.client, true)
	if _, err := g.client.RegisterDelegatedAdministrator(t.Context(), &sdk.RegisterDelegatedAdministratorInput{AccountId: aws.String(g.unitAccount), ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	identities := &identityPolicies{}
	g.service.SetAuthorizer(authorization.New(identities, orgControlSource{g.service}))
	meta := orgRoot(managementID, "aws")
	meta.PrincipalARN = "arn:aws:iam::" + managementID + ":user/feature-admin"
	meta.PrincipalID = "AIDAROOTFEATUREADMIN1"
	user := awsctx.WithMetadata(t.Context(), meta)
	identities.set(allowAction("iam:ListOrganizationsFeatures", "*"))
	if _, _, err := g.service.RootAccessFeatures(user); err != nil {
		t.Fatal("IAM-only permission should suffice:", err)
	}
	_, _, err := g.service.SetRootAccessFeature(user, provider.RootSessions, true)
	requireRootCode(t, err, "AccessDenied", 403)
	identities.set(allowAction("iam:*Organizations*", "*"), `{"Statement":{"Effect":"Deny","Action":"organizations:*","Resource":"*"}}`)
	if _, _, err := g.service.SetRootAccessFeature(user, provider.RootSessions, true); err != nil {
		t.Fatal("Org API denial blocked IAM feature action:", err)
	}
	deny := `{"Statement":{"Effect":"Deny","Action":"iam:DisableOrganizationsRootSessions","Resource":"*"}}`
	g.policy(t, "deny-root-disable", deny, g.unitAccount)
	delegate := awsctx.WithMetadata(t.Context(), orgRoot(g.unitAccount, "aws"))
	_, _, err = g.service.SetRootAccessFeature(delegate, provider.RootSessions, false)
	requireRootCode(t, err, "AccessDenied", 403)
	_, flags, err := g.service.RootAccessFeatures(g.ctx)
	if err != nil || !flags.Sessions {
		t.Fatalf("denied transition changed state: %+v %v", flags, err)
	}
}

// revokeRootTrustOnCommit simulates an ordinary Organizations change between
// IAM authorization and the feature operation's compare-and-swap.
type revokeRootTrustOnCommit struct {
	provider.Storage
	mu     sync.Mutex
	armed  bool
	fail   bool
	cancel context.CancelFunc
}

func (s *revokeRootTrustOnCommit) CompareAndSwap(ctx context.Context, partition string, revision uint64, record provider.PartitionRecord, commit func(context.Context) error) (bool, error) {
	s.mu.Lock()
	armed, fail, cancel := s.armed, s.fail, s.cancel
	s.armed = false
	s.mu.Unlock()
	if fail {
		return false, errors.New("injected commit failure")
	}
	if cancel != nil {
		cancel()
	}
	if armed {
		current, version, err := s.Storage.Load(ctx, partition)
		if err != nil {
			return false, err
		}
		for i := range current.Organizations {
			current.Organizations[i].Services = slices.DeleteFunc(current.Organizations[i].Services, func(s provider.ServiceAccessRecord) bool { return s.Principal == "iam.amazonaws.com" })
		}
		if _, err := s.Storage.CompareAndSwap(ctx, partition, version, current, nil); err != nil {
			return false, err
		}
	}
	return s.Storage.CompareAndSwap(ctx, partition, revision, record, commit)
}

func TestRootAccessFeaturesCommitFailureCancellationAndConflict(t *testing.T) {
	for _, mode := range []string{"failure", "cancellation", "trust revoked"} {
		t.Run(mode, func(t *testing.T) {
			g := newAccessReportGraph(t)
			enableRootTrust(t, g.client, true)
			ctx, cancel := context.WithCancel(g.ctx)
			defer cancel()
			store := &revokeRootTrustOnCommit{Storage: g.storage, fail: mode == "failure", armed: mode == "trust revoked"}
			if mode == "cancellation" {
				store.cancel = cancel
			}
			s := provider.NewWithStorage(store)
			id, flags, err := s.SetRootAccessFeature(ctx, provider.RootSessions, true)
			if id != "" || flags != (provider.RootAccessFeatures{}) {
				t.Fatalf("failed commit returned success data: %s %+v", id, flags)
			}
			switch mode {
			case "failure":
				requireRootCode(t, err, "ServiceFailure", 500)
			case "cancellation":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "trust revoked":
				requireRootCode(t, err, "ServiceAccessNotEnabledException", 400)
			}
			record, _, err := g.storage.Load(g.ctx, "aws")
			if err != nil || record.Organizations[0].RootAccess.Sessions {
				t.Fatalf("failed feature transition committed: %+v %v", record, err)
			}
		})
	}
}

type rootAccessConcurrentReads struct {
	provider.Storage
	mu     sync.Mutex
	reads  int
	loaded sync.WaitGroup
}

func (s *rootAccessConcurrentReads) Load(ctx context.Context, partition string) (provider.PartitionRecord, uint64, error) {
	record, revision, err := s.Storage.Load(ctx, partition)
	s.mu.Lock()
	s.reads++
	first := s.reads <= 2
	s.mu.Unlock()
	if first {
		s.loaded.Done()
		s.loaded.Wait()
	}
	return record, revision, err
}

func TestRootAccessConcurrentIndependentFeatureChanges(t *testing.T) {
	g := newAccessReportGraph(t)
	enableRootTrust(t, g.client, true)
	for _, enabled := range []bool{true, false} {
		// Force both commands to read the same version before either commits.
		store := &rootAccessConcurrentReads{Storage: g.storage}
		store.loaded.Add(2)
		s := provider.NewWithStorage(store)
		results := make(chan error, 2)
		for _, feature := range []provider.RootAccessFeature{provider.RootCredentialsManagement, provider.RootSessions} {
			go func() {
				_, _, err := s.SetRootAccessFeature(g.ctx, feature, enabled)
				results <- err
			}()
		}
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		_, flags, err := g.service.RootAccessFeatures(g.ctx)
		if err != nil || flags != (provider.RootAccessFeatures{CredentialsManagement: enabled, Sessions: enabled}) {
			t.Fatalf("concurrent change lost independent feature state: %+v %v", flags, err)
		}
	}
}

func TestRootAccessPrerequisitesAndInvalidFeature(t *testing.T) {
	s := organizationsOnly(nil)
	ctx := awsctx.WithMetadata(t.Context(), orgRoot(managementID, "aws"))
	_, _, err := s.RootAccessFeatures(ctx)
	requireRootCode(t, err, "OrganizationNotFoundException", 400)
	client := fixedClient(t, s, orgRoot(managementID, "aws"))
	if _, err := client.CreateOrganization(t.Context(), &sdk.CreateOrganizationInput{FeatureSet: "CONSOLIDATED_BILLING"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.RootAccessFeatures(ctx)
	requireRootCode(t, err, "OrganizationNotInAllFeaturesModeException", 400)
	_, _, err = s.SetRootAccessFeature(ctx, "FutureFeature", true)
	requireRootCode(t, err, "InvalidInput", 400)
	requireRootCode(t, s.CheckRootSession(ctx, "222222222222", rootAuditPolicyARN), "AccessDenied", 403)
	_, _, err = s.RootAccessFeatures(t.Context())
	requireRootCode(t, err, "AccessDenied", 403)
}
