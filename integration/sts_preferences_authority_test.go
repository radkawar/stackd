package stackd_test

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestSTSTokenPreferenceOrderedPropagationAndReconstruction(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0).UTC())
	config := stackd.Config{Clock: source, Storage: storage.NewMemory()}
	c := clockCloud(t, config)
	enableAccountRegion(t, c, source, "test", "ap-east-1")
	root := c.iam("test", "test", "")
	global := globalSTSClient(t, c, "test", "test", "")
	check := func(modern bool) {
		t.Helper()
		out, err := global.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{})
		if err != nil {
			t.Fatal(err)
		}
		tokenWorksInRegion(t, c, out.Credentials, "ap-east-1", modern)
	}
	setTokenPreference(t, root, true)
	advanceClock(t, source, 10*time.Second-time.Nanosecond)
	check(false)
	advanceClock(t, source, time.Nanosecond)
	check(true)
	setTokenPreference(t, root, false)
	advanceClock(t, source, 3*time.Second)
	setTokenPreference(t, root, true)
	// Retained backend state and caller-owned service time reconstruct the
	// setting's pending changes, without relying on an old provider's timers.
	c = clockCloud(t, config)
	root = c.iam("test", "test", "")
	global = globalSTSClient(t, c, "test", "test", "")
	advanceClock(t, source, 7*time.Second)
	check(false)
	summary, err := root.GetAccountSummary(t.Context(), &iam.GetAccountSummaryInput{})
	if err != nil || summary.SummaryMap["GlobalEndpointTokenVersion"] != 2 {
		t.Fatal("propagation changed the current IAM preference", err)
	}
	advanceClock(t, source, 3*time.Second)
	check(true)
}

func TestSTSTokenPreferenceFailedWritesDoNotPropagate(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0).UTC())
	backends := storage.NewMemory()
	repository := &accountSettingsRepository{Repository: backends.IAM}
	backends.IAM = repository
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
	enableAccountRegion(t, c, source, "test", "ap-east-1")
	root := c.iam("test", "test", "")
	global := globalSTSClient(t, c, "test", "test", "")
	for _, modern := range []bool{true, false} {
		repository.reject.Store(true)
		version := iamtypes.GlobalEndpointTokenVersionV1Token
		if modern {
			version = iamtypes.GlobalEndpointTokenVersionV2Token
		}
		out, err := root.SetSecurityTokenServicePreferences(t.Context(), &iam.SetSecurityTokenServicePreferencesInput{GlobalEndpointTokenVersion: version})
		if err == nil || out != nil {
			t.Fatalf("failed configuration published output: %+v %v", out, err)
		}
		repository.reject.Store(false)
		advanceClock(t, source, 20*time.Second)
		session, err := global.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{})
		if err != nil {
			t.Fatal(err)
		}
		tokenWorksInRegion(t, c, session.Credentials, "ap-east-1", !modern)
		setTokenPreference(t, root, modern)
		advanceClock(t, source, 10*time.Second)
	}
}

func TestSTSTokenPreferenceReadsCurrentIssuanceTransaction(t *testing.T) {
	for _, failure := range []string{"", "commit", "cancel"} {
		t.Run("failure_"+failure, func(t *testing.T) {
			source := clock.NewManual(time.Unix(0, 0).UTC())
			backends := storage.NewMemory()
			repository := &signedAuthorityRepository{Repository: backends.IAM}
			backends.IAM = repository
			c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
			enableAccountRegion(t, c, source, "test", "ap-east-1")
			root := c.iam("test", "test", "")
			_, key, secret := c.user(t, "test", "preference-authority")
			plan := &signedAuthorityPlan{key: key, failCommit: failure == "commit", cancelCommit: failure == "cancel"}
			plan.before = func(ctx context.Context) error {
				if _, err := root.SetSecurityTokenServicePreferences(ctx, &iam.SetSecurityTokenServicePreferencesInput{GlobalEndpointTokenVersion: iamtypes.GlobalEndpointTokenVersionV2Token}); err != nil {
					return err
				}
				return source.Advance(10 * time.Second)
			}
			repository.arm(plan)
			ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
			defer cancel()
			out, err := globalSTSClient(t, c, key, secret, "").GetSessionToken(ctx, &sts.GetSessionTokenInput{})
			plan.wait(t, ctx)
			if plan.hookErr != nil {
				t.Fatal(plan.hookErr)
			}
			if failure == "" {
				if err != nil {
					t.Fatal(err)
				}
				tokenWorksInRegion(t, c, out.Credentials, "ap-east-1", true)
				return
			}
			if err == nil || out != nil {
				t.Fatalf("failed publication: %+v %v", out, err)
			}
			if len(plan.issued) != 1 {
				t.Fatalf("expected one staged credential, got %d", len(plan.issued))
			}
			credential := plan.issued[0]
			_, err = c.sts(credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			assertAPIError(t, err, "InvalidClientTokenId")
		})
	}
}

func TestSTSTokenPreferenceRequiresAccountPermission(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	arn, key, secret := c.user(t, "test", "preference-permission")
	caller := c.iam(key, secret, "")
	in := &iam.SetSecurityTokenServicePreferencesInput{GlobalEndpointTokenVersion: iamtypes.GlobalEndpointTokenVersionV2Token}
	for _, document := range []string{"", allow(`"iam:SetSecurityTokenServicePreferences"`, arn), `{"Statement":{"Effect":"Deny","Action":"iam:SetSecurityTokenServicePreferences","Resource":"*"}}`} {
		if document != "" {
			putUserPolicy(t, root, "preference-permission", document)
		}
		_, err := caller.SetSecurityTokenServicePreferences(t.Context(), in)
		assertAPIError(t, err, "AccessDenied")
	}
	putUserPolicy(t, root, "preference-permission", allow(`"iam:SetSecurityTokenServicePreferences"`, "*"))
	if _, err := caller.SetSecurityTokenServicePreferences(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	summary, err := root.GetAccountSummary(t.Context(), &iam.GetAccountSummaryInput{})
	if err != nil || summary.SummaryMap["GlobalEndpointTokenVersion"] != 2 {
		t.Fatal("authorized preference was not applied", err)
	}
	other, err := c.iam("111111111111", "test", "").GetAccountSummary(t.Context(), &iam.GetAccountSummaryInput{})
	if err != nil || other.SummaryMap["GlobalEndpointTokenVersion"] != 1 {
		t.Fatal("preference crossed account boundaries", err)
	}
}
