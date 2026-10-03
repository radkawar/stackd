package stackd_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"stackd"
	"stackd/clock"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// Sign the real global hostname while routing the test connection locally.
func globalSTSClient(t *testing.T, c cloudClients, key, secret, token string) *sts.Client {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, c.server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return sts.New(c.sts(key, secret, token).Options(), func(o *sts.Options) {
		o.BaseEndpoint = aws.String("http://sts.amazonaws.com")
		o.HTTPClient = &http.Client{Transport: transport}
	})
}

func setTokenPreference(t *testing.T, client *iam.Client, modern bool) {
	t.Helper()
	version := iamtypes.GlobalEndpointTokenVersionV1Token
	if modern {
		version = iamtypes.GlobalEndpointTokenVersionV2Token
	}
	if _, err := client.SetSecurityTokenServicePreferences(t.Context(), &iam.SetSecurityTokenServicePreferencesInput{GlobalEndpointTokenVersion: version}); err != nil {
		t.Fatal(err)
	}
}

func tokenWorksInRegion(t *testing.T, c cloudClients, credential *ststypes.Credentials, region string, valid bool) {
	t.Helper()
	_, err := c.sessionSTS(credential).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}, func(o *sts.Options) { o.Region = region })
	if valid {
		if err != nil {
			t.Fatalf("session rejected in %s: %v", region, err)
		}
	} else {
		assertAPIError(t, err, "InvalidClientTokenId")
	}
}

func TestSTSTokenPreferenceControlsIssuedCredentials(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0).UTC())
	c := clockCloud(t, stackd.Config{Clock: source})
	enableAccountRegion(t, c, source, "test", "ap-east-1")
	ctx := t.Context()
	root := c.iam("test", "test", "")
	summary, err := root.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil || summary.SummaryMap["GlobalEndpointTokenVersion"] != 1 {
		t.Fatalf("default token preference: %+v %v", summary, err)
	}
	userARN, key, secret := c.user(t, "test", "token-preference")
	putUserPolicy(t, root, "token-preference", allow(`["sts:AssumeRole","sts:GetFederationToken"]`, "*"))
	role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("preference"), AssumeRolePolicyDocument: aws.String(fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sts:AssumeRole"}}`, userARN))})
	if err != nil {
		t.Fatal(err)
	}
	global, regional := globalSTSClient(t, c, key, secret, ""), c.sts(key, secret, "")
	issuers := []struct {
		name  string
		issue func(*sts.Client) (*ststypes.Credentials, error)
	}{
		{"user", func(client *sts.Client) (*ststypes.Credentials, error) {
			out, err := client.GetSessionToken(ctx, &sts.GetSessionTokenInput{})
			if err != nil {
				return nil, err
			}
			return out.Credentials, nil
		}},
		{"role", func(client *sts.Client) (*ststypes.Credentials, error) {
			out, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("preference")})
			if err != nil {
				return nil, err
			}
			return out.Credentials, nil
		}},
		{"federated", func(client *sts.Client) (*ststypes.Credentials, error) {
			out, err := client.GetFederationToken(ctx, &sts.GetFederationTokenInput{Name: aws.String("preference")})
			if err != nil {
				return nil, err
			}
			return out.Credentials, nil
		}},
	}
	var oldLegacy, oldModern []*ststypes.Credentials
	for _, modern := range []bool{false, true} {
		setTokenPreference(t, root, modern)
		advanceClock(t, source, 10*time.Second)
		for _, issuer := range issuers {
			legacy, err := issuer.issue(global)
			if err != nil {
				t.Fatalf("%s global: %v", issuer.name, err)
			}
			local, err := issuer.issue(regional)
			if err != nil {
				t.Fatalf("%s regional: %v", issuer.name, err)
			}
			for _, region := range []string{"us-east-1", "ap-northeast-3", "ap-east-1"} {
				tokenWorksInRegion(t, c, legacy, region, modern || region != "ap-east-1")
				tokenWorksInRegion(t, c, local, region, true)
			}
			if !modern {
				if len(aws.ToString(legacy.SessionToken)) >= len(aws.ToString(local.SessionToken)) {
					t.Fatal("legacy token should be shorter than the regional token")
				}
				oldLegacy = append(oldLegacy, legacy)
			} else {
				oldModern = append(oldModern, legacy)
			}
		}
	}
	summary, err = root.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil || summary.SummaryMap["GlobalEndpointTokenVersion"] != 2 {
		t.Fatalf("changed token preference: %+v %v", summary, err)
	}
	for _, credential := range oldLegacy {
		tokenWorksInRegion(t, c, credential, "ap-east-1", false)
	}
	setTokenPreference(t, root, false)
	for _, credential := range oldModern {
		tokenWorksInRegion(t, c, credential, "ap-east-1", true)
	}
	// A legacy parent can obtain a modern role session through a default-region
	// regional endpoint. Compatibility belongs to each issuance, not its parent.
	upgraded, err := c.sessionSTS(oldLegacy[0]).AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("regional-upgrade")})
	if err != nil {
		t.Fatal(err)
	}
	tokenWorksInRegion(t, c, upgraded.Credentials, "ap-east-1", true)
	tokenWorksInRegion(t, c, oldLegacy[0], "ap-east-1", false)
}

func TestSTSTokenPreferenceUsesDestinationRoleAccount(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0).UTC())
	c := clockCloud(t, stackd.Config{Clock: source})
	enableAccountRegion(t, c, source, "111111111111", "ap-east-1")
	ctx := t.Context()
	caller := c.iam("test", "test", "")
	target := c.iam("111111111111", "test", "")
	userARN, key, secret := c.user(t, "test", "cross-preference")
	putUserPolicy(t, caller, "cross-preference", allow(`"sts:AssumeRole"`, "*"))
	role, err := target.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("destination"), AssumeRolePolicyDocument: aws.String(fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":%q}}}`, userARN))})
	if err != nil {
		t.Fatal(err)
	}
	client := globalSTSClient(t, c, key, secret, "")
	for _, modern := range []bool{true, false} {
		setTokenPreference(t, caller, !modern)
		setTokenPreference(t, target, modern)
		advanceClock(t, source, 10*time.Second)
		out, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("cross")})
		if err != nil {
			t.Fatal(err)
		}
		tokenWorksInRegion(t, c, out.Credentials, "ap-east-1", modern)
	}
}
