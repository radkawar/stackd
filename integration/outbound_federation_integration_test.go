package stackd_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd"
)

func TestInboundFederationRetainsProviderForOutboundIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	source := &federationIntegrationDiscovery{key: key, kid: "initial"}
	c, sourceClock := outboundCloud(t, stackd.Config{OIDCDiscovery: source})
	root := c.iam("test", "test", "")
	enabled, err := root.EnableOutboundWebIdentityFederation(t.Context(), &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil {
		t.Fatal(err)
	}
	advanceClock(t, sourceClock, 10*time.Second)
	role, provider := federationIntegrationRole(t, c, "000000000000", "external-caller", `"sts:AssumeRoleWithWebIdentity"`)
	putRolePolicy(t, root, "external-caller", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:GetWebIdentityToken","Resource":"*","Condition":{"StringEquals":{"aws:FederatedProvider":%q}}}}`, provider))
	inbound := source.token(t, map[string]any{"iat": sourceClock.Now().Add(-time.Minute).Unix(), "exp": sourceClock.Now().Add(time.Hour).Unix()})
	assumed, err := federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(t.Context(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("federated"), WebIdentityToken: &inbound})
	if err != nil {
		t.Fatal(err)
	}
	token, err := c.sessionSTS(assumed.Credentials).GetWebIdentityToken(t.Context(), outboundInput())
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyOutboundJWT(t, aws.ToString(enabled.IssuerIdentifier), aws.ToString(token.WebIdentityToken), sourceClock.Now())
	custom := claims["https://sts.amazonaws.com/"].(map[string]any)
	if custom["federated_provider"] != provider {
		t.Fatalf("provider identity lost: %+v", custom)
	}
}
