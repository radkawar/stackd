package stackd_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

func TestSTSTokenPreferenceAppliesToUnsignedFederation(t *testing.T) {
	source := clock.NewManual(time.Now().UTC())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	discovery := &federationIntegrationDiscovery{key: key, kid: "preference"}
	c := clockCloud(t, stackd.Config{Clock: source, OIDCDiscovery: discovery})
	enableAccountRegion(t, c, source, "test", "ap-east-1")
	root := c.iam("test", "test", "")
	role, _ := federationIntegrationRole(t, c, "000000000000", "preference-federation", `"sts:AssumeRoleWithWebIdentity"`)
	global, regional := globalSTSClient(t, c, "", "", ""), federationIntegrationUnsigned(c)
	for _, modern := range []bool{false, true} {
		setTokenPreference(t, root, modern)
		advanceClock(t, source, 10*time.Second)
		token := discovery.token(t, map[string]any{"iat": source.Now().Add(-time.Minute).Unix(), "exp": source.Now().Add(time.Hour).Unix()})
		input := &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("preference"), WebIdentityToken: &token}
		out, err := global.AssumeRoleWithWebIdentity(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		tokenWorksInRegion(t, c, out.Credentials, "ap-east-1", modern)
		out, err = regional.AssumeRoleWithWebIdentity(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		tokenWorksInRegion(t, c, out.Credentials, "ap-east-1", true)
	}
}
