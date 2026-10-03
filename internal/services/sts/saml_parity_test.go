package sts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
)

// Replay the exact signed-assertion mutations used by the owned AWS probe.
// This tests verification and claim extraction; API issuance/trust integration
// remains a separate compatibility gate.
func TestSAMLAWSAssertionParity(t *testing.T) {
	for _, path := range []string{"testdata/saml_aws.json", "testdata/saml_required_aws.json"} {
		t.Run(path, func(t *testing.T) {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture samlAWSFixture
			if err := json.Unmarshal(body, &fixture); err != nil {
				t.Fatal(err)
			}
			if !fixture.CleanupVerified || len(fixture.Observations) == 0 {
				t.Fatal("fixture lacks cleanup or observations")
			}
			f := newSAMLTestFixture(t)
			f.provider.AssertionEncryptionMode = fixture.EncryptionMode
			client, authority := newSAMLHandlerClient(t, f)
			authority.role.TrustPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithSAML","sts:TagSession","sts:SetSourceIdentity"]}]}`, f.provider.ARN)
			for _, observation := range fixture.Observations {
				t.Run(observation.Scenario, func(t *testing.T) {
					raw, duration := samlAWSScenario(t, f, observation.Scenario)
					claims, apiErr := verifySAMLResponse(raw, f.provider, f.roleARN, f.now)
					code := "Success"
					if apiErr != nil {
						code = apiErr.Code
					}
					if code != observation.Code {
						t.Fatalf("verification=%s (%v); AWS=%s", code, apiErr, observation.Code)
					}
					out, err := client.AssumeRoleWithSAML(context.Background(), &sdksts.AssumeRoleWithSAMLInput{PrincipalArn: aws.String(f.provider.ARN), RoleArn: aws.String(f.roleARN), SAMLAssertion: aws.String(base64.StdEncoding.EncodeToString(raw)), DurationSeconds: duration})
					if observation.Code != "Success" {
						samlSDKError(t, err, observation.Code)
					} else {
						if err != nil {
							t.Fatal(err)
						}
						if aws.ToString(out.Audience) != observation.Audience || aws.ToString(out.Subject) != observation.Subject || aws.ToString(out.SubjectType) != observation.SubjectType || aws.ToString(out.SourceIdentity) != observation.SourceIdentity {
							t.Fatalf("generated SDK output differs from AWS: %+v", out)
						}
					}
					if apiErr != nil {
						return
					}
					if claims.Audience != observation.Audience || claims.Subject != observation.Subject || claims.SubjectType != observation.SubjectType || claims.SourceIdentity != observation.SourceIdentity {
						t.Fatalf("claims differ from AWS: %+v; expected %+v", claims, observation)
					}
					want := time.Hour
					if duration != nil {
						want = time.Duration(*duration) * time.Second
					}
					if claims.SessionDuration > 0 && claims.SessionDuration < want {
						want = claims.SessionDuration
					}
					if !claims.NotAfter.IsZero() && claims.NotAfter.Sub(f.now) < want {
						want = claims.NotAfter.Sub(f.now)
					}
					difference := want - time.Duration(observation.DurationSeconds)*time.Second
					if difference < 0 || difference > 5*time.Second {
						t.Fatalf("derived duration=%v; AWS=%ds", want, observation.DurationSeconds)
					}
				})
			}
		})
	}
}

func TestSAMLInheritedNamespaces(t *testing.T) {
	f := newSAMLTestFixture(t)
	a := f.sign(t, f.assertion())
	r := f.response(a)
	r.CreateAttr("xmlns:saml", samlAssertionNS)
	a.RemoveAttr("xmlns:saml")
	if _, err := verifySAMLResponse(samlTestBytes(t, r), f.provider, f.roleARN, f.now); err != nil {
		t.Fatal(err)
	}
}
