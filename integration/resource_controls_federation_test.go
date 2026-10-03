package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestResourceControlsFederationDeniesBeforeCredentialPublication(t *testing.T) {
	c, source, repository := newFederationIntegrationCloud(t)
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	created, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := org.ListRoots(t.Context(), &organizations.ListRootsInput{})
	if err != nil {
		t.Fatal(err)
	}
	f := organizationReportFixture{cloud: c, org: org, iam: c.iam("test", "test", ""), rootID: *roots.Roots[0].Id, rootPath: *created.Organization.Id + "/" + *roots.Roots[0].Id}
	member := f.account(t, f.rootID, "rcp-federation")
	oidcRole, _ := federationIntegrationRole(t, c, member, "rcp-oidc", `"sts:AssumeRoleWithWebIdentity"`)
	signer := newSAMLIntegrationSigner(t)
	memberIAM := c.iam(member, "test", "")
	provider, err := memberIAM.CreateSAMLProvider(t.Context(), &iam.CreateSAMLProviderInput{Name: aws.String("rcp-saml"), SAMLMetadataDocument: aws.String(signer.metadata())})
	if err != nil {
		t.Fatal(err)
	}
	samlRole, err := memberIAM.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("rcp-saml"), AssumeRolePolicyDocument: aws.String(fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithSAML","sts:TagSession"],"Condition":{"StringEquals":{"saml:aud":"https://signin.aws.amazon.com/saml"}}}}`, *provider.SAMLProviderArn))})
	if err != nil {
		t.Fatal(err)
	}
	client := federationIntegrationUnsigned(c)
	oidc := func() error {
		_, err := client.AssumeRoleWithWebIdentity(t.Context(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: oidcRole.Arn, RoleSessionName: aws.String("rcp"), WebIdentityToken: aws.String(source.token(t, nil))})
		return err
	}
	saml := func(tags bool) error {
		_, err := client.AssumeRoleWithSAML(t.Context(), &sts.AssumeRoleWithSAMLInput{RoleArn: samlRole.Role.Arn, PrincipalArn: provider.SAMLProviderArn, SAMLAssertion: aws.String(signer.token(t, *samlRole.Role.Arn, *provider.SAMLProviderArn, samlIntegrationClaims{tags: tags}))})
		return err
	}
	if err := oidc(); err != nil {
		t.Fatal(err)
	}
	if err := saml(false); err != nil {
		t.Fatal(err)
	}
	f.enableRCP(t)
	doc := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity","Resource":%q,"Condition":{"StringEquals":{"federation.example.test:sub":"verified-subject"}}},{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML","Resource":%q,"Condition":{"StringEquals":{"saml:sub":"verified-subject"},"Bool":{"aws:PrincipalIsAWSService":"false"}}}]}`, *oidcRole.Arn, *samlRole.Role.Arn)
	id := f.rcp(t, "federation-control", doc, member)
	assertAPIError(t, oidc(), "AccessDenied")
	assertAPIError(t, saml(false), "AccessDenied")
	for _, roleID := range []*string{oidcRole.RoleId, samlRole.Role.RoleId} {
		if got := federationIntegrationCredentialCount(t, repository, member, *roleID); got != 1 {
			t.Fatalf("RCP denial published credentials: %d", got)
		}
	}
	doc = fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"sts:TagSession","Resource":%q}}`, *samlRole.Role.Arn)
	if _, err := org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &id, Content: &doc}); err != nil {
		t.Fatal(err)
	}
	if err := oidc(); err != nil {
		t.Fatal(err)
	}
	if err := saml(false); err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, saml(true), "AccessDenied")
	if got := federationIntegrationCredentialCount(t, repository, member, *samlRole.Role.RoleId); got != 2 {
		t.Fatalf("dependent TagSession denial published credentials: %d", got)
	}
}
