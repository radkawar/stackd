package iam_test

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/services/iam"
)

type certificateDenyControls struct{}

func (certificateDenyControls) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":["iam:DeleteServerCertificate","iam:UpdateSigningCertificate","iam:UpdateSSHPublicKey"],"Resource":"*"}]}`}}}}, nil
}

func TestIAMCertificateAuthorizationResourcesAndTags(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("certificate-manager")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, s, u.User)
	key := certificateTestECKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	input := &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("server"), Path: aws.String("/tls/"), CertificateBody: aws.String(body), PrivateKey: aws.String(certificateTestPrivate(t, key)), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("infra")}}}
	put := func(doc string) {
		t.Helper()
		_, err := root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("Certificates"), PolicyDocument: aws.String(doc)})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = caller.UploadServerCertificate(ctx, input)
	requireCode(t, err, "AccessDenied")
	arn := "arn:aws:iam::123456789012:server-certificate/tls/server"
	put(`{"Statement":{"Effect":"Allow","Action":"iam:UploadServerCertificate","Resource":"` + arn + `"}}`)
	_, err = caller.UploadServerCertificate(ctx, input)
	requireCode(t, err, "AccessDenied")
	list, err := root.ListServerCertificates(ctx, &sdkiam.ListServerCertificatesInput{})
	if err != nil || len(list.ServerCertificateMetadataList) != 0 {
		t.Fatal("denied tag-on-create changed state")
	}
	put(`{"Statement":{"Effect":"Allow","Action":["iam:UploadServerCertificate","iam:TagServerCertificate"],"Resource":"` + arn + `","Condition":{"StringEquals":{"aws:RequestTag/team":"infra"}}}}`)
	if _, err := caller.UploadServerCertificate(ctx, input); err != nil {
		t.Fatal("path/tag-scoped grant failed", err)
	}
	put(`{"Statement":{"Effect":"Allow","Action":"iam:GetServerCertificate","Resource":"` + arn + `","Condition":{"StringEquals":{"aws:ResourceTag/team":"infra"}}}}`)
	if _, err := caller.GetServerCertificate(ctx, &sdkiam.GetServerCertificateInput{ServerCertificateName: aws.String("SERVER")}); err != nil {
		t.Fatal("stored ARN/tag resource scope failed", err)
	}
	put(`{"Statement":[{"Effect":"Allow","Action":"iam:DeleteServerCertificate","Resource":"` + arn + `"},{"Effect":"Deny","Action":"iam:DeleteServerCertificate","Resource":"*"}]}`)
	_, err = caller.DeleteServerCertificate(ctx, &sdkiam.DeleteServerCertificateInput{ServerCertificateName: aws.String("server")})
	requireCode(t, err, "AccessDenied")
	put(`{"Statement":{"Effect":"Allow","Action":"iam:DeleteServerCertificate","Resource":"` + arn + `"}}`)
	s.SetAuthorizer(authorization.New(s, certificateDenyControls{}))
	_, err = caller.DeleteServerCertificate(ctx, &sdkiam.DeleteServerCertificateInput{ServerCertificateName: aws.String("server")})
	requireCode(t, err, "AccessDenied")
	s.SetAuthorizer(nil)
	boundary, err := root.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("CertificateReadOnly"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetServerCertificate","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: u.User.UserName, PermissionsBoundary: boundary.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	_, err = caller.DeleteServerCertificate(ctx, &sdkiam.DeleteServerCertificateInput{ServerCertificateName: aws.String("server")})
	requireCode(t, err, "AccessDenied")
	if _, err := root.GetServerCertificate(ctx, &sdkiam.GetServerCertificateInput{ServerCertificateName: aws.String("server")}); err != nil {
		t.Fatal("denied deletion changed state", err)
	}
}

func TestIAMSigningAndSSHAuthorizationIdentity(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("certificate-user"), Path: aws.String("/identities/")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, s, u.User)
	key := certificateTestECKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, err = caller.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{CertificateBody: aws.String(body)})
	requireCode(t, err, "AccessDenied")
	_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("OwnCertificate"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":["iam:UploadSigningCertificate","iam:ListSigningCertificates","iam:UpdateSigningCertificate"],"Resource":"` + aws.ToString(u.User.Arn) + `"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	created, err := caller.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{CertificateBody: aws.String(body)})
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(authorization.New(s, certificateDenyControls{}))
	_, err = caller.UpdateSigningCertificate(ctx, &sdkiam.UpdateSigningCertificateInput{CertificateId: created.Certificate.CertificateId, Status: types.StatusTypeInactive})
	requireCode(t, err, "AccessDenied")
	list, err := caller.ListSigningCertificates(ctx, &sdkiam.ListSigningCertificatesInput{})
	if err != nil || len(list.Certificates) != 1 || list.Certificates[0].Status != types.StatusTypeActive {
		t.Fatal("denied status change modified state")
	}
}
