package iam_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/services/iam"
)

func TestIAMServiceCredentialsAuthorization(t *testing.T) {
	service, root := newServiceCredentialTestService(t)
	ctx := context.Background()
	actor, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("credential-manager")})
	if err != nil {
		t.Fatal(err)
	}
	target, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("credential-target"), Path: aws.String("/managed/")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, actor.User)
	put := func(document string) {
		t.Helper()
		_, err := root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: actor.User.UserName, PolicyName: aws.String("ManageCredentials"), PolicyDocument: aws.String(document)})
		if err != nil {
			t.Fatal(err)
		}
	}
	create := &sdkiam.CreateServiceSpecificCredentialInput{UserName: target.User.UserName, ServiceName: aws.String("BEDROCK.amazonaws.com"), CredentialAgeDays: aws.Int32(1)}
	_, err = caller.CreateServiceSpecificCredential(ctx, create)
	requireCode(t, err, "AccessDenied")
	put(`{"Statement":{"Effect":"Allow","Action":"iam:CreateServiceSpecificCredential","Resource":"` + aws.ToString(target.User.Arn) + `","Condition":{"StringEquals":{"iam:ServiceSpecificCredentialServiceName":"bedrock.amazonaws.com"},"NumericLessThanEquals":{"iam:ServiceSpecificCredentialAgeDays":"1"}}}}`)
	for _, input := range []*sdkiam.CreateServiceSpecificCredentialInput{
		{UserName: target.User.UserName, ServiceName: aws.String("bedrock.amazonaws.com")},
		{UserName: target.User.UserName, ServiceName: aws.String("bedrock.amazonaws.com"), CredentialAgeDays: aws.Int32(2)},
		{UserName: target.User.UserName, ServiceName: aws.String("logs.amazonaws.com"), CredentialAgeDays: aws.Int32(1)},
		{UserName: actor.User.UserName, ServiceName: aws.String("bedrock.amazonaws.com"), CredentialAgeDays: aws.Int32(1)},
	} {
		_, err = caller.CreateServiceSpecificCredential(ctx, input)
		requireCode(t, err, "AccessDenied")
	}
	list, err := root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: target.User.UserName})
	if err != nil || len(list.ServiceSpecificCredentials) != 0 {
		t.Fatalf("denied creation changed state: %+v %v", list, err)
	}
	created, err := caller.CreateServiceSpecificCredential(ctx, create)
	if err != nil {
		t.Fatalf("canonical service name / age condition denied: %v", err)
	}
	credential := created.ServiceSpecificCredential
	put(`{"Statement":{"Effect":"Allow","Action":["iam:UpdateServiceSpecificCredential","iam:ResetServiceSpecificCredential","iam:DeleteServiceSpecificCredential"],"Resource":"` + aws.ToString(target.User.Arn) + `","Condition":{"StringEquals":{"iam:ServiceSpecificCredentialServiceName":"logs.amazonaws.com"}}}}`)
	_, err = caller.UpdateServiceSpecificCredential(ctx, &sdkiam.UpdateServiceSpecificCredentialInput{UserName: target.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId, Status: types.StatusTypeInactive})
	requireCode(t, err, "AccessDenied")
	_, err = caller.ResetServiceSpecificCredential(ctx, &sdkiam.ResetServiceSpecificCredentialInput{UserName: target.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
	requireCode(t, err, "AccessDenied")
	_, err = caller.DeleteServiceSpecificCredential(ctx, &sdkiam.DeleteServiceSpecificCredentialInput{UserName: target.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
	requireCode(t, err, "AccessDenied")
	requireIAMMetadataQueryDenied(t, service, actor.User, url.Values{
		"Action": {"DeleteServiceSpecificCredential"}, "UserName": {aws.ToString(target.User.UserName)},
		"ServiceSpecificCredentialId": {aws.ToString(credential.ServiceSpecificCredentialId)}, "ServiceName": {"logs.amazonaws.com"},
	})
	put(`{"Statement":{"Effect":"Allow","Action":"iam:ListServiceSpecificCredentials","Resource":"` + aws.ToString(target.User.Arn) + `"}}`)
	_, err = caller.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{AllUsers: aws.Bool(true)})
	requireCode(t, err, "AccessDenied")
	list, err = caller.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: target.User.UserName})
	if err != nil || len(list.ServiceSpecificCredentials) != 1 || list.ServiceSpecificCredentials[0].Status != types.StatusTypeActive {
		t.Fatalf("target listing or denied mutation: %+v %v", list, err)
	}
	put(`{"Statement":{"Effect":"Allow","Action":"iam:ListServiceSpecificCredentials","Resource":"arn:aws:iam::123456789012:user/*"}}`)
	list, err = caller.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{AllUsers: aws.Bool(true)})
	if err != nil || len(list.ServiceSpecificCredentials) != 1 {
		t.Fatalf("account user wildcard must authorize all-user listing: %+v %v", list, err)
	}
	put(`{"Statement":[{"Effect":"Allow","Action":"iam:DeleteServiceSpecificCredential","Resource":"` + aws.ToString(target.User.Arn) + `","Condition":{"StringEquals":{"iam:ServiceSpecificCredentialServiceName":"bedrock.amazonaws.com"}}},{"Effect":"Deny","Action":"iam:DeleteServiceSpecificCredential","Resource":"*"}]}`)
	_, err = caller.DeleteServiceSpecificCredential(ctx, &sdkiam.DeleteServiceSpecificCredentialInput{UserName: target.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
	requireCode(t, err, "AccessDenied")
}

type serviceCredentialDenyControls struct{}

func (serviceCredentialDenyControls) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:ResetServiceSpecificCredential","Resource":"*"}]}`}}}}, nil
}

func TestIAMServiceCredentialsBoundaryAndSCP(t *testing.T) {
	for _, layer := range []string{"boundary", "scp"} {
		t.Run(layer, func(t *testing.T) {
			service, root := newServiceCredentialTestService(t)
			ctx := context.Background()
			u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("restricted-credential-user")})
			if err != nil {
				t.Fatal(err)
			}
			credential, err := root.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String("codecommit.amazonaws.com")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("SelfCredentialReset"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:ResetServiceSpecificCredential","Resource":"` + aws.ToString(u.User.Arn) + `"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			if layer == "boundary" {
				boundary, err := root.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("CredentialReadOnly"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:ListServiceSpecificCredentials","Resource":"*"}}`)})
				if err != nil {
					t.Fatal(err)
				}
				_, err = root.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: u.User.UserName, PermissionsBoundary: boundary.Policy.Arn})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				service.SetAuthorizer(authorization.New(service, serviceCredentialDenyControls{}))
			}
			caller := clientForIAMPrincipal(t, service, u.User)
			_, err = caller.ResetServiceSpecificCredential(ctx, &sdkiam.ResetServiceSpecificCredentialInput{ServiceSpecificCredentialId: credential.ServiceSpecificCredential.ServiceSpecificCredentialId})
			requireCode(t, err, "AccessDenied")
			identifier, secret := serviceCredentialMaterial(credential.ServiceSpecificCredential)
			if _, err := service.VerifyServiceCredential(ctx, iam.Scope{Partition: "aws", AccountID: "123456789012"}, "codecommit.amazonaws.com", identifier, secret); err != nil {
				t.Fatalf("denied reset changed the existing secret: %v", err)
			}
		})
	}
}
