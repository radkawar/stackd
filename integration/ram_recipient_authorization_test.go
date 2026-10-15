package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
)

func TestRAMRecipientRoleReadsAndWithdrawalRetained(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, principalKind := range []string{"account", "role"} {
			t.Run(backend+"/"+principalKind, func(t *testing.T) {
				const owner, consumer, outsider = "111122223333", "444455556666", "777788889999"
				ctx := t.Context()
				cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner})
				cl.user(t, consumer, "registered-recipient")
				cl.user(t, outsider, "registered-outsider")
				roleName, policyName := "ram-recipient", "administrator"
				trust := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}}`, consumer)
				admin := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
				createRole := func() string {
					t.Helper()
					root := cl.iam(consumer, "test", "")
					role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust})
					if err != nil {
						t.Fatal(err)
					}
					_, err = root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: &roleName, PolicyName: &policyName, PolicyDocument: &admin})
					if err != nil {
						t.Fatal(err)
					}
					return aws.ToString(role.Role.Arn)
				}
				roleARN := createRole()
				issue := func() aws.Credentials {
					t.Helper()
					out, err := cl.sts(consumer, "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &roleARN, RoleSessionName: new("terraform-consumer")})
					if err != nil {
						t.Fatal(err)
					}
					return aws.Credentials{AccessKeyID: aws.ToString(out.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey), SessionToken: aws.ToString(out.Credentials.SessionToken)}
				}
				session := issue()
				reader := func(region string, creds aws.Credentials) *ram.Client {
					return ram.New(ram.Options{Region: region, BaseEndpoint: new(cl.server.URL), HTTPClient: cl.server.Client(), Credentials: credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken), RetryMaxAttempts: 1})
				}
				parameterReader := func(creds aws.Credentials) *ssm.Client {
					return ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: new(cl.server.URL), HTTPClient: cl.server.Client(), Credentials: credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken), RetryMaxAttempts: 1})
				}
				name, resourceARN := "/ram/recipient", "arn:aws:ssm:us-east-1:"+owner+":parameter/ram/recipient"
				_, err := cl.ssm("us-east-1", owner, "test").PutParameter(ctx, &ssm.PutParameterInput{Name: &name, Value: new("real-recipient-value"), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierAdvanced})
				if err != nil {
					t.Fatal(err)
				}
				principal := consumer
				if principalKind == "role" {
					principal = roleARN
				}
				var shares []string
				for i := range 2 {
					share, err := cl.ram("us-east-1", owner, "test").CreateResourceShare(ctx, &ram.CreateResourceShareInput{Name: new(fmt.Sprintf("recipient-%d", i)), ResourceArns: []string{resourceARN}, Principals: []string{principal}, AllowExternalPrincipals: new(true)})
					if err != nil {
						t.Fatal(err)
					}
					shares = append(shares, aws.ToString(share.ResourceShare.ResourceShareArn))
				}
				foreign, err := cl.ram("us-east-1", owner, "test").CreateResourceShare(ctx, &ram.CreateResourceShareInput{Name: new("unrelated"), ResourceArns: []string{resourceARN}, Principals: []string{outsider}, AllowExternalPrincipals: new(true)})
				if err != nil {
					t.Fatal(err)
				}
				outsiderRAM := cl.ram("us-east-1", outsider, "test")
				foreignInvitations, err := outsiderRAM.GetResourceShareInvitations(ctx, &ram.GetResourceShareInvitationsInput{ResourceShareArns: []string{aws.ToString(foreign.ResourceShare.ResourceShareArn)}})
				if err != nil || len(foreignInvitations.ResourceShareInvitations) != 1 {
					t.Fatalf("foreign invitation: %+v %v", foreignInvitations, err)
				}
				_, err = outsiderRAM.AcceptResourceShareInvitation(ctx, &ram.AcceptResourceShareInvitationInput{ResourceShareInvitationArn: foreignInvitations.ResourceShareInvitations[0].ResourceShareInvitationArn})
				if err != nil {
					t.Fatal(err)
				}
				read := func(creds aws.Credentials, filter []string, want int) {
					t.Helper()
					out, err := reader("us-east-1", creds).GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerOtherAccounts, ResourceShareArns: filter})
					if err != nil || len(out.ResourceShares) != want {
						t.Fatalf("recipient share read: %+v %v, want %d", out, err, want)
					}
				}
				read(session, shares, 0)
				invitations, err := reader("us-east-1", session).GetResourceShareInvitations(ctx, &ram.GetResourceShareInvitationsInput{ResourceShareArns: shares})
				if err != nil || len(invitations.ResourceShareInvitations) != 2 {
					t.Fatalf("invitations: %+v %v", invitations, err)
				}
				for _, invitation := range invitations.ResourceShareInvitations {
					_, err := reader("us-east-1", session).AcceptResourceShareInvitation(ctx, &ram.AcceptResourceShareInvitationInput{ResourceShareInvitationArn: invitation.ResourceShareInvitationArn})
					if err != nil {
						t.Fatal(err)
					}
				}
				read(session, nil, 2)
				self, err := reader("us-east-1", session).GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerSelf})
				if err != nil || len(self.ResourceShares) != 0 {
					t.Fatalf("foreign shares appeared in SELF: %+v %v", self, err)
				}
				read(session, []string{shares[0]}, 1)
				read(session, []string{aws.ToString(foreign.ResourceShare.ResourceShareArn), "arn:aws:ram:us-east-1:" + owner + ":resource-share/missing"}, 0)
				wrongRegion, err := reader("us-west-2", session).GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerOtherAccounts, ResourceShareArns: shares})
				if err != nil || len(wrongRegion.ResourceShares) != 0 {
					t.Fatalf("cross-region enumeration: %+v %v", wrongRegion, err)
				}
				var listed []string
				pages := ram.NewGetResourceSharesPaginator(reader("us-east-1", session), &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerOtherAccounts, MaxResults: new(int32(1))})
				for pages.HasMorePages() {
					page, err := pages.NextPage(ctx)
					if err != nil {
						t.Fatal(err)
					}
					for _, share := range page.ResourceShares {
						listed = append(listed, aws.ToString(share.ResourceShareArn))
					}
				}
				if len(listed) != 2 || listed[0] == listed[1] {
					t.Fatalf("recipient pagination: %v", listed)
				}
				resources, err := reader("us-east-1", session).ListResources(ctx, &ram.ListResourcesInput{ResourceOwner: ramtypes.ResourceOwnerOtherAccounts, ResourceShareArns: []string{shares[0]}})
				if err != nil || len(resources.Resources) != 1 || aws.ToString(resources.Resources[0].Arn) != resourceARN {
					t.Fatalf("accepter resources read: %+v %v", resources, err)
				}
				checkValue := func(creds aws.Credentials, allowed bool) {
					t.Helper()
					out, err := parameterReader(creds).GetParameter(ctx, &ssm.GetParameterInput{Name: &resourceARN})
					if !allowed {
						assertAPIError(t, err, "AccessDeniedException")
						return
					}
					if err != nil || aws.ToString(out.Parameter.Value) != "real-recipient-value" {
						t.Fatalf("shared data-plane value: %+v %v", out, err)
					}
				}
				checkValue(session, true)
				denied := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"ram:GetResourceShares","Resource":"*"}]}`
				_, err = cl.iam(consumer, "test", "").PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: &roleName, PolicyName: &policyName, PolicyDocument: &denied})
				if err != nil {
					t.Fatal(err)
				}
				_, err = reader("us-east-1", session).GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerOtherAccounts, ResourceShareArns: shares})
				assertAPIError(t, err, "AccessDeniedException")
				_, err = cl.iam(consumer, "test", "").PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: &roleName, PolicyName: &policyName, PolicyDocument: &admin})
				if err != nil {
					t.Fatal(err)
				}
				cl = reopen()
				read(session, shares, 2)
				checkValue(session, true)
				_, err = cl.iam(consumer, "test", "").DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: &roleName, PolicyName: &policyName})
				if err != nil {
					t.Fatal(err)
				}
				_, err = cl.iam(consumer, "test", "").DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: &roleName})
				if err != nil {
					t.Fatal(err)
				}
				_, err = reader("us-east-1", session).GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerOtherAccounts})
				assertAPIError(t, err, "AccessDeniedException")
				roleARN = createRole()
				fresh := issue()
				want := 2
				if principalKind == "role" {
					want = 0
				}
				read(fresh, shares, want)
				checkValue(fresh, principalKind == "account")
				for _, shareARN := range shares {
					manager := cl.ram("us-east-1", owner, "test")
					if principalKind == "account" {
						input := &ram.DisassociateResourceShareInput{ResourceShareArn: &shareARN, Principals: []string{consumer}, ClientToken: new("leave-" + shareARN[len(shareARN)-36:])}
						_, err = reader("us-east-1", fresh).DisassociateResourceShare(ctx, input)
						assertAPIError(t, err, "OperationNotPermittedException")
						_, err = manager.DisassociateResourceShare(ctx, &ram.DisassociateResourceShareInput{ResourceShareArn: &shareARN, ResourceArns: []string{resourceARN}})
						if err != nil {
							t.Fatal(err)
						}
						for range 2 {
							left, err := reader("us-east-1", fresh).DisassociateResourceShare(ctx, input)
							if err != nil || len(left.ResourceShareAssociations) != 1 || left.ResourceShareAssociations[0].Status != ramtypes.ResourceShareAssociationStatusDisassociated {
								t.Fatalf("withdraw/replay: %+v %v", left, err)
							}
						}
					} else {
						_, err = manager.DisassociateResourceShare(ctx, &ram.DisassociateResourceShareInput{ResourceShareArn: &shareARN, Principals: []string{principal}})
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				cl = reopen()
				read(fresh, nil, 0)
				checkValue(fresh, false)
				for _, shareARN := range shares {
					_, err := reader("us-east-1", fresh).ListResourceSharePermissions(ctx, &ram.ListResourceSharePermissionsInput{ResourceShareArn: &shareARN})
					assertAPIError(t, err, "UnknownResourceException")
					_, err = cl.ram("us-east-1", owner, "test").DeleteResourceShare(ctx, &ram.DeleteResourceShareInput{ResourceShareArn: &shareARN})
					if err != nil {
						t.Fatal(err)
					}
				}
				read(fresh, shares, 0)
			})
		}
	}
}
