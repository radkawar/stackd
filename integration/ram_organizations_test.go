package stackd_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
	"stackd/clock"
)

func TestRAMOrganizationSharingUsesCurrentMembershipRetained(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
			cl, reopen := retainedCloud(t, backend, stackd.Config{Clock: source})
			f := organizationFixture(t, cl, source)
			unit := f.unit(t, f.rootID, "sharing-consumers")
			owner := f.account(t, f.rootID, "sharing-owner")
			consumer := f.account(t, unit, "sharing-consumer")
			ou, err := f.org.DescribeOrganizationalUnit(ctx, &organizations.DescribeOrganizationalUnitInput{OrganizationalUnitId: new(unit)})
			if err != nil {
				t.Fatal(err)
			}
			arn := "arn:aws:ssm:us-east-1:" + owner + ":parameter/ram/organization"
			_, err = cl.ssm("us-east-1", owner, "test").PutParameter(ctx, &ssm.PutParameterInput{Name: new("/ram/organization"), Value: new("current-ou-value"), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierAdvanced})
			if err != nil {
				t.Fatal(err)
			}
			ownerRAM := cl.ram("us-east-1", owner, "test")
			input := &ram.CreateResourceShareInput{Name: new("organization"), ResourceArns: []string{arn}, Principals: []string{aws.ToString(ou.OrganizationalUnit.Arn)}, AllowExternalPrincipals: new(false)}
			_, err = ownerRAM.CreateResourceShare(ctx, input)
			assertAPIError(t, err, "OperationNotPermittedException")
			_, err = f.org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: new("ram.amazonaws.com")})
			if err != nil {
				t.Fatal(err)
			}
			// Trusted access alone does not create RAM's protected IAM service role.
			_, err = ownerRAM.CreateResourceShare(ctx, input)
			assertAPIError(t, err, "OperationNotPermittedException")
			enabled, err := cl.ram("us-east-1", "test", "test").EnableSharingWithAwsOrganization(ctx, &ram.EnableSharingWithAwsOrganizationInput{})
			if err != nil || !aws.ToBool(enabled.ReturnValue) {
				t.Fatalf("enable organization sharing: %+v %v", enabled, err)
			}
			share, err := ownerRAM.CreateResourceShare(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			invitations, err := cl.ram("us-east-1", consumer, "test").GetResourceShareInvitations(ctx, &ram.GetResourceShareInvitationsInput{ResourceShareArns: []string{aws.ToString(share.ResourceShare.ResourceShareArn)}})
			if err != nil || len(invitations.ResourceShareInvitations) != 0 {
				t.Fatalf("organization invitation: %+v %v", invitations, err)
			}
			check := func(allowed bool) {
				t.Helper()
				out, err := cl.ssm("us-east-1", consumer, "test").GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
				if !allowed {
					assertAPIError(t, err, "AccessDeniedException")
					return
				}
				if err != nil || aws.ToString(out.Parameter.Value) != "current-ou-value" {
					t.Fatalf("current organization access: %+v %v", out, err)
				}
			}
			check(true)
			_, err = f.org.MoveAccount(ctx, &organizations.MoveAccountInput{AccountId: new(consumer), SourceParentId: new(unit), DestinationParentId: new(f.rootID)})
			if err != nil {
				t.Fatal(err)
			}
			check(false)
			cl = reopen()
			check(false)
			f.org = organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: new(cl.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: cl.server.Client(), RetryMaxAttempts: 1})
			_, err = f.org.MoveAccount(ctx, &organizations.MoveAccountInput{AccountId: new(consumer), SourceParentId: new(f.rootID), DestinationParentId: new(unit)})
			if err != nil {
				t.Fatal(err)
			}
			check(true)
			_, err = f.org.DisableAWSServiceAccess(ctx, &organizations.DisableAWSServiceAccessInput{ServicePrincipal: new("ram.amazonaws.com")})
			if err != nil {
				t.Fatal(err)
			}
			check(false)
		})
	}
}
