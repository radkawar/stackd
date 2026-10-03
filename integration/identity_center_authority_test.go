package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

func identityAdminClient(c cloudClients, key, secret string) *ssoadmin.Client {
	return ssoadmin.New(ssoadmin.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func provisionIdentityPermission(t *testing.T, c cloudClients, admin *ssoadmin.Client, instance, permission *string, account string) iamtypes.Role {
	t.Helper()
	if _, err := admin.ProvisionPermissionSet(t.Context(), &ssoadmin.ProvisionPermissionSetInput{InstanceArn: instance, PermissionSetArn: permission, TargetType: "AWS_ACCOUNT", TargetId: aws.String(account)}); err != nil {
		t.Fatal(err)
	}
	roles, err := c.iam(account, "test", "").ListRoles(t.Context(), &iam.ListRolesInput{PathPrefix: aws.String("/aws-reserved/sso.amazonaws.com/")})
	if err != nil || len(roles.Roles) != 1 {
		t.Fatalf("provisioned roles: %+v %v", roles, err)
	}
	return roles.Roles[0]
}

func TestIdentityCenterReservedRolesRejectPublicMutation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			admin := identityAdminClient(c, eventDeliveryAccount, "test")
			instance, err := admin.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{Name: aws.String("protected-roles")})
			if err != nil {
				t.Fatal(err)
			}
			root := c.iam(eventDeliveryAccount, "test", "")
			trust := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}}`, eventDeliveryAccount)
			policy := `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`
			managed := aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")
			cases := []struct {
				name   string
				bare   bool
				mutate func(*string) error
			}{
				{name: "trust", mutate: func(role *string) error {
					_, e := root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: role, PolicyDocument: &trust})
					return e
				}},
				{name: "inline", mutate: func(role *string) error {
					_, e := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role, PolicyName: aws.String("injected"), PolicyDocument: &policy})
					return e
				}},
				{name: "delete-inline", mutate: func(role *string) error {
					_, e := root.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: role, PolicyName: aws.String("AwsSSOInlinePolicy")})
					return e
				}},
				{name: "attach", mutate: func(role *string) error {
					_, e := root.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{RoleName: role, PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")})
					return e
				}},
				{name: "detach", mutate: func(role *string) error {
					_, e := root.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{RoleName: role, PolicyArn: managed})
					return e
				}},
				{name: "boundary", mutate: func(role *string) error {
					_, e := root.PutRolePermissionsBoundary(ctx, &iam.PutRolePermissionsBoundaryInput{RoleName: role, PermissionsBoundary: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")})
					return e
				}},
				{name: "delete-boundary", mutate: func(role *string) error {
					_, e := root.DeleteRolePermissionsBoundary(ctx, &iam.DeleteRolePermissionsBoundaryInput{RoleName: role})
					return e
				}},
				{name: "duration", mutate: func(role *string) error {
					_, e := root.UpdateRole(ctx, &iam.UpdateRoleInput{RoleName: role, MaxSessionDuration: aws.Int32(7200)})
					return e
				}},
				{name: "description", mutate: func(role *string) error {
					_, e := root.UpdateRole(ctx, &iam.UpdateRoleInput{RoleName: role, Description: aws.String("changed")})
					return e
				}},
				{name: "role-description", mutate: func(role *string) error {
					_, e := root.UpdateRoleDescription(ctx, &iam.UpdateRoleDescriptionInput{RoleName: role, Description: aws.String("changed")})
					return e
				}},
				{name: "tag", mutate: func(role *string) error {
					_, e := root.TagRole(ctx, &iam.TagRoleInput{RoleName: role, Tags: []iamtypes.Tag{{Key: aws.String("authority"), Value: aws.String("changed")}}})
					return e
				}},
				{name: "delete", bare: true, mutate: func(role *string) error { _, e := root.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: role}); return e }},
			}
			for _, row := range cases {
				t.Run(row.name, func(t *testing.T) {
					permission, e := admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: aws.String("Protected-" + row.name)})
					if e != nil {
						t.Fatal(e)
					}
					arn := permission.PermissionSet.PermissionSetArn
					if !row.bare {
						if _, e = admin.PutInlinePolicyToPermissionSet(ctx, &ssoadmin.PutInlinePolicyToPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn, InlinePolicy: &policy}); e != nil {
							t.Fatal(e)
						}
						if _, e = admin.AttachManagedPolicyToPermissionSet(ctx, &ssoadmin.AttachManagedPolicyToPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn, ManagedPolicyArn: managed}); e != nil {
							t.Fatal(e)
						}
						if _, e = admin.PutPermissionsBoundaryToPermissionSet(ctx, &ssoadmin.PutPermissionsBoundaryToPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn, PermissionsBoundary: &ssotypes.PermissionsBoundary{ManagedPolicyArn: managed}}); e != nil {
							t.Fatal(e)
						}
					}
					role := provisionIdentityPermission(t, c, admin, instance.InstanceArn, arn, eventDeliveryAccount)
					t.Cleanup(func() {
						if _, e := admin.DeletePermissionSet(ctx, &ssoadmin.DeletePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn}); e != nil {
							t.Errorf("trusted cleanup: %v", e)
						}
					})
					assertAPIError(t, row.mutate(role.RoleName), "UnmodifiableEntity")
					retained, e := root.GetRole(ctx, &iam.GetRoleInput{RoleName: role.RoleName})
					if e != nil || aws.ToString(retained.Role.AssumeRolePolicyDocument) != aws.ToString(role.AssumeRolePolicyDocument) || aws.ToString(retained.Role.RoleId) != aws.ToString(role.RoleId) {
						t.Fatalf("reserved trust/incarnation changed: %v", e)
					}
					if row.name == "trust" {
						_, e = c.sts(eventDeliveryAccount, "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Arn, RoleSessionName: aws.String("unauthorized")})
						assertAPIError(t, e, "AccessDenied")
					}
					if _, e = admin.UpdatePermissionSet(ctx, &ssoadmin.UpdatePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn, SessionDuration: aws.String("PT2H")}); e != nil {
						t.Fatal(e)
					}
					updated := provisionIdentityPermission(t, c, admin, instance.InstanceArn, arn, eventDeliveryAccount)
					if aws.ToInt32(updated.MaxSessionDuration) != 7200 || aws.ToString(updated.RoleId) != aws.ToString(role.RoleId) {
						t.Fatal("trusted provisioning did not retain and update protected role")
					}
				})
			}
		})
	}
}

func TestIdentityCenterPermissionDeletionRequiresCurrentAccountAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, revoke := range []string{"delegation", "trusted-access"} {
			t.Run(backend+"/"+revoke, func(t *testing.T) {
				ctx := t.Context()
				source := clock.NewManual(time.Now().UTC())
				c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
				org := c.organizations(eventDeliveryAccount, "test")
				if _, e := org.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: "ALL"}); e != nil {
					t.Fatal(e)
				}
				accounts := []string{}
				names := []string{"target"}
				if revoke == "delegation" {
					names = []string{"delegate", "target"}
				}
				for _, name := range names {
					created, e := org.CreateAccount(ctx, &organizations.CreateAccountInput{AccountName: &name, Email: aws.String(name + "@example.test")})
					if e != nil {
						t.Fatal(e)
					}
					status := waitAccountCreation(t, org, created.CreateAccountStatus, source)
					if status.State != "SUCCEEDED" {
						t.Fatalf("account failed: %+v", status)
					}
					accounts = append(accounts, aws.ToString(status.AccountId))
				}
				owner, target := eventDeliveryAccount, accounts[len(accounts)-1]
				if revoke == "delegation" {
					owner = accounts[0]
					if owner >= target {
						t.Fatal("fixture must visit eligible own account before revoked foreign account")
					}
				}
				accounts = []string{owner, target}
				principal := aws.String("sso.amazonaws.com")
				if _, e := org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: principal}); e != nil {
					t.Fatal(e)
				}
				if revoke == "delegation" {
					if _, e := org.RegisterDelegatedAdministrator(ctx, &organizations.RegisterDelegatedAdministratorInput{AccountId: &owner, ServicePrincipal: principal}); e != nil {
						t.Fatal(e)
					}
				}
				admin := identityAdminClient(c, owner, "test")
				instance, e := admin.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{Name: aws.String("authority")})
				if e != nil {
					t.Fatal(e)
				}
				permission, e := admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: aws.String("ScopedDelete")})
				if e != nil {
					t.Fatal(e)
				}
				arn := permission.PermissionSet.PermissionSetArn
				roles := map[string]iamtypes.Role{}
				for _, account := range accounts {
					roles[account] = provisionIdentityPermission(t, c, admin, instance.InstanceArn, arn, account)
				}
				_, key, secret := c.user(t, owner, "permission-deleter")
				putUserPolicy(t, c.iam(owner, "test", ""), "permission-deleter", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sso:DeletePermissionSet","Resource":[%q,%q]}}`, aws.ToString(instance.InstanceArn), aws.ToString(arn)))
				if revoke == "delegation" {
					_, e = org.DeregisterDelegatedAdministrator(ctx, &organizations.DeregisterDelegatedAdministratorInput{AccountId: &owner, ServicePrincipal: principal})
				} else {
					_, e = org.DisableAWSServiceAccess(ctx, &organizations.DisableAWSServiceAccessInput{ServicePrincipal: principal})
				}
				if e != nil {
					t.Fatal(e)
				}
				deleter := identityAdminClient(c, key, secret)
				_, e = deleter.DeletePermissionSet(ctx, &ssoadmin.DeletePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn})
				assertAPIError(t, e, "AccessDeniedException")
				c = reopen()
				admin = identityAdminClient(c, owner, "test")
				org = c.organizations(eventDeliveryAccount, "test")
				if _, e = admin.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn}); e != nil {
					t.Fatalf("denied deletion lost permission set: %v", e)
				}
				for account, role := range roles {
					retained, e := c.iam(account, "test", "").GetRole(ctx, &iam.GetRoleInput{RoleName: role.RoleName})
					if e != nil || aws.ToString(retained.Role.RoleId) != aws.ToString(role.RoleId) {
						t.Fatalf("denied deletion partially changed account %s: %v", account, e)
					}
				}
				if revoke == "delegation" {
					_, e = org.RegisterDelegatedAdministrator(ctx, &organizations.RegisterDelegatedAdministratorInput{AccountId: &owner, ServicePrincipal: principal})
				} else {
					_, e = org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: principal})
				}
				if e != nil {
					t.Fatal(e)
				}
				deleter = identityAdminClient(c, key, secret)
				if _, e = deleter.DeletePermissionSet(ctx, &ssoadmin.DeletePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: arn}); e != nil {
					t.Fatalf("scoped authorized deletion rejected: %v", e)
				}
				for account, role := range roles {
					_, e = c.iam(account, "test", "").GetRole(ctx, &iam.GetRoleInput{RoleName: role.RoleName})
					assertAPIError(t, e, "NoSuchEntity")
				}
			})
		}
	}
}
