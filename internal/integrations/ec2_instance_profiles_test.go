package integrations

import (
	"errors"
	"testing"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
)

func TestEC2ProfileDeliveredCredentialSurvivesMembershipAndTrustChanges(t *testing.T) {
	f := newLambdaRoleFixture(t)
	trust := `{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.role.AssumeRolePolicyDocument = trust
	profile := iam.InstanceProfile{Path: "/", InstanceProfileName: "guest", InstanceProfileId: "AIPAEC2PROFILE", Arn: "arn:aws:iam::123456789012:instance-profile/guest", RoleId: f.role.RoleId, CreateDate: f.clock.Now()}
	f.update(t, func(tx iam.WriteTx) error {
		if err := tx.PutRole(f.scope, f.role); err != nil {
			return err
		}
		return tx.PutInstanceProfile(f.scope, profile)
	})
	adapter := EC2InstanceProfiles{IAM: f.adapter.IAM.(EC2InstanceProfileAuthority), Roles: f.adapter.ServiceRoles}
	instance := ec2.InstanceCredentialOrigin{InstanceARN: "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", VPCID: "vpc-0123456789abcdef0", PrivateIPv4: "10.0.1.10"}
	projection := api.IamInstanceProfile{Arn: new(api.String(profile.Arn)), Id: new(api.String(profile.InstanceProfileId))}
	first, err := adapter.InstanceProfileCredentials(f.ctx, instance, projection, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if first.Credentials == nil || first.RoleName != f.role.RoleName || first.LastUpdated != f.clock.Now() {
		t.Fatalf("initial credential identity/time: role=%s updated=%s", first.RoleName, first.LastUpdated)
	}
	if lifetime := first.Credentials.Expiration.Sub(first.LastUpdated); lifetime <= time.Duration(f.role.MaxSessionDuration)*time.Second {
		t.Fatalf("EC2 credential lifetime %s was constrained by the role's one-hour session maximum", lifetime)
	}
	credentialID := string(*first.Credentials.AccessKeyId)
	profile.RoleId = ""
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.update(t, func(tx iam.WriteTx) error {
		if err := tx.PutRole(f.scope, f.role); err != nil {
			return err
		}
		return tx.PutInstanceProfile(f.scope, profile)
	})
	// Reconstruct the adapter so no in-process session cache can supply this
	// reference. The shared IAM credential record remains authoritative.
	adapter = EC2InstanceProfiles{IAM: f.adapter.IAM.(EC2InstanceProfileAuthority), Roles: f.adapter.ServiceRoles}
	retained, err := adapter.InstanceProfileCredentials(f.ctx, instance, projection, credentialID, true)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Credentials == nil || string(*retained.Credentials.AccessKeyId) != credentialID || retained.RoleName != f.role.RoleName {
		t.Fatal("membership/trust edit revoked delivered credential before refresh")
	}
	empty, err := adapter.InstanceProfileCredentials(f.ctx, instance, projection, "", true)
	if err != nil || empty.Credentials != nil || empty.RoleName != "" {
		t.Fatalf("fresh delivery reused removed profile role: role=%s error=%v", empty.RoleName, err)
	}
	f.clock.Advance(time.Hour)
	refreshed, err := adapter.InstanceProfileCredentials(f.ctx, instance, projection, credentialID, true)
	if err != nil || refreshed.Credentials != nil || refreshed.RoleName != "" {
		t.Fatalf("removed role survived the bounded current-owner refresh: role=%s error=%v", refreshed.RoleName, err)
	}
	profile.RoleId = f.role.RoleId
	f.update(t, func(tx iam.WriteTx) error { return tx.PutInstanceProfile(f.scope, profile) })
	denied, err := adapter.InstanceProfileCredentials(f.ctx, instance, projection, "", true)
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.Code != "AccessDenied" || denied.RoleName != f.role.RoleName {
		t.Fatalf("fresh association bypassed current trust: role=%s error=%v", denied.RoleName, err)
	}
	if _, err := f.adapter.Credentials.Resolve(f.ctx, credentialID); err != nil {
		t.Fatalf("trust denial revoked already issued STS credential: %v", err)
	}
	profile.InstanceProfileId = "AIPARECREATED"
	f.role.AssumeRolePolicyDocument = trust
	f.update(t, func(tx iam.WriteTx) error {
		if err := tx.PutRole(f.scope, f.role); err != nil {
			return err
		}
		return tx.PutInstanceProfile(f.scope, profile)
	})
	f.clock.Advance(time.Hour)
	_, err = adapter.InstanceProfileCredentials(f.ctx, instance, projection, credentialID, true)
	if !errors.As(err, &rejected) || rejected.Code != "InstanceProfileNotFound" {
		t.Fatalf("old association adopted recreated profile with same ARN: %v", err)
	}
}
