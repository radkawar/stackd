package integrations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"stackd/clock"
	iamapi "stackd/internal/awsapi/iam"
	orgapi "stackd/internal/awsapi/organizations"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
)

// This principal is a real native IAM user with a mutable inline policy, not an
// authorizer stub. Denials therefore exercise the same owner evaluation as API calls.
func cfnGovernanceUser(t *testing.T, f *cfnOrgSSOOwnerFixture, name string) (context.Context, func(...string)) {
	t.Helper()
	out, e := cfnOrgIdentityCall[iamapi.CreateUserResponse](f.ctx, f.commands, "iam", "CreateUser", map[string]any{"UserName": name})
	if e != nil {
		t.Fatal(e)
	}
	metadata := awsctx.FromContext(f.ctx)
	metadata.PrincipalARN = cfnComputeValue(out.User.Arn)
	metadata.PrincipalID = cfnComputeValue(out.User.UserId)
	ctx := awsctx.WithMetadata(f.ctx, metadata)
	policy := func(denied ...string) {
		t.Helper()
		statements := []any{map[string]any{"Effect": "Allow", "Action": "*", "Resource": "*"}}
		if len(denied) > 0 {
			statements = append(statements, map[string]any{"Effect": "Deny", "Action": denied, "Resource": "*"})
		}
		doc, e := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if e != nil {
			t.Fatal(e)
		}
		f.run(t, "iam", "PutUserPolicy", map[string]any{"UserName": name, "PolicyName": "current-authority", "PolicyDocument": string(doc)})
	}
	policy()
	return ctx, policy
}

func TestCFNOrganizationsAccountPrivateReceiptAndNativeMembership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNOrgSSOOwnerFixture(t, backend)
			at := clock.NewManual(time.Date(2034, 1, 2, 3, 4, 5, 0, time.UTC))
			f.source = at
			f.restart(t)
			f.run(t, "organizations", "CreateOrganization", map[string]any{"FeatureSet": "ALL"})
			user, policy := cfnGovernanceUser(t, f, "account-controller")
			h := cfnOrganizationAccount{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::Organizations::Account", "Account", cloudformation.Properties{"AccountName": "private-member", "Email": "private@example.com", "Tags": []any{map[string]any{"Key": "team", "Value": "one"}}})
			r.DeletionPolicy = "Delete"
			native, e := cfnOrgIdentityCall[orgapi.CreateAccountOutput](f.ctx, f.commands, "organizations", "CreateAccount", map[string]any{"AccountName": "counterfeit", "Email": "counterfeit@example.com", "Tags": cfnOrgSSOCounterfeit(r)})
			if e != nil {
				t.Fatal(e)
			}
			if native.CreateAccountStatus.AccountId != nil {
				t.Fatal("ordinary pending account exposed the reserved ID")
			}
			if e = at.Advance(time.Second); e != nil {
				t.Fatal(e)
			}
			if _, e = f.org.JobDriver().RunDue(f.ctx, 100); e != nil {
				t.Fatal(e)
			}
			status, e := cfnOrgIdentityCall[orgapi.DescribeCreateAccountStatusOutput](f.ctx, f.commands, "organizations", "DescribeCreateAccountStatus", map[string]any{"CreateAccountRequestId": cfnComputeValue(native.CreateAccountStatus.Id)})
			if e != nil {
				t.Fatal(e)
			}
			counterfeit := cfnComputeValue(status.CreateAccountStatus.AccountId)
			if counterfeit == "" {
				t.Fatalf("native account did not provision: %+v", status)
			}
			observed, e := h.RecoverCreation(user, r)
			cfnOrgSSONotAdmitted(t, "counterfeit account receipt", observed, e)
			stale := r
			stale.PhysicalID = counterfeit
			if _, e = h.Update(user, stale); e == nil {
				t.Fatal("public markers adopted native account on no-op update")
			}
			if e = h.Delete(user, stale); e == nil {
				t.Fatal("public markers authorized native account removal")
			}

			// Lose only the reply after the real owner commits its accepted job.
			boundary := &cfnDeveloperLostReply{owner: f.org, action: "CreateAccount"}
			lossy := cfnOrganizationAccount{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"organizations": boundary})}
			admitted, e := lossy.Create(user, r)
			if e == nil || admitted.PhysicalID == "" || admitted.PhysicalID == counterfeit {
				t.Fatalf("lost admission identity: %+v %v", admitted, e)
			}
			r.PhysicalID = admitted.PhysicalID
			if stable, e := h.Stabilize(user, r); e != nil || stable {
				t.Fatalf("pending account stabilized prematurely: %v %v", stable, e)
			}
			f.restart(t)
			h = cfnOrganizationAccount{f.commands}
			recovered, e := h.RecoverCreation(user, r)
			cfnOrgSSOSame(t, "pending receipt after reopen", r.PhysicalID, recovered, e)
			replay, e := h.Create(user, r)
			cfnOrgSSOSame(t, "account create replay", r.PhysicalID, replay, e)
			if e = at.Advance(time.Second); e != nil {
				t.Fatal(e)
			}
			if _, e = f.org.JobDriver().RunDue(f.ctx, 100); e != nil {
				t.Fatal(e)
			}
			if stable, e := h.Stabilize(user, r); e != nil || !stable {
				t.Fatalf("native role provisioning did not stabilize: %v %v", stable, e)
			}
			tags, e := cfnOrganizationsTags(f.ctx, f.commands, r.PhysicalID)
			if e != nil {
				t.Fatal(e)
			}
			cfnOrgSSONoPublicClaim(t, "account", tags)
			member := awsctx.FromContext(f.ctx)
			member.AccountID = r.PhysicalID
			member.PrincipalARN = "arn:aws:iam::" + r.PhysicalID + ":root"
			member.PrincipalID = r.PhysicalID
			memberCtx := awsctx.WithMetadata(f.ctx, member)
			for _, name := range []string{"OrganizationAccountAccessRole", "AWSServiceRoleForOrganizations"} {
				out, e := cfnOrgIdentityCall[iamapi.GetRoleResponse](memberCtx, f.commands, "iam", "GetRole", map[string]any{"RoleName": name})
				if e != nil || out.Role == nil {
					t.Fatalf("actual native IAM role %s missing: %+v %v", name, out, e)
				}
			}

			// Public deletion/forgery and ordinary Cloud Control updates cannot transfer a claim.
			f.run(t, "organizations", "UntagResource", map[string]any{"ResourceId": r.PhysicalID, "TagKeys": []string{"team"}})
			f.run(t, "organizations", "TagResource", map[string]any{"ResourceId": r.PhysicalID, "Tags": cfnOrgSSOCounterfeit(cfnOrgSSOOther(r))})
			r.Previous = r.Properties
			if _, e = h.Update(user, r); e != nil {
				t.Fatal(e)
			}
			direct := r
			direct.CloudControl = true
			direct.Previous = r.Properties
			direct.Properties = cloudformation.Properties{"AccountName": "private-member", "Email": "private@example.com", "Tags": []any{map[string]any{"Key": "team", "Value": "direct"}}}
			if _, e = h.Update(user, direct); e != nil {
				t.Fatal(e)
			}
			foreign := cfnOrgSSOOther(r)
			if _, e = h.Update(user, foreign); e == nil {
				t.Fatal("ordinary update transferred private ownership")
			}
			if e = h.Delete(user, foreign); e == nil {
				t.Fatal("foreign incarnation removed owned member")
			}
			regional := awsctx.FromContext(user)
			regional.Region = "us-west-2"
			if _, e = h.Update(awsctx.WithMetadata(user, regional), r); e == nil {
				t.Fatal("different region matched the private account claim")
			}
			policy("organizations:ListCreateAccountStatus", "organizations:DescribeAccount")
			if observed, e = h.RecoverCreation(user, r); e == nil || observed.PhysicalID != "" {
				t.Fatalf("denied recovery invented an identity: %+v %v", observed, e)
			}
			if _, e = h.Update(user, r); e == nil {
				t.Fatal("denied no-op update passed private provenance")
			}
			if e = h.Delete(user, r); e == nil {
				t.Fatal("denied delete passed private provenance")
			}
			policy()
			retained := r
			retained.DeletionPolicy = ""
			if e = h.Delete(user, retained); e != nil {
				t.Fatal(e)
			}
			if _, e = h.Read(f.ctx, r); e != nil {
				t.Fatalf("default Retain removed the real account: %v", e)
			}

			// Native membership removal ends ownership; rejoining the same registered
			// account is a fresh unclaimed membership despite its retained creation history.
			f.run(t, "organizations", "RemoveAccountFromOrganization", map[string]any{"AccountId": r.PhysicalID})
			invite, e := cfnOrgIdentityCall[orgapi.InviteAccountToOrganizationOutput](f.ctx, f.commands, "organizations", "InviteAccountToOrganization", map[string]any{"Target": map[string]any{"Id": r.PhysicalID, "Type": "ACCOUNT"}})
			if e != nil {
				t.Fatal(e)
			}
			if e = cfnComputeRun(memberCtx, f.commands, "organizations", "AcceptHandshake", map[string]any{"HandshakeId": cfnComputeValue(invite.Handshake.Id)}); e != nil {
				t.Fatal(e)
			}
			f.run(t, "organizations", "TagResource", map[string]any{"ResourceId": r.PhysicalID, "Tags": cfnOrgSSOCounterfeit(r)})
			f.restart(t)
			h = cfnOrganizationAccount{f.commands}
			observed, e = h.RecoverCreation(user, r)
			cfnOrgSSONotAdmitted(t, "removed/rejoined account receipt", observed, e)
			if e = h.Delete(user, r); e == nil {
				t.Fatal("stale controller removed rejoined native account")
			}
			if _, e = h.Read(f.ctx, r); e != nil {
				t.Fatalf("rejoined membership was damaged: %v", e)
			}
		})
	}
}
