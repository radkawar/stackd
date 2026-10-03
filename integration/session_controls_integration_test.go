package stackd_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd/storage"
)

func TestSignedSessionKeepsOrganizationControlsUntilPublication(t *testing.T) {
	for _, action := range []string{"AssumeRole", "GetFederationToken"} {
		t.Run(action, func(t *testing.T) {
			backends := storage.NewMemory()
			repository := &signedAuthorityRepository{Repository: backends.IAM}
			backends.IAM = repository
			organization := newOrganizationReportFixture(t, backends)
			member := organization.account(t, organization.rootID, "session-controls")
			arn, key, secret := organization.cloud.user(t, member, "controlled-caller")
			putUserPolicy(t, organization.cloud.iam(member, "test", ""), "controlled-caller", allow(`"sts:*"`, "*"))
			role, err := organization.iam.CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName:                 aws.String("controlled-role"),
				AssumeRolePolicyDocument: aws.String(fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sts:AssumeRole"}}`, arn)),
			})
			if err != nil {
				t.Fatal(err)
			}
			policyID := organization.policy(t, "session-controls", allow(`"*"`, "*"), member)
			deny := fmt.Sprintf(`{"Statement":{"Effect":"Deny","Action":"sts:%s","Resource":"*"}}`, action)
			changed, revision, err := backends.Organizations.Load(t.Context(), "aws")
			if err != nil {
				t.Fatal(err)
			}
			for i := range changed.Organizations {
				for j := range changed.Organizations[i].Policies {
					policy := &changed.Organizations[i].Policies[j]
					if policy.PolicySummary.ID == policyID {
						policy.Content = deny
					}
				}
			}
			f := &signedAuthorityFixture{
				cloudClients: organization.cloud, repository: repository, key: key,
				caller:     organization.cloud.sts(key, secret, ""),
				assume:     &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("controlled")},
				federation: &sts.GetFederationTokenInput{Name: aws.String("controlled")},
			}
			called := false
			plan := &signedAuthorityPlan{key: key}
			plan.duringRoleRead = func() {
				called = true
				// This is an independent request at the native Organizations write
				// boundary, after its earlier authorization. It must wait for the
				// active IAM publication instead of changing a detached snapshot.
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				committed, err := backends.Organizations.CompareAndSwap(ctx, "aws", revision, changed, nil)
				if committed || !errors.Is(err, context.DeadlineExceeded) {
					plan.hookErr = fmt.Errorf("Organizations changed during IAM publication: committed=%v err=%v", committed, err)
				}
			}
			repository.arm(plan)
			ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
			defer cancel()
			issued, err := f.issue(ctx, action)
			plan.wait(t, ctx)
			if err != nil || plan.hookErr != nil || !called || issued == nil {
				t.Fatalf("issuance: %v, controls: %v, hook called=%v", err, plan.hookErr, called)
			}
			if _, err := f.sessionSTS(issued).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
				t.Fatal("committed credentials are unusable", err)
			}
			if _, err := organization.org.UpdatePolicy(ctx, &organizations.UpdatePolicyInput{PolicyId: &policyID, Content: &deny}); err != nil {
				t.Fatal("control update did not resume after publication", err)
			}
			_, err = f.issue(ctx, action)
			assertAPIError(t, err, "AccessDenied")
		})
	}
}
