package stackd_test

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd"
	"stackd/storage"
)

func TestOutboundIdentityRevalidatesBeforePublishing(t *testing.T) {
	for _, change := range []string{"disable", "revoke_key", "deny_policy", "commit_failure", "cancel"} {
		t.Run(change, func(t *testing.T) {
			backends := storage.NewMemory()
			repository := &signedAuthorityRepository{Repository: backends.IAM}
			backends.IAM = repository
			c, source := outboundCloud(t, stackd.Config{Storage: backends})
			root := c.iam("test", "test", "")
			_, err := root.EnableOutboundWebIdentityFederation(t.Context(), &iam.EnableOutboundWebIdentityFederationInput{})
			if err != nil {
				t.Fatal(err)
			}
			_, key, secret := c.user(t, "test", "outbound-authority")
			putUserPolicy(t, root, "outbound-authority", allow(`"sts:GetWebIdentityToken"`, "*"))
			advanceClock(t, source, 10*time.Second)
			plan := &signedAuthorityPlan{key: key}
			code := "AccessDenied"
			switch change {
			case "disable":
				code = "OutboundWebIdentityFederationDisabledException"
				plan.before = func(ctx context.Context) error {
					_, err := root.DisableOutboundWebIdentityFederation(ctx, &iam.DisableOutboundWebIdentityFederationInput{})
					if err != nil {
						return err
					}
					return source.Advance(10 * time.Second)
				}
			case "revoke_key":
				code = "InvalidClientTokenId"
				plan.before = func(ctx context.Context) error {
					_, err := root.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String("outbound-authority"), AccessKeyId: &key})
					return err
				}
			case "deny_policy":
				plan.before = func(ctx context.Context) error {
					_, err := root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String("outbound-authority"), PolicyName: aws.String("access"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"sts:GetWebIdentityToken","Resource":"*"}}`)})
					return err
				}
			case "commit_failure":
				plan.failCommit = true
				code = "InternalFailure"
			case "cancel":
				plan.cancelCommit = true
				code = "InternalFailure"
			}
			repository.arm(plan)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			out, err := c.sts(key, secret, "").GetWebIdentityToken(ctx, outboundInput())
			plan.wait(t, ctx)
			if plan.hookErr != nil {
				t.Fatal(plan.hookErr)
			}
			if out != nil {
				t.Fatalf("token escaped failed authority: %+v", out)
			}
			assertAPIError(t, err, code)
		})
	}
}
