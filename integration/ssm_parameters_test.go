package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
	"stackd/clock"
)

func (c cloudClients) ssm(region, key, secret string) *ssm.Client {
	return ssm.New(ssm.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestSSMParameterKMSAuthorityAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			root := cl.ssm("us-east-1", account, "test")
			key, err := cl.kms(account, "test", "").CreateKey(ctx, &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			keyARN := aws.ToString(key.KeyMetadata.Arn)
			for _, tier := range []ssmtypes.ParameterTier{ssmtypes.ParameterTierStandard, ssmtypes.ParameterTierAdvanced} {
				name := "/authority/" + string(tier)
				plain := "original-" + string(tier)
				if tier == ssmtypes.ParameterTierAdvanced {
					plain = strings.Repeat("s", 5000)
				}
				out, err := root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new(plain), Type: ssmtypes.ParameterTypeSecureString, Tier: tier, KeyId: new(keyARN)})
				if err != nil {
					t.Fatal(err)
				}
				if out.Version != 1 || out.Tier != tier {
					t.Fatalf("creation identity: %+v", out)
				}
				_, err = root.LabelParameterVersion(ctx, &ssm.LabelParameterVersionInput{Name: new(name), Labels: []string{"stable"}})
				if err != nil {
					t.Fatal(err)
				}
				_, err = root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new("new-" + string(tier)), Overwrite: new(true), KeyId: new(keyARN)})
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name + ":stable")})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToString(encoded.Parameter.Value) == plain {
					t.Fatal("SecureString plaintext leaked without decryption")
				}
			}
			_, userKey, userSecret := cl.user(t, account, "parameter-reader")
			policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters","ssm:GetParameterHistory"],"Resource":"arn:aws:ssm:us-east-1:111122223333:parameter/authority/*"}]}`
			putUserPolicy(t, cl.iam(account, "test", ""), "parameter-reader", policy)
			reader := cl.ssm("us-east-1", userKey, userSecret)
			_, err = reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new("/authority/Standard"), WithDecryption: new(true)})
			assertAPIError(t, err, "AccessDeniedException")
			keyPolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters","ssm:GetParameterHistory"],"Resource":"arn:aws:ssm:us-east-1:111122223333:parameter/authority/*"},{"Effect":"Allow","Action":"kms:Decrypt","Resource":%q,"Condition":{"StringEquals":{"kms:ViaService":"ssm.us-east-1.amazonaws.com","kms:EncryptionContext:PARAMETER_ARN":"arn:aws:ssm:us-east-1:111122223333:parameter/authority/Standard"}}}]}`, keyARN)
			putUserPolicy(t, cl.iam(account, "test", ""), "parameter-reader", keyPolicy)
			got, err := reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new("/authority/Standard:stable"), WithDecryption: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(got.Parameter.Value) != "original-Standard" || got.Parameter.Version != 1 {
				t.Fatalf("label decryption: %+v", got.Parameter)
			}
			_, err = reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new("/authority/Advanced"), WithDecryption: new(true)})
			assertAPIError(t, err, "AccessDeniedException")
			cl = reopen()
			root = cl.ssm("us-east-1", account, "test")
			for _, tier := range []string{"Standard", "Advanced"} {
				history, err := root.GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{Name: new("/authority/" + tier), WithDecryption: new(true)})
				if err != nil {
					t.Fatal(err)
				}
				original := "original-Standard"
				if tier == "Advanced" {
					original = strings.Repeat("s", 5000)
				}
				if len(history.Parameters) != 2 || history.Parameters[0].Version != 1 || aws.ToString(history.Parameters[0].Value) != original || len(history.Parameters[0].Labels) != 1 || history.Parameters[0].Labels[0] != "stable" || aws.ToString(history.Parameters[1].Value) != "new-"+tier {
					t.Fatalf("retained encrypted history %s: %+v", tier, history.Parameters)
				}
			}
			_, err = cl.ssm("us-west-2", account, "test").GetParameter(ctx, &ssm.GetParameterInput{Name: new("/authority/Standard")})
			assertAPIError(t, err, "ParameterNotFound")
			_, err = cl.ssm("us-east-1", "444455556666", "test").GetParameter(ctx, &ssm.GetParameterInput{Name: new("/authority/Standard")})
			assertAPIError(t, err, "ParameterNotFound")
			putUserPolicy(t, cl.iam(account, "test", ""), "parameter-reader", policy)
			_, err = cl.ssm("us-east-1", userKey, userSecret).GetParameter(ctx, &ssm.GetParameterInput{Name: new("/authority/Standard:stable"), WithDecryption: new(true)})
			assertAPIError(t, err, "AccessDeniedException")
		})
	}
}

func TestSSMParameterSharingAndPolicyRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const owner = "111122223333"
			const consumer = "444455556666"
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
			var active *stackd.Stack
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner, Clock: source}, func(c stackd.Config) (*stackd.Stack, *httptest.Server) {
				cloud, server := startPublicCloud(t, c)
				active = cloud
				return cloud, server
			})
			root := cl.ssm("us-east-1", owner, "test")
			name := "/shared/config"
			arn := "arn:aws:ssm:us-east-1:" + owner + ":parameter/shared/config"
			expiry := source.Now().Add(2 * time.Hour).Format(time.RFC3339)
			policies := fmt.Sprintf(`[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":%q}}]`, expiry)
			_, err := root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new("shared-original"), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierAdvanced, Policies: new(policies)})
			if err != nil {
				t.Fatal(err)
			}
			userARN, userKey, userSecret := cl.user(t, consumer, "shared-reader")
			putUserPolicy(t, cl.iam(consumer, "test", ""), "shared-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParameter","Resource":%q}]}`, arn))
			remote := cl.ssm("us-east-1", userKey, userSecret)
			_, err = remote.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"ssm:GetParameter","Resource":%q}]}`, userARN, arn)
			grant, err := root.PutResourcePolicy(ctx, &ssm.PutResourcePolicyInput{ResourceArn: new(arn), Policy: new(policy)})
			if err != nil {
				t.Fatal(err)
			}
			got, err := remote.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(got.Parameter.Value) != "shared-original" {
				t.Fatalf("shared read: %+v", got.Parameter)
			}
			cl = reopen()
			root = cl.ssm("us-east-1", owner, "test")
			remote = cl.ssm("us-east-1", userKey, userSecret)
			got, err = remote.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			if err != nil || aws.ToString(got.Parameter.Value) != "shared-original" {
				t.Fatalf("retained share: %v %v", got, err)
			}
			_, err = root.DeleteResourcePolicy(ctx, &ssm.DeleteResourcePolicyInput{ResourceArn: new(arn), PolicyId: grant.PolicyId, PolicyHash: grant.PolicyHash})
			if err != nil {
				t.Fatal(err)
			}
			_, err = remote.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := active.AdvanceTime(ctx, 2*time.Hour); err != nil {
				t.Fatal(err)
			}
			if _, err := active.RunDueJobs(ctx, 100); err != nil {
				t.Fatal(err)
			}
			_, err = root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name)})
			assertAPIError(t, err, "ParameterNotFound")
		})
	}
}
