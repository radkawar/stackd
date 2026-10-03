package stackd_test

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"stackd"
	"stackd/clock"
)

func rcpSecretClient(c cloudClients, account string) *secretsmanager.Client {
	return secretsmanager.New(secretsmanager.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

// These are primary-documentation replay cases, not new native AWS captures.
// Both services authorize retained owner resources, including calls by outsiders
// and the management account. Reopening SQLite reloads the organization graph,
// resource policies, encrypted secret bytes and S3 payload from real storage.
func TestResourceControlsOwnerMutationsRetained(t *testing.T) {
	var fixture struct {
		Mutations []struct {
			Mutation      string `json:"mutation"`
			ObjectAllowed bool   `json:"object_allowed"`
			SecretAllowed bool   `json:"secret_allowed"`
		} `json:"organization_mutations"`
	}
	awsReadFixture(t, "iam/resource_control_current.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const management, outsider = "000000000000", "333333333333"
			const objectKey, payload, secretValue = "payload", "retained owner object", "retained owner secret"
			source := clock.NewManual(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: management, Clock: source})
			f := organizationFixture(t, c, source)
			unit := f.unit(t, f.rootID, "rcp-owner")
			member := f.account(t, unit, "rcp-owner-member")
			orgID, _, _ := strings.Cut(f.rootPath, "/")
			principals := fmt.Sprintf(`["arn:aws:iam::%s:root","arn:aws:iam::%s:root","arn:aws:iam::%s:root"]`, member, management, outsider)
			type ownedResources struct{ bucket, secretARN string }
			resources := make(map[string]ownedResources)
			for _, owner := range []string{member, management} {
				bucket := "rcp-owner-" + owner
				objects := s3NativeClient(c, owner, "test")
				if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
					t.Fatal(err)
				}
				if _, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: aws.String(objectKey), Body: strings.NewReader(payload)}); err != nil {
					t.Fatal(err)
				}
				policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%s},"Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}}`, principals, bucket)
				if _, err := objects.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy}); err != nil {
					t.Fatal(err)
				}
				keyPolicy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%s},"Action":"kms:*","Resource":"*"}}`, principals)
				key, err := c.kms(owner, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{Policy: &keyPolicy})
				if err != nil {
					t.Fatal(err)
				}
				secrets := rcpSecretClient(c, owner)
				secret, err := secrets.CreateSecret(t.Context(), &secretsmanager.CreateSecretInput{Name: aws.String("rcp-owner"), KmsKeyId: key.KeyMetadata.Arn, SecretString: aws.String(secretValue)})
				if err != nil {
					t.Fatal(err)
				}
				secretPolicy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%s},"Action":"secretsmanager:GetSecretValue","Resource":%q}}`, principals, *secret.ARN)
				if _, err := secrets.PutResourcePolicy(t.Context(), &secretsmanager.PutResourcePolicyInput{SecretId: secret.ARN, ResourcePolicy: &secretPolicy}); err != nil {
					t.Fatal(err)
				}
				resources[owner] = ownedResources{bucket: bucket, secretARN: *secret.ARN}
			}
			both := fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":"*","Action":["s3:GetObject","secretsmanager:GetSecretValue"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceOrgID":%q}}}}`, orgID)
			secretOnly := fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":"*","Action":["s3:GetObject","secretsmanager:GetSecretValue"],"Resource":%q}}`, resources[member].secretARN)
			var policyID string
			check := func(t *testing.T, owner, caller string, objectAllowed, secretAllowed bool) {
				t.Helper()
				resource := resources[owner]
				object, err := s3NativeClient(c, caller, "test").GetObject(t.Context(), &s3.GetObjectInput{Bucket: &resource.bucket, Key: aws.String(objectKey)})
				if !objectAllowed {
					assertAPIError(t, err, "AccessDenied")
				} else {
					if err != nil {
						t.Fatalf("owner=%s caller=%s S3: %v", owner, caller, err)
					}
					data, err := io.ReadAll(object.Body)
					object.Body.Close()
					if err != nil || string(data) != payload {
						t.Fatalf("retained object = %q, %v", data, err)
					}
				}
				secret, err := rcpSecretClient(c, caller).GetSecretValue(t.Context(), &secretsmanager.GetSecretValueInput{SecretId: &resource.secretARN})
				if !secretAllowed {
					assertAPIError(t, err, "AccessDeniedException")
				} else if err != nil || aws.ToString(secret.SecretString) != secretValue {
					t.Fatalf("owner=%s caller=%s retained secret = %+v, %v", owner, caller, secret, err)
				}
			}
			for index, row := range fixture.Mutations {
				if !t.Run(fmt.Sprintf("%02d-%s", index, row.Mutation), func(t *testing.T) {
					var err error
					switch row.Mutation {
					case "baseline":
					case "attach_ou":
						f.enableRCP(t)
						policyID = f.rcp(t, "owner-deny", both, unit)
					case "reopen":
						c = reopen()
						f.cloud, f.org = c, c.organizations("test", "test")
					case "update_secret_only":
						_, err = f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policyID, Content: &secretOnly})
					case "update_both":
						_, err = f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policyID, Content: &both})
					case "move_to_root":
						_, err = f.org.MoveAccount(t.Context(), &organizations.MoveAccountInput{AccountId: &member, SourceParentId: &unit, DestinationParentId: &f.rootID})
					case "attach_root":
						_, err = f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: &policyID, TargetId: &f.rootID})
					case "detach_root":
						_, err = f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: &policyID, TargetId: &f.rootID})
					case "attach_account":
						_, err = f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: &policyID, TargetId: &member})
					case "disable":
						_, err = f.org.DisablePolicyType(t.Context(), &organizations.DisablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeResourceControlPolicy})
					default:
						t.Fatalf("unknown primary mutation %q", row.Mutation)
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, caller := range []string{member, management, outsider} {
						check(t, member, caller, row.ObjectAllowed, row.SecretAllowed)
					}
					// Root-level RCPs cannot restrict management-owned resources,
					// even for callers outside the organization.
					check(t, management, outsider, true, true)
				}) {
					return
				}
			}
		})
	}
}
