package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"stackd"
)

func (c cloudClients) ram(region, key, secret string) *ram.Client {
	return ram.New(ram.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestRAMParameterAccessContractRetained(t *testing.T) {
	var fixture struct {
		Principals  []string `json:"principals"`
		Transitions []struct {
			Name         string   `json:"name"`
			Value        string   `json:"value"`
			GetError     string   `json:"get_error"`
			HistoryError string   `json:"history_error"`
			History      []string `json:"history"`
		} `json:"transitions"`
	}
	raw, err := os.ReadFile("../testdata/aws/ram/parameter_access_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, principalKind := range fixture.Principals {
			t.Run(backend+"/"+principalKind, func(t *testing.T) {
				const owner, consumer = "111122223333", "444455556666"
				ctx := t.Context()
				cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner})
				userARN, key, secret := cl.user(t, consumer, "ram-reader")
				name := "/ram/config"
				arn := "arn:aws:ssm:us-east-1:" + owner + ":parameter/ram/config"
				putUserPolicy(t, cl.iam(consumer, "test", ""), "ram-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameterHistory"],"Resource":%q},{"Effect":"Allow","Action":"ssm:DescribeParameters","Resource":"*"}]}`, arn))
				root := cl.ssm("us-east-1", owner, "test")
				for _, value := range []string{"public-version-one", "public-version-two"} {
					_, err := root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new(value), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierAdvanced, Overwrite: new(true)})
					if err != nil {
						t.Fatal(err)
					}
				}
				principal := consumer
				if principalKind == "iam-user" {
					principal = userARN
				}
				manager := cl.ram("us-east-1", owner, "test")
				shared, err := manager.CreateResourceShare(ctx, &ram.CreateResourceShareInput{Name: new("parameters"), ResourceArns: []string{arn}, Principals: []string{principal}, AllowExternalPrincipals: new(true)})
				if err != nil {
					t.Fatal(err)
				}
				shareARN := aws.ToString(shared.ResourceShare.ResourceShareArn)
				for _, transition := range fixture.Transitions {
					t.Run(transition.Name, func(t *testing.T) {
						switch transition.Name {
						case "accept":
							recipient := cl.ram("us-east-1", consumer, "test")
							invitations, err := recipient.GetResourceShareInvitations(ctx, &ram.GetResourceShareInvitationsInput{ResourceShareArns: []string{shareARN}})
							if err != nil || len(invitations.ResourceShareInvitations) != 1 {
								t.Fatalf("invitations: %+v %v", invitations, err)
							}
							_, err = recipient.AcceptResourceShareInvitation(ctx, &ram.AcceptResourceShareInvitationInput{ResourceShareInvitationArn: invitations.ResourceShareInvitations[0].ResourceShareInvitationArn})
							if err != nil {
								t.Fatal(err)
							}
						case "reopen":
							cl = reopen()
							manager = cl.ram("us-east-1", owner, "test")
						case "history-permission":
							_, err := manager.AssociateResourceSharePermission(ctx, &ram.AssociateResourceSharePermissionInput{ResourceShareArn: new(shareARN), PermissionArn: new("arn:aws:ram::aws:permission/AWSRAMPermissionSSMParameterReadOnlyWithHistory"), Replace: new(true)})
							if err != nil {
								t.Fatal(err)
							}
						case "resource-removed":
							_, err := manager.DisassociateResourceShare(ctx, &ram.DisassociateResourceShareInput{ResourceShareArn: new(shareARN), ResourceArns: []string{arn}})
							if err != nil {
								t.Fatal(err)
							}
						case "resource-associated":
							_, err := manager.AssociateResourceShare(ctx, &ram.AssociateResourceShareInput{ResourceShareArn: new(shareARN), ResourceArns: []string{arn}})
							if err != nil {
								t.Fatal(err)
							}
						case "principal-removed":
							_, err := manager.DisassociateResourceShare(ctx, &ram.DisassociateResourceShareInput{ResourceShareArn: new(shareARN), Principals: []string{principal}})
							if err != nil {
								t.Fatal(err)
							}
						}
						reader := cl.ssm("us-east-1", key, secret)
						out, err := reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
						if transition.GetError != "" {
							assertAPIError(t, err, transition.GetError)
						} else if err != nil || aws.ToString(out.Parameter.Value) != transition.Value {
							t.Fatalf("actual shared value: %+v %v", out, err)
						}
						history, err := reader.GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{Name: new(arn)})
						if transition.HistoryError != "" {
							assertAPIError(t, err, transition.HistoryError)
						} else {
							if err != nil {
								t.Fatal(err)
							}
							values := make([]string, len(history.Parameters))
							for i, parameter := range history.Parameters {
								values[i] = aws.ToString(parameter.Value)
							}
							if !slices.Equal(values, transition.History) {
								t.Fatalf("history bytes: %v want %v", values, transition.History)
							}
						}
						metadata, err := reader.DescribeParameters(ctx, &ssm.DescribeParametersInput{Shared: new(true)})
						if err != nil {
							t.Fatal(err)
						}
						var listed []string
						for _, parameter := range metadata.Parameters {
							listed = append(listed, aws.ToString(parameter.ARN))
						}
						if slices.Contains(listed, arn) != (transition.GetError == "") {
							t.Fatalf("shared discovery: %v", listed)
						}
					})
				}
				_, err = manager.DeleteResourceShare(ctx, &ram.DeleteResourceShareInput{ResourceShareArn: new(shareARN)})
				if err != nil {
					t.Fatal(err)
				}
				shares, err := cl.ram("us-east-1", consumer, "test").GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwner("OTHER-ACCOUNTS")})
				if err != nil || len(shares.ResourceShares) != 0 {
					t.Fatalf("deleted share visible: %+v %v", shares, err)
				}
			})
		}
	}
}

func TestRAMParameterConditionsUseCurrentOwnerTags(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const owner, consumer = "111122223333", "444455556666"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner})
			_, key, secret := cl.user(t, consumer, "condition-reader")
			name, arn := "/ram/condition", "arn:aws:ssm:us-east-1:"+owner+":parameter/ram/condition"
			putUserPolicy(t, cl.iam(consumer, "test", ""), "condition-reader", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"ssm:GetParameter","Resource":%q}}`, arn))
			root := cl.ssm("us-east-1", owner, "test")
			_, err := root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new("tag-scoped-value"), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierAdvanced, Tags: []ssmtypes.Tag{{Key: new("environment"), Value: new("staging")}}})
			if err != nil {
				t.Fatal(err)
			}
			manager := cl.ram("us-east-1", owner, "test")
			permission, err := manager.CreatePermission(ctx, &ram.CreatePermissionInput{Name: new("tagged-parameter"), ResourceType: new("ssm:Parameter"), PolicyTemplate: new(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter"],"Condition":{"StringEquals":{"aws:ResourceTag/environment":"production"}}}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			share, err := manager.CreateResourceShare(ctx, &ram.CreateResourceShareInput{Name: new("conditional"), ResourceArns: []string{arn}, Principals: []string{consumer}, PermissionArns: []string{aws.ToString(permission.Permission.Arn)}, AllowExternalPrincipals: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			recipient := cl.ram("us-east-1", consumer, "test")
			invitations, err := recipient.GetResourceShareInvitations(ctx, &ram.GetResourceShareInvitationsInput{ResourceShareArns: []string{aws.ToString(share.ResourceShare.ResourceShareArn)}})
			if err != nil || len(invitations.ResourceShareInvitations) != 1 {
				t.Fatalf("invitation: %+v %v", invitations, err)
			}
			_, err = recipient.AcceptResourceShareInvitation(ctx, &ram.AcceptResourceShareInvitationInput{ResourceShareInvitationArn: invitations.ResourceShareInvitations[0].ResourceShareInvitationArn})
			if err != nil {
				t.Fatal(err)
			}
			cl = reopen()
			reader := cl.ssm("us-east-1", key, secret)
			_, err = reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = cl.ssm("us-east-1", owner, "test").AddTagsToResource(ctx, &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTagging("Parameter"), ResourceId: new(name), Tags: []ssmtypes.Tag{{Key: new("environment"), Value: new("production")}}})
			if err != nil {
				t.Fatal(err)
			}
			out, err := reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			if err != nil || aws.ToString(out.Parameter.Value) != "tag-scoped-value" {
				t.Fatalf("owner condition grant: %+v %v", out, err)
			}
			putUserPolicy(t, cl.iam(consumer, "test", ""), "condition-reader", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"ssm:GetParameter","Resource":%q},{"Effect":"Deny","Action":"ssm:GetParameter","Resource":%q}]}`, arn, arn))
			_, err = reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
		})
	}
}

func TestRAMPolicyPromotionAndOwnerDeletionRetained(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const owner, consumer = "111122223333", "444455556666"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner})
			cl.user(t, consumer, "registered-recipient")
			name, arn := "/ram/promoted", "arn:aws:ssm:us-east-1:"+owner+":parameter/ram/promoted"
			root := cl.ssm("us-east-1", owner, "test")
			_, err := root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new("original-promoted-value"), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierAdvanced, Tags: []ssmtypes.Tag{{Key: new("environment"), Value: new("production")}}})
			if err != nil {
				t.Fatal(err)
			}
			document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":["ssm:GetParameter","ssm:DescribeParameters"],"Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/environment":"production"}}}]}`, consumer, arn)
			_, err = root.PutResourcePolicy(ctx, &ssm.PutResourcePolicyInput{ResourceArn: new(arn), Policy: new(document)})
			if err != nil {
				t.Fatal(err)
			}
			remote := cl.ssm("us-east-1", consumer, "test")
			out, err := remote.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			if err != nil || aws.ToString(out.Parameter.Value) != "original-promoted-value" {
				t.Fatalf("direct policy access: %+v %v", out, err)
			}
			discovery, err := remote.DescribeParameters(ctx, &ssm.DescribeParametersInput{Shared: new(true)})
			if err != nil || len(discovery.Parameters) != 0 {
				t.Fatalf("unpromoted discovery: %+v %v", discovery, err)
			}
			manager := cl.ram("us-east-1", owner, "test")
			shares, err := manager.GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwner("SELF")})
			if err != nil || len(shares.ResourceShares) != 1 {
				t.Fatalf("policy-created share: %+v %v", shares, err)
			}
			shareARN := aws.ToString(shares.ResourceShares[0].ResourceShareArn)
			permissions, err := manager.ListResourceSharePermissions(ctx, &ram.ListResourceSharePermissionsInput{ResourceShareArn: new(shareARN)})
			if err != nil || len(permissions.Permissions) != 1 {
				t.Fatalf("policy-created permission: %+v %v", permissions, err)
			}
			_, err = manager.PromotePermissionCreatedFromPolicy(ctx, &ram.PromotePermissionCreatedFromPolicyInput{PermissionArn: permissions.Permissions[0].Arn, Name: new("promoted-parameter")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.PromoteResourceShareCreatedFromPolicy(ctx, &ram.PromoteResourceShareCreatedFromPolicyInput{ResourceShareArn: new(shareARN)})
			if err != nil {
				t.Fatal(err)
			}
			cl = reopen()
			root = cl.ssm("us-east-1", owner, "test")
			remote = cl.ssm("us-east-1", consumer, "test")
			discovery, err = remote.DescribeParameters(ctx, &ssm.DescribeParametersInput{Shared: new(true)})
			if err != nil || len(discovery.Parameters) != 1 || aws.ToString(discovery.Parameters[0].ARN) != arn {
				t.Fatalf("promoted discovery: %+v %v", discovery, err)
			}
			out, err = remote.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			if err != nil || aws.ToString(out.Parameter.Value) != "original-promoted-value" {
				t.Fatalf("promoted value: %+v %v", out, err)
			}
			_, err = root.AddTagsToResource(ctx, &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTagging("Parameter"), ResourceId: new(name), Tags: []ssmtypes.Tag{{Key: new("environment"), Value: new("staging")}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = remote.GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			discovery, err = remote.DescribeParameters(ctx, &ssm.DescribeParametersInput{Shared: new(true)})
			if err != nil || len(discovery.Parameters) != 0 {
				t.Fatalf("promoted condition-filtered discovery: %+v %v", discovery, err)
			}
			_, err = root.AddTagsToResource(ctx, &ssm.AddTagsToResourceInput{ResourceType: ssmtypes.ResourceTypeForTagging("Parameter"), ResourceId: new(name), Tags: []ssmtypes.Tag{{Key: new("environment"), Value: new("production")}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.DeleteParameter(ctx, &ssm.DeleteParameterInput{Name: new(name)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new("replacement-private-value"), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierAdvanced, Tags: []ssmtypes.Tag{{Key: new("environment"), Value: new("production")}}})
			if err != nil {
				t.Fatal(err)
			}
			cl = reopen()
			_, err = cl.ssm("us-east-1", consumer, "test").GetParameter(ctx, &ssm.GetParameterInput{Name: new(arn)})
			assertAPIError(t, err, "AccessDeniedException")
			ownerRead, err := cl.ssm("us-east-1", owner, "test").GetParameter(ctx, &ssm.GetParameterInput{Name: new(name)})
			if err != nil || aws.ToString(ownerRead.Parameter.Value) != "replacement-private-value" {
				t.Fatalf("recreated owner value: %+v %v", ownerRead, err)
			}
		})
	}
}

func TestRAMParameterSharingChecksCanonicalKeyOwnership(t *testing.T) {
	const owner, consumer = "111122223333", "444455556666"
	c, _ := retainedCloud(t, "memory", stackd.Config{AccountID: owner})
	root := c.ssm("us-east-1", owner, "test")
	ctx := t.Context()
	_, err := root.PutParameter(ctx, &ssm.PutParameterInput{Name: new("/ram/default-key"), Value: new("private"), Type: ssmtypes.ParameterTypeSecureString, Tier: ssmtypes.ParameterTierAdvanced})
	if err != nil {
		t.Fatal(err)
	}
	managed, err := c.kms(owner, "test", "").DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: new("alias/aws/ssm")})
	if err != nil {
		t.Fatal(err)
	}
	name, arn := "/ram/managed-arn", "arn:aws:ssm:us-east-1:"+owner+":parameter/ram/managed-arn"
	_, err = root.PutParameter(ctx, &ssm.PutParameterInput{Name: new(name), Value: new("encrypted"), Type: ssmtypes.ParameterTypeSecureString, Tier: ssmtypes.ParameterTierAdvanced, KeyId: managed.KeyMetadata.Arn})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ram("us-east-1", owner, "test").CreateResourceShare(ctx, &ram.CreateResourceShareInput{Name: new("managed-arn"), ResourceArns: []string{arn}, Principals: []string{consumer}, AllowExternalPrincipals: new(true)})
	assertAPIError(t, err, "InvalidResourceTypeException")
}
