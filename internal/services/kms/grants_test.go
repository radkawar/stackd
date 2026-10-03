package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/internal/authorization"
)

func TestSDKGrantConstraintsTokensRevocationAndRetirement(t *testing.T) {
	ctx := context.Background()
	root := rootMetadata("111122223333", "us-east-1", "aws")
	identity := &testIdentity{principal: authorization.Principal{ARN: "arn:aws:iam::111122223333:user/grantee", ID: "AIDA11111111111111111"}}
	s := NewWithAuthorization(authorization.New(identity, nil))
	c := sdkClient(t, s, root)
	k := createSDKKey(t, c)
	user := root
	user.PrincipalARN, user.PrincipalID = identity.principal.ARN, identity.principal.ID
	u := sdkClient(t, s, user)
	encryptionContext := map[string]string{"Department": "IT", "Team": "Infrastructure"}
	encrypted, err := c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("protected"), EncryptionContext: encryptionContext})
	if err != nil {
		t.Fatal(err)
	}
	input := &sdkkms.CreateGrantInput{KeyId: k.KeyId, GranteePrincipal: aws.String(user.PrincipalARN), RetiringPrincipal: aws.String(user.PrincipalARN), Operations: []types.GrantOperation{types.GrantOperationDecrypt, types.GrantOperationDescribeKey, types.GrantOperationRetireGrant}, Name: aws.String("application-read"), Constraints: &types.GrantConstraints{EncryptionContextSubset: map[string]string{"Department": "IT"}}}
	created, err := c.CreateGrant(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := c.CreateGrant(ctx, input)
	if err != nil || aws.ToString(created.GrantId) != aws.ToString(retried.GrantId) || aws.ToString(created.GrantToken) == aws.ToString(retried.GrantToken) {
		t.Fatalf("grant idempotency/token freshness: %+v, %v", retried, err)
	}
	for _, token := range []*string{nil, created.GrantToken, retried.GrantToken} {
		request := &sdkkms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: encryptionContext}
		if token != nil {
			request.GrantTokens = []string{*token}
		}
		out, err := u.Decrypt(ctx, request)
		if err != nil || string(out.Plaintext) != "protected" {
			t.Fatalf("grant decrypt: %+v, %v", out, err)
		}
	}
	if _, err := u.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: k.KeyId, GrantTokens: []string{*created.GrantToken}}); err != nil {
		t.Fatal(err)
	}
	_, err = u.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: map[string]string{"Department": "Finance"}})
	requireCode(t, err, "AccessDeniedException")
	_, err = u.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: encryptionContext, GrantTokens: []string{"invented-token"}})
	requireCode(t, err, "InvalidGrantTokenException")
	listed, err := c.ListGrants(ctx, &sdkkms.ListGrantsInput{KeyId: k.KeyId, GranteePrincipal: aws.String(user.PrincipalARN)})
	if err != nil || len(listed.Grants) != 1 || aws.ToString(listed.Grants[0].GrantId) != *created.GrantId || listed.Grants[0].CreationDate == nil || listed.Grants[0].Constraints.EncryptionContextSubset["Department"] != "IT" {
		t.Fatalf("grant listing: %+v, %v", listed, err)
	}
	retirable, err := c.ListRetirableGrants(ctx, &sdkkms.ListRetirableGrantsInput{RetiringPrincipal: aws.String(user.PrincipalARN)})
	if err != nil || len(retirable.Grants) != 1 {
		t.Fatalf("retirable: %+v, %v", retirable, err)
	}
	denied := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}`, root.PrincipalARN)
	if _, err := c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: k.KeyId, Policy: aws.String(denied)}); err != nil {
		t.Fatal(err)
	}
	_, err = u.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: encryptionContext})
	requireCode(t, err, "AccessDeniedException")
	if _, err := c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: k.KeyId, Policy: aws.String(defaultPolicyForTest(root.Partition, root.AccountID))}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RevokeGrant(ctx, &sdkkms.RevokeGrantInput{KeyId: k.KeyId, GrantId: created.GrantId}); err != nil {
		t.Fatal(err)
	}
	_, err = u.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: encryptionContext})
	requireCode(t, err, "AccessDeniedException")
	created, err = c.CreateGrant(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.RetireGrant(ctx, &sdkkms.RetireGrantInput{GrantToken: created.GrantToken}); err != nil {
		t.Fatal(err)
	}
	listed, err = c.ListGrants(ctx, &sdkkms.ListGrantsInput{KeyId: k.KeyId})
	if err != nil || len(listed.Grants) != 0 {
		t.Fatalf("retired grant remained: %+v, %v", listed, err)
	}
}

func defaultPolicyForTest(partition, account string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:%s:iam::%s:root"},"Action":"kms:*","Resource":"*"}]}`, partition, account)
}

func TestSDKDelegatedGrantCannotBroadenConstraints(t *testing.T) {
	ctx := context.Background()
	root := rootMetadata("111122223333", "us-east-1", "aws")
	identity := &testIdentity{principal: authorization.Principal{ARN: "arn:aws:iam::111122223333:user/delegated", ID: "AIDA11111111111111111"}}
	s := NewWithAuthorization(authorization.New(identity, nil))
	c := sdkClient(t, s, root)
	k := createSDKKey(t, c)
	user := root
	user.PrincipalARN, user.PrincipalID = identity.principal.ARN, identity.principal.ID
	u := sdkClient(t, s, user)
	parent, err := c.CreateGrant(ctx, &sdkkms.CreateGrantInput{KeyId: k.KeyId, GranteePrincipal: aws.String(user.PrincipalARN), Operations: []types.GrantOperation{types.GrantOperationCreateGrant, types.GrantOperationDecrypt}, Constraints: &types.GrantConstraints{EncryptionContextSubset: map[string]string{"Department": "IT"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.CreateGrant(ctx, &sdkkms.CreateGrantInput{KeyId: k.KeyId, GranteePrincipal: aws.String(user.PrincipalARN), Operations: []types.GrantOperation{types.GrantOperationDecrypt}, GrantTokens: []string{*parent.GrantToken}})
	requireCode(t, err, "AccessDeniedException")
	_, err = u.CreateGrant(ctx, &sdkkms.CreateGrantInput{KeyId: k.KeyId, GranteePrincipal: aws.String(user.PrincipalARN), Operations: []types.GrantOperation{types.GrantOperationDecrypt}, Constraints: &types.GrantConstraints{EncryptionContextEquals: map[string]string{"Department": "IT", "Project": "restricted"}}, GrantTokens: []string{*parent.GrantToken}})
	if err != nil {
		t.Fatal(err)
	}
}
