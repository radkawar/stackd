package kms

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

type testIdentity struct {
	principal authorization.Principal
	policies  []string
}

func (s *testIdentity) IdentityPolicies(ctx context.Context) (authorization.PolicySet, error) {
	m := awsctx.FromContext(ctx)
	if m.PrincipalARN != s.principal.ARN || m.PrincipalID != s.principal.ID {
		return authorization.PolicySet{}, authorization.ErrInvalidPrincipal
	}
	set := authorization.PolicySet{}
	for _, doc := range s.policies {
		set.Identity = append(set.Identity, iampolicy.Policy{Document: doc})
	}
	return set, nil
}

func (s *testIdentity) ResolvePrincipal(_ context.Context, reference string) (authorization.Principal, error) {
	if reference == s.principal.ARN || reference == s.principal.ID {
		return s.principal, nil
	}
	return authorization.Principal{}, authorization.ErrInvalidPrincipal
}

func (s *testIdentity) ResolveGrantPrincipal(ctx context.Context, reference string) (authorization.Principal, error) {
	return s.ResolvePrincipal(ctx, reference)
}

func TestSDKPolicyPrincipalBindingAndCrossAccount(t *testing.T) {
	ctx := context.Background()
	root := rootMetadata("111122223333", "us-east-1", "aws")
	identity := &testIdentity{principal: authorization.Principal{ARN: "arn:aws:iam::111122223333:user/alice", ID: "AIDA11111111111111111"}}
	s := NewWithAuthorization(authorization.New(identity, nil))
	c := sdkClient(t, s, root)
	k := createSDKKey(t, c)
	document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"AWS":%q},"Action":"kms:Encrypt","Resource":"*"}]}`, root.PrincipalARN, identity.principal.ARN)
	if _, err := c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: k.KeyId, Policy: aws.String(document)}); err != nil {
		t.Fatal(err)
	}
	user := root
	user.PrincipalARN, user.PrincipalID = identity.principal.ARN, identity.principal.ID
	u := sdkClient(t, s, user)
	if _, err := u.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("allowed directly")}); err != nil {
		t.Fatal(err)
	}
	oldID := identity.principal.ID
	s.mu.Lock()
	identity.principal.ID = "AIDA22222222222222222"
	s.mu.Unlock()
	user.PrincipalID = identity.principal.ID
	recreated := sdkClient(t, s, user)
	_, err := recreated.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("must not recover old grant")})
	requireCode(t, err, "AccessDeniedException")
	policy, err := c.GetKeyPolicy(ctx, &sdkkms.GetKeyPolicyInput{KeyId: k.KeyId})
	if err != nil || !strings.Contains(aws.ToString(policy.Policy), oldID) {
		t.Fatalf("stale principal rendering: %+v, %v", policy, err)
	}
	other := rootMetadata("444455556666", root.Region, root.Partition)
	cross := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"AWS":%q},"Action":["kms:Encrypt","kms:Decrypt","kms:DescribeKey"],"Resource":"*"}]}`, root.PrincipalARN, other.PrincipalARN)
	if _, err := c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: k.KeyId, Policy: aws.String(cross)}); err != nil {
		t.Fatal(err)
	}
	foreign := sdkClient(t, s, other)
	encrypted, err := foreign.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.Arn, Plaintext: []byte("cross-account")})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := foreign.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	if err != nil || string(decrypted.Plaintext) != "cross-account" {
		t.Fatalf("cross-account cryptography: %+v, %v", decrypted, err)
	}
	described, err := foreign.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: k.Arn})
	if err != nil || aws.ToString(described.KeyMetadata.AWSAccountId) != root.AccountID {
		t.Fatalf("owner metadata: %+v, %v", described, err)
	}
	_, err = foreign.DisableKey(ctx, &sdkkms.DisableKeyInput{KeyId: k.Arn})
	requireCode(t, err, "AccessDeniedException")
}
