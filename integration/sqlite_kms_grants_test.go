package stackd_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/storage"
)

func TestSQLiteKMSRetainsGrantConstraintsAndRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	backends := storage.NewMemory() // IAM identity is retained separately.
	c, close := openSQLiteCloud(t, path, backends, nil)
	identity, owner := c.iam("test", "test", ""), c.kms("test", "test", "")
	user, err := identity.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("grantee")})
	if err != nil {
		t.Fatal(err)
	}
	access, err := identity.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: user.User.UserName})
	if err != nil {
		t.Fatal(err)
	}
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{Tags: []types.Tag{{TagKey: aws.String("team"), TagValue: aws.String("storage")}}})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: user.User.Arn, Operations: []types.GrantOperation{types.GrantOperationDecrypt}, Constraints: &types.GrantConstraints{EncryptionContextEquals: map[string]string{"purpose": "retained"}}})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("grant-protected plaintext")
	encrypted, err := owner.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyMetadata.KeyId, Plaintext: plain, EncryptionContext: map[string]string{"purpose": "retained"}})
	if err != nil {
		t.Fatal(err)
	}
	close()
	c, _ = openSQLiteCloud(t, path, backends, nil)
	owner = c.kms("test", "test", "")
	grantee := c.kms(aws.ToString(access.AccessKey.AccessKeyId), aws.ToString(access.AccessKey.SecretAccessKey), "")
	input := &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: map[string]string{"purpose": "retained"}, GrantTokens: []string{aws.ToString(grant.GrantToken)}}
	out, err := grantee.Decrypt(t.Context(), input)
	if err != nil || !bytes.Equal(out.Plaintext, plain) {
		t.Fatal("grant or key material was not restored", err)
	}
	input.EncryptionContext = map[string]string{"purpose": "wrong"}
	_, err = grantee.Decrypt(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := owner.RevokeGrant(t.Context(), &kms.RevokeGrantInput{KeyId: key.KeyMetadata.KeyId, GrantId: grant.GrantId}); err != nil {
		t.Fatal(err)
	}
	input.EncryptionContext = map[string]string{"purpose": "retained"}
	_, err = grantee.Decrypt(t.Context(), input)
	assertAPIError(t, err, "InvalidGrantTokenException")
	input.GrantTokens = nil
	_, err = grantee.Decrypt(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	tags, err := owner.ListResourceTags(t.Context(), &kms.ListResourceTagsInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].TagValue) != "storage" {
		t.Fatal("regional tags were not restored", tags, err)
	}
}
