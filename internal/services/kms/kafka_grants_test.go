package kms

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestKafkaGrantCurrentAuthorityAndContext(t *testing.T) {
	ctx := context.Background()
	root := rootMetadata("111122223333", "us-east-1", "aws")
	s := NewWithAuthorization(authorization.New(&testIdentity{}, nil))
	owner := sdkClient(t, s, root)
	key := createSDKKey(t, owner)
	metadata := awsctx.Metadata{AccountID: root.AccountID, Region: root.Region, Partition: root.Partition, ServicePrincipal: awsctx.ServicePrincipal{Name: "kafka.amazonaws.com", Type: "AWSService"}}
	consumer := sdkClient(t, s, metadata)
	contextA := map[string]string{"SecretARN": "secret-a", "SecretVersionId": "version-a"}
	sealed, err := owner.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: []byte{0, 255, 1}, EncryptionContext: contextA})
	if err != nil {
		t.Fatal(err)
	}
	request := &sdkkms.DecryptInput{CiphertextBlob: sealed.CiphertextBlob, EncryptionContext: contextA}
	_, err = consumer.Decrypt(ctx, request)
	requireCode(t, err, "AccessDeniedException")
	grant, err := owner.CreateGrant(ctx, &sdkkms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: aws.String("kafka.amazonaws.com"), RetiringPrincipal: aws.String("kafka.amazonaws.com"), Operations: []types.GrantOperation{types.GrantOperationDecrypt}, Constraints: &types.GrantConstraints{EncryptionContextSubset: map[string]string{"SecretARN": "secret-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := consumer.Decrypt(ctx, request)
	if err != nil || string(opened.Plaintext) != string([]byte{0, 255, 1}) {
		t.Fatalf("service grant decrypt: %+v, %v", opened, err)
	}
	other, err := owner.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: []byte("other"), EncryptionContext: map[string]string{"SecretARN": "secret-b"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = consumer.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: other.CiphertextBlob, EncryptionContext: map[string]string{"SecretARN": "secret-b"}})
	requireCode(t, err, "AccessDeniedException")
	metadata.ServicePrincipal.Name = "secretsmanager.amazonaws.com"
	_, err = sdkClient(t, s, metadata).Decrypt(ctx, request)
	requireCode(t, err, "AccessDeniedException")
	if _, err := owner.RevokeGrant(ctx, &sdkkms.RevokeGrantInput{KeyId: key.KeyId, GrantId: grant.GrantId}); err != nil {
		t.Fatal(err)
	}
	_, err = consumer.Decrypt(ctx, request)
	requireCode(t, err, "AccessDeniedException")
}
