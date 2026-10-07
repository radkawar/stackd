package integrations

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/kms"
)

func cfnKMSReplicaSDKClient(t *testing.T, owner *kms.Service, region string) *sdkkms.Client {
	t.Helper()
	metadata := awsctx.FromContext(cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, region, "aws"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// As in KMS's native SDK tests, transport supplies a verified principal;
		// all policy evaluation, state transitions and crypto stay in KMS.
		owner.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
	}))
	t.Cleanup(server.Close)
	return sdkkms.New(sdkkms.Options{Region: region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
}

func TestCFNKMSReplicaRealSDKConsumerTransport(t *testing.T) {
	source := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	owner := cfnKMSReplicaTestService(t, kms.NewMemoryStorage(nil), source)
	east, west := cfnKMSReplicaSDKClient(t, owner, "us-east-1"), cfnKMSReplicaSDKClient(t, owner, "us-west-2")
	created, err := east.CreateKey(t.Context(), &sdkkms.CreateKeyInput{MultiRegion: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := cfnKMSReplicaTestContext(t.Context(), cfnKMSReplicaTestAccount, "us-west-2", "aws")
	r := cfnKMSReplicaTestRequest(aws.ToString(created.KeyMetadata.Arn))
	h := cfnKMSReplicaKey{cfnKMSReplicaTestCommands(owner)}
	result, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = result.PhysicalID
	if ready, err := h.Stabilize(ctx, r); err != nil || !ready {
		t.Fatalf("CFN replica readiness = %v %v", ready, err)
	}
	described, err := west.DescribeKey(t.Context(), &sdkkms.DescribeKeyInput{KeyId: aws.String(result.PhysicalID)})
	if err != nil || described.KeyMetadata.MultiRegionConfiguration.MultiRegionKeyType != types.MultiRegionKeyTypeReplica || aws.ToString(described.KeyMetadata.KeyId) != aws.ToString(created.KeyMetadata.KeyId) || aws.ToString(described.KeyMetadata.CurrentKeyMaterialId) != aws.ToString(created.KeyMetadata.CurrentKeyMaterialId) {
		t.Fatalf("SDK did not observe the real CFN replica and shared material: %+v %v", described, err)
	}
	plain := []byte("SDK reads the material created by the CFN replication owner")
	cipher, err := east.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: created.KeyMetadata.KeyId, Plaintext: plain})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := west.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: cipher.CiphertextBlob})
	if err != nil || !bytes.Equal(decrypted.Plaintext, plain) || aws.ToString(decrypted.KeyId) != result.Attributes["Arn"] {
		t.Fatalf("SDK cross-Region plaintext/material/routing mismatch: %+v %v", decrypted, err)
	}
	if _, err := west.UpdateKeyDescription(t.Context(), &sdkkms.UpdateKeyDescriptionInput{KeyId: described.KeyMetadata.KeyId, Description: aws.String("SDK native mutation")}); err != nil {
		t.Fatal(err)
	}
	read, err := h.Read(ctx, cloudformation.ResourceRequest{CloudControl: true, PhysicalID: result.PhysicalID})
	if err != nil || read["Description"] != "SDK native mutation" {
		t.Fatalf("Cloud Control read did not observe the SDK's real mutation: %+v %v", read, err)
	}
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	deleted, err := west.DescribeKey(t.Context(), &sdkkms.DescribeKeyInput{KeyId: described.KeyMetadata.KeyId})
	if err != nil || deleted.KeyMetadata.KeyState != types.KeyStatePendingDeletion || deleted.KeyMetadata.DeletionDate == nil {
		t.Fatalf("SDK did not observe real CFN scheduled deletion: %+v %v", deleted, err)
	}
}
