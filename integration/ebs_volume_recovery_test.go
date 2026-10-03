package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	ebsdomain "stackd/internal/services/ebs"
	"stackd/storage"
)

// Pause after the first destination block commits, not while a transaction owns
// SQLite's connection. Closing the service interrupts the pause like a controller
// crash, leaving real partial encrypted contents for the next owner to recover.
type pausedVolumeRepository struct {
	ebsdomain.Repository
	armed     atomic.Bool
	committed chan struct{}
}

type observedVolumeWriter struct {
	ebsdomain.Transaction
	wrote *bool
}

func (w observedVolumeWriter) PutVolumeBlock(block ebsdomain.VolumeBlockRecord) error {
	if err := w.Transaction.PutVolumeBlock(block); err != nil {
		return err
	}
	*w.wrote = true
	return nil
}

func (r *pausedVolumeRepository) Update(ctx context.Context, fn func(ebsdomain.Transaction) error) error {
	wrote := false
	err := r.Repository.Update(ctx, func(tx ebsdomain.Transaction) error {
		return fn(observedVolumeWriter{Transaction: tx, wrote: &wrote})
	})
	if err == nil && wrote && r.armed.CompareAndSwap(true, false) {
		close(r.committed)
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func TestEBSVolumeHydrationRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			manual := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var cloud *stackd.Stack
			var stores *storage.Backends
			var paused *pausedVolumeRepository
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "111111111111", Clock: manual}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				stores = config.Storage
				if paused == nil {
					paused = &pausedVolumeRepository{Repository: stores.EBS, committed: make(chan struct{})}
					stores.EBS = paused
				}
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			provider := func(account string) aws.CredentialsProvider {
				return credentials.NewStaticCredentialsProvider(account, "test", "")
			}
			ec2Client := func(account string) *ec2.Client {
				return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider(account), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			ebsClient := func(account string) *ebs.Client {
				return ebs.New(ebs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider(account), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			kmsClient := func(account string) *kms.Client {
				return kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider(account), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			const owner, member = "111111111111", "222222222222"
			policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::222222222222:root"]},"Action":"kms:*","Resource":"*"}]}`
			sourceKey, err := kmsClient(owner).CreateKey(ctx, &kms.CreateKeyInput{Policy: &policy})
			if err != nil {
				t.Fatal(err)
			}
			targetKey, err := kmsClient(member).CreateKey(ctx, &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			source, err := ebsClient(owner).StartSnapshot(ctx, &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), Encrypted: aws.Bool(true), KmsKeyArn: sourceKey.KeyMetadata.Arn})
			if err != nil {
				t.Fatal(err)
			}
			payloads := map[int32][]byte{1: bytes.Repeat([]byte("a"), ebsdomain.BlockSize), 9: bytes.Repeat([]byte("z"), ebsdomain.BlockSize)}
			for index, payload := range payloads {
				digest := sha256.Sum256(payload)
				_, err = ebsClient(owner).PutSnapshotBlock(ctx, &ebs.PutSnapshotBlockInput{SnapshotId: source.SnapshotId, BlockIndex: aws.Int32(index), BlockData: bytes.NewReader(payload), DataLength: aws.Int32(int32(len(payload))), Checksum: aws.String(base64.StdEncoding.EncodeToString(digest[:])), ChecksumAlgorithm: "SHA256"})
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = ebsClient(owner).CompleteSnapshot(ctx, &ebs.CompleteSnapshotInput{SnapshotId: source.SnapshotId, ChangedBlocksCount: aws.Int32(2)}); err != nil {
				t.Fatal(err)
			}
			manual.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
			trailNativeDrain(t, cloud)
			if _, err = ec2Client(owner).ModifySnapshotAttribute(ctx, &ec2.ModifySnapshotAttributeInput{SnapshotId: source.SnapshotId, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission, CreateVolumePermission: &ec2types.CreateVolumePermissionModifications{Add: []ec2types.CreateVolumePermission{{UserId: aws.String(member)}}}}); err != nil {
				t.Fatal(err)
			}
			manual.Advance(ebsdomain.SharingDelay)
			trailNativeDrain(t, cloud)
			zones, err := ec2Client(member).DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{})
			if err != nil {
				t.Fatal(err)
			}
			volume, err := ec2Client(member).CreateVolume(ctx, &ec2.CreateVolumeInput{SnapshotId: source.SnapshotId, AvailabilityZone: zones.AvailabilityZones[0].ZoneName, Encrypted: aws.Bool(true), KmsKeyId: targetKey.KeyMetadata.Arn})
			if err != nil {
				t.Fatal(err)
			}
			key := ebsdomain.VolumeKey{Scope: ebsdomain.Scope{Partition: "aws", AccountID: member, Region: "us-east-1"}, ID: aws.ToString(volume.VolumeId)}
			if err := stores.EBS.View(ctx, func(r ebsdomain.Reader) error {
				blocks, err := r.VolumeBlocks(key)
				if len(blocks) != 0 {
					t.Fatalf("admission copied %d payload blocks", len(blocks))
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			paused.armed.Store(true)
			manual.Advance(ebsdomain.VolumeCreationDelay)
			select {
			case <-paused.committed:
			case <-time.After(10 * time.Second):
				t.Fatal("volume worker did not commit its first block")
			}
			responsive, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			state, err := ec2Client(member).DescribeVolumes(responsive, &ec2.DescribeVolumesInput{VolumeIds: []string{key.ID}})
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Volumes) != 1 || state.Volumes[0].State != ec2types.VolumeStateCreating {
				t.Fatalf("partial volume became available: %+v", state.Volumes)
			}
			manual.Advance(ebsdomain.VolumeInitializationDelay)
			status, err := ec2Client(member).DescribeVolumeStatus(responsive, &ec2.DescribeVolumeStatusInput{VolumeIds: []string{key.ID}})
			if err != nil {
				t.Fatal(err)
			}
			if len(status.VolumeStatuses) != 1 || status.VolumeStatuses[0].InitializationStatusDetails == nil || aws.ToInt64(status.VolumeStatuses[0].InitializationStatusDetails.Progress) != 0 {
				t.Fatalf("partial volume initialization was published complete: %+v", status.VolumeStatuses)
			}
			queue, err := clients.sqs("test", "test", "").CreateQueue(responsive, &sqs.CreateQueueInput{QueueName: aws.String("during-hydration")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := clients.sqs("test", "test", "").SendMessage(responsive, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("independent request")}); err != nil {
				t.Fatal(err)
			}
			if _, err := ec2Client(owner).ResetSnapshotAttribute(responsive, &ec2.ResetSnapshotAttributeInput{SnapshotId: source.SnapshotId, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission}); err != nil {
				t.Fatal(err)
			}
			if _, err := ec2Client(owner).DeleteSnapshot(responsive, &ec2.DeleteSnapshotInput{SnapshotId: source.SnapshotId}); err != nil {
				t.Fatal(err)
			}
			if _, err := kmsClient(owner).DisableKey(responsive, &kms.DisableKeyInput{KeyId: sourceKey.KeyMetadata.Arn}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			trailNativeDrain(t, cloud)
			state, err = ec2Client(member).DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{key.ID}})
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Volumes) != 1 || state.Volumes[0].State != ec2types.VolumeStateAvailable {
				t.Fatalf("recovered volume is not available: %+v", state.Volumes)
			}
			captured, err := ec2Client(member).CreateSnapshot(ctx, &ec2.CreateSnapshotInput{VolumeId: volume.VolumeId})
			if err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			manual.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
			trailNativeDrain(t, cloud)
			listed, err := ebsClient(member).ListSnapshotBlocks(ctx, &ebs.ListSnapshotBlocksInput{SnapshotId: captured.SnapshotId})
			if err != nil {
				t.Fatal(err)
			}
			if len(listed.Blocks) != len(payloads) {
				t.Fatalf("recovered sparse block set: %+v", listed.Blocks)
			}
			for _, block := range listed.Blocks {
				out, err := ebsClient(member).GetSnapshotBlock(ctx, &ebs.GetSnapshotBlockInput{SnapshotId: captured.SnapshotId, BlockIndex: block.BlockIndex, BlockToken: block.BlockToken})
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(out.BlockData)
				out.BlockData.Close()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data, payloads[aws.ToInt32(block.BlockIndex)]) {
					t.Fatalf("recovered block %d differs", aws.ToInt32(block.BlockIndex))
				}
			}
		})
	}
}
