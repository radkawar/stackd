package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http/httptest"
	"os"
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
	native "stackd/compute/ec2"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	ebsdomain "stackd/internal/services/ebs"
	"stackd/storage"
)

// Observe the actual admission transaction, then interrupt the worker after a
// committed block, outside the transaction. A replacement process must finish
// from the admitted volume bytes without exposing the partial snapshot.
type pausedVolumeSnapshotRepository struct {
	ebsdomain.Repository
	armed           atomic.Bool
	admissionBlocks atomic.Int32
	committed       chan struct{}
}

type observedVolumeSnapshotWriter struct {
	ebsdomain.Transaction
	admitted        *bool
	wrote           *bool
	admissionBlocks *atomic.Int32
}

func (w observedVolumeSnapshotWriter) PutSnapshot(v ebsdomain.SnapshotRecord) error {
	if v.Volume != nil {
		if _, err := w.Transaction.Snapshot(v.Key); errors.Is(err, ebsdomain.ErrNotFound) {
			*w.admitted = true
		}
	}
	return w.Transaction.PutSnapshot(v)
}

func (w observedVolumeSnapshotWriter) PutBlock(v ebsdomain.BlockRecord) error {
	if err := w.Transaction.PutBlock(v); err != nil {
		return err
	}
	*w.wrote = true
	if *w.admitted {
		w.admissionBlocks.Add(1)
	}
	return nil
}

func (r *pausedVolumeSnapshotRepository) Update(ctx context.Context, fn func(ebsdomain.Transaction) error) error {
	admitted, wrote := false, false
	err := r.Repository.Update(ctx, func(tx ebsdomain.Transaction) error {
		return fn(observedVolumeSnapshotWriter{Transaction: tx, admitted: &admitted, wrote: &wrote, admissionBlocks: &r.admissionBlocks})
	})
	if err == nil && !admitted && wrote && r.armed.CompareAndSwap(true, false) {
		close(r.committed)
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func TestEBSVolumeSnapshotRecovery(t *testing.T) {
	for _, scenario := range []struct{ backend, change string }{
		{"memory", "delete-source"}, {"sqlite", "delete-source"},
		{"memory", "attach-source"}, {"sqlite", "attach-source"},
		{"memory", "delete-snapshot"}, {"sqlite", "delete-snapshot"},
		{"memory", "fail-image"}, {"sqlite", "fail-image"},
	} {
		backend, change := scenario.backend, scenario.change
		t.Run(backend+"/"+change, func(t *testing.T) {
			ctx := t.Context()
			manual := clock.NewManual(time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC))
			var cloud *stackd.Stack
			var stores *storage.Backends
			var paused *pausedVolumeSnapshotRepository
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "111111111111", Clock: manual}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				stores = config.Storage
				if paused == nil {
					paused = &pausedVolumeSnapshotRepository{Repository: stores.EBS, committed: make(chan struct{})}
					stores.EBS = paused
				}
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			provider := credentials.NewStaticCredentialsProvider("111111111111", "test", "")
			ec2Client := func() *ec2.Client {
				return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			ebsClient := func() *ebs.Client {
				return ebs.New(ebs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			kmsClient := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			key, err := kmsClient.CreateKey(ctx, &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			start := &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1)}
			if change != "attach-source" {
				start.Encrypted, start.KmsKeyArn = aws.Bool(true), key.KeyMetadata.Arn
			}
			source, err := ebsClient().StartSnapshot(ctx, start)
			if err != nil {
				t.Fatal(err)
			}
			payloads := map[int32][]byte{2: bytes.Repeat([]byte("a"), ebsdomain.BlockSize), 13: bytes.Repeat([]byte("z"), ebsdomain.BlockSize)}
			for index, payload := range payloads {
				digest := sha256.Sum256(payload)
				_, err = ebsClient().PutSnapshotBlock(ctx, &ebs.PutSnapshotBlockInput{SnapshotId: source.SnapshotId, BlockIndex: aws.Int32(index), BlockData: bytes.NewReader(payload), DataLength: aws.Int32(int32(len(payload))), Checksum: aws.String(base64.StdEncoding.EncodeToString(digest[:])), ChecksumAlgorithm: "SHA256"})
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = ebsClient().CompleteSnapshot(ctx, &ebs.CompleteSnapshotInput{SnapshotId: source.SnapshotId, ChangedBlocksCount: aws.Int32(2)}); err != nil {
				t.Fatal(err)
			}
			manual.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
			trailNativeDrain(t, cloud)
			zones, err := ec2Client().DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{})
			if err != nil {
				t.Fatal(err)
			}
			volume, err := ec2Client().CreateVolume(ctx, &ec2.CreateVolumeInput{SnapshotId: source.SnapshotId, AvailabilityZone: zones.AvailabilityZones[0].ZoneName})
			if err != nil {
				t.Fatal(err)
			}
			manual.Advance(ebsdomain.VolumeCreationDelay)
			trailNativeDrain(t, cloud)
			volumeKey := ebsdomain.VolumeKey{Scope: ebsdomain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, ID: aws.ToString(volume.VolumeId)}
			paused.armed.Store(true)
			captured, err := ec2Client().CreateSnapshot(ctx, &ec2.CreateSnapshotInput{VolumeId: volume.VolumeId})
			if err != nil {
				t.Fatal(err)
			}
			if copied := paused.admissionBlocks.Load(); copied != 0 {
				t.Fatalf("CreateSnapshot admission copied %d payload blocks inside its transaction", copied)
			}
			select {
			case <-paused.committed:
			case <-time.After(10 * time.Second):
				t.Fatal("volume snapshot worker did not commit its first block")
			}
			responsive, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			manual.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
			state, err := ec2Client().DescribeSnapshots(responsive, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(captured.SnapshotId)}})
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Snapshots) != 1 || state.Snapshots[0].State != ec2types.SnapshotStatePending {
				t.Fatalf("partial snapshot became complete: %+v", state.Snapshots)
			}
			_, err = ebsClient().ListSnapshotBlocks(responsive, &ebs.ListSnapshotBlocksInput{SnapshotId: captured.SnapshotId})
			assertAPIError(t, err, "ResourceNotFoundException")
			queue, err := clients.sqs("test", "test", "").CreateQueue(responsive, &sqs.CreateQueueInput{QueueName: aws.String("during-volume-snapshot")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = clients.sqs("test", "test", "").SendMessage(responsive, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("independent request")}); err != nil {
				t.Fatal(err)
			}
			if _, err = ec2Client().DeleteSnapshot(responsive, &ec2.DeleteSnapshotInput{SnapshotId: source.SnapshotId}); err != nil {
				t.Fatal(err)
			}
			if change == "attach-source" {
				snapshotTestNativeHandoff(t, stores.EBS, manual, volumeKey, payloads)
			} else {
				if change == "delete-snapshot" {
					if _, err = ec2Client().DeleteSnapshot(responsive, &ec2.DeleteSnapshotInput{SnapshotId: captured.SnapshotId}); err != nil {
						t.Fatal(err)
					}
				}
				if change == "fail-image" {
					service := ebsdomain.New(ebsdomain.Config{Repository: stores.EBS, Clock: manual})
					// Use the image collaborator without starting a second scheduler.
					service.Close()
					failureContext := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: volumeKey.Partition, AccountID: volumeKey.AccountID, Region: volumeKey.Region})
					if err := service.FailImageSnapshots(failureContext, []string{aws.ToString(captured.SnapshotId)}, "image preparation failed"); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = ec2Client().DeleteVolume(responsive, &ec2.DeleteVolumeInput{VolumeId: volume.VolumeId}); err != nil {
					t.Fatal(err)
				}
				manual.Advance(ebsdomain.VolumeDeletionDelay)
			}
			clients = reopen()
			trailNativeDrain(t, cloud)
			if change == "delete-source" || change == "attach-source" {
				state, err := ec2Client().DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(captured.SnapshotId)}})
				if err != nil {
					t.Fatal(err)
				}
				if len(state.Snapshots) != 1 || state.Snapshots[0].State != ec2types.SnapshotStatePending {
					t.Fatalf("recovery skipped completion delay: %+v", state.Snapshots)
				}
				manual.Advance(ebsdomain.CompletionDelay)
				trailNativeDrain(t, cloud)
				_, err = ebsClient().ListSnapshotBlocks(ctx, &ebs.ListSnapshotBlocksInput{SnapshotId: captured.SnapshotId})
				assertAPIError(t, err, "ResourceNotFoundException")
				manual.Advance(ebsdomain.ReadinessDelay)
				trailNativeDrain(t, cloud)
			}
			if change == "delete-snapshot" || change == "fail-image" {
				_, err = ebsClient().ListSnapshotBlocks(ctx, &ebs.ListSnapshotBlocksInput{SnapshotId: captured.SnapshotId})
				assertAPIError(t, err, "ResourceNotFoundException")
				if change == "fail-image" {
					state, err := ec2Client().DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(captured.SnapshotId)}})
					if err != nil {
						t.Fatal(err)
					}
					if len(state.Snapshots) != 1 || state.Snapshots[0].State != ec2types.SnapshotStateError {
						t.Fatalf("failed image snapshot did not reach error: %+v", state.Snapshots)
					}
				}
			} else {
				listed, err := ebsClient().ListSnapshotBlocks(ctx, &ebs.ListSnapshotBlocksInput{SnapshotId: captured.SnapshotId})
				if err != nil {
					t.Fatal(err)
				}
				if len(listed.Blocks) != len(payloads) {
					t.Fatalf("recovered sparse block set: %+v", listed.Blocks)
				}
				for _, block := range listed.Blocks {
					out, err := ebsClient().GetSnapshotBlock(ctx, &ebs.GetSnapshotBlockInput{SnapshotId: captured.SnapshotId, BlockIndex: block.BlockIndex, BlockToken: block.BlockToken})
					if err != nil {
						t.Fatal(err)
					}
					data, err := io.ReadAll(out.BlockData)
					out.BlockData.Close()
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(data, payloads[aws.ToInt32(block.BlockIndex)]) {
						t.Fatalf("captured block %d differs after %s and restart", aws.ToInt32(block.BlockIndex), change)
					}
				}
			}
			if err := stores.EBS.View(ctx, func(r ebsdomain.Reader) error {
				v, err := r.Volume(volumeKey)
				if err != nil {
					return err
				}
				if change == "attach-source" {
					if v.NativePath == "" {
						t.Fatal("native handoff did not retain byte authority")
					}
				} else if string(v.Status) != "deleted" {
					t.Fatalf("source did not finish deletion: %s", v.Status)
				}
				blocks, err := r.VolumeBlocks(volumeKey)
				if err != nil {
					return err
				}
				pending, err := r.VolumeSnapshotBlocksPending(volumeKey)
				if err != nil {
					return err
				}
				if pending {
					t.Fatal("terminal snapshot retained a source pin")
				}
				if change == "delete-snapshot" || change == "fail-image" {
					discarded, err := r.Blocks(ebsdomain.SnapshotKey{Scope: volumeKey.Scope, ID: aws.ToString(captured.SnapshotId)})
					if err != nil {
						return err
					}
					if len(discarded) != 0 {
						t.Fatalf("discarded snapshot retained %d partial blocks", len(discarded))
					}
				}
				if len(blocks) != 0 {
					t.Fatalf("released source retained %d blocks", len(blocks))
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The file-backed disk fixture exercises the production byte-authority handoff,
// not QEMU itself. It has no implementation for unused native operations, so the
// SQL snapshot worker cannot silently recapture the disk.
type volumeSnapshotTestDisks struct{ ebsdomain.NativeDisks }

func (volumeSnapshotTestDisks) CreateDisk(_ context.Context, disk native.Disk, size int64) error {
	file, err := os.OpenFile(disk.Path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Truncate(size)
}

func (volumeSnapshotTestDisks) WriteDisk(_ context.Context, disk native.Disk, fn func(io.WriterAt) error) error {
	file, err := os.OpenFile(disk.Path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	return fn(file)
}

func (volumeSnapshotTestDisks) DeleteDisk(_ context.Context, disk native.Disk) error {
	err := os.Remove(disk.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func snapshotTestNativeHandoff(t *testing.T, repository ebsdomain.Repository, manual *clock.Manual, key ebsdomain.VolumeKey, payloads map[int32][]byte) {
	t.Helper()
	disks := volumeSnapshotTestDisks{}
	service := ebsdomain.New(ebsdomain.Config{Repository: repository, Clock: manual, NativeDisks: disks, NativeVolumeDirectory: t.TempDir()})
	defer service.Close()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
	instance := ec2api.Instance{InstanceId: new(ec2api.String("i-00000000000000001")), RootDeviceName: new(ec2api.String("/dev/sda1")), BlockDeviceMappings: ec2api.InstanceBlockDeviceMappingList{
		{DeviceName: new(ec2api.String("/dev/sda1")), Ebs: &ec2api.EbsInstanceBlockDevice{VolumeId: new(ec2api.String(key.ID)), Status: new(ec2api.AttachmentStatusAttached)}},
	}}
	prepared, err := service.PrepareInstanceVolumes(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 1 {
		t.Fatalf("native handoff disks: %+v", prepared)
	}
	if err := repository.View(ctx, func(r ebsdomain.Reader) error {
		blocks, err := r.VolumeBlocks(key)
		if len(blocks) != len(payloads) {
			t.Fatalf("native handoff discarded pinned snapshot bytes: %+v", blocks)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(prepared[0].Path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	buffer := make([]byte, ebsdomain.BlockSize)
	for index, payload := range payloads {
		if _, err := file.ReadAt(buffer, int64(index)*ebsdomain.BlockSize); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer, payload) {
			t.Fatalf("hydrated native block %d differs", index)
		}
	}
	for _, index := range []int64{2, 13, 21} {
		if _, err := file.WriteAt(bytes.Repeat([]byte("new guest bytes"), ebsdomain.BlockSize/len("new guest bytes")), index*ebsdomain.BlockSize); err != nil {
			t.Fatal(err)
		}
	}
}
