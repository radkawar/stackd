package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	ebsdomain "stackd/internal/services/ebs"
)

// Pause after a committed destination block, not inside a transaction. This
// models process loss between bounded effects and makes unrelated signed request
// progress deterministic rather than depending on a machine-speed threshold.
type snapshotCopyPauseRepository struct {
	ebsdomain.Repository
	armed   atomic.Bool
	written atomic.Int32
	paused  chan struct{}
}

type snapshotCopyPauseTx struct {
	ebsdomain.Transaction
	copied *bool
}

func (tx snapshotCopyPauseTx) PutBlock(block ebsdomain.BlockRecord) error {
	v, err := tx.Snapshot(block.Key.Snapshot)
	if err != nil {
		return err
	}
	if v.Copy != nil {
		*tx.copied = true
	}
	return tx.Transaction.PutBlock(block)
}

func (r *snapshotCopyPauseRepository) Update(ctx context.Context, fn func(ebsdomain.Transaction) error) error {
	copied := false
	err := r.Repository.Update(ctx, func(tx ebsdomain.Transaction) error {
		return fn(snapshotCopyPauseTx{Transaction: tx, copied: &copied})
	})
	if err == nil && copied && r.armed.Load() && r.written.Add(1) == 2 {
		close(r.paused)
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

// Native copy_data establishes independent bytes and source-sharing authority;
// this regression adds the local crash boundary without introducing new AWS
// timing expectations. All admissions, revocation, deletion and reads are signed.
func TestEBSCopySnapshotInterruptedPayload(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, name := range []string{"shared-cross-region", "encrypted-incremental", "encrypted-full"} {
			encrypted := name != "shared-cross-region"
			t.Run(backend+"/"+name, func(t *testing.T) {
				const owner, recipient = "111111111111", "222222222222"
				const sourceRegion = "us-east-1"
				destinationAccount, destinationRegion := recipient, "us-west-2"
				if encrypted {
					destinationAccount, destinationRegion = owner, sourceRegion
				}
				now := clock.NewManual(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
				var paused *snapshotCopyPauseRepository
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner, Clock: now}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					repository := config.Storage.EBS
					if previous, ok := repository.(*snapshotCopyPauseRepository); ok {
						repository = previous.Repository
					}
					paused = &snapshotCopyPauseRepository{Repository: repository, paused: make(chan struct{})}
					config.Storage.EBS = paused
					return startPublicCloud(t, config)
				})
				ec2Client := func(account, region string) *ec2.Client {
					return ec2.New(ec2.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				ebsClient := func(account, region string) *ebs.Client {
					return ebs.New(ebs.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				start := &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1)}
				var copyKey *string
				if encrypted {
					keys := kms.New(kms.Options{Region: sourceRegion, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(owner, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
					key, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
					if err != nil {
						t.Fatal(err)
					}
					start.Encrypted, start.KmsKeyArn = aws.Bool(true), key.KeyMetadata.Arn
					copyKey = key.KeyMetadata.Arn
					if name == "encrypted-full" {
						key, err = keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
						if err != nil {
							t.Fatal(err)
						}
						copyKey = key.KeyMetadata.Arn
					}
				}
				source, err := ebsClient(owner, sourceRegion).StartSnapshot(t.Context(), start)
				if err != nil {
					t.Fatal(err)
				}
				const blockCount = 8
				payload := func(index int32) []byte {
					return bytes.Repeat([]byte{byte(index + 1), 0x93, 0x2c, 0xe7}, ebsdomain.BlockSize/4)
				}
				for index := int32(0); index < blockCount; index++ {
					body := payload(index)
					checksum := sha256.Sum256(body)
					_, err = ebsClient(owner, sourceRegion).PutSnapshotBlock(t.Context(), &ebs.PutSnapshotBlockInput{
						SnapshotId: source.SnapshotId, BlockIndex: aws.Int32(index), BlockData: bytes.NewReader(body),
						DataLength: aws.Int32(ebsdomain.BlockSize), Checksum: aws.String(base64.StdEncoding.EncodeToString(checksum[:])), ChecksumAlgorithm: ebstypes.ChecksumAlgorithmChecksumAlgorithmSha256,
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err := ebsClient(owner, sourceRegion).CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: source.SnapshotId, ChangedBlocksCount: aws.Int32(blockCount)}); err != nil {
					t.Fatal(err)
				}
				now.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
				if !encrypted {
					_, err := ec2Client(owner, sourceRegion).ModifySnapshotAttribute(t.Context(), &ec2.ModifySnapshotAttributeInput{
						SnapshotId: source.SnapshotId, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission,
						CreateVolumePermission: &ec2types.CreateVolumePermissionModifications{Add: []ec2types.CreateVolumePermission{{UserId: aws.String(recipient)}}},
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				copied, err := ec2Client(destinationAccount, destinationRegion).CopySnapshot(t.Context(), &ec2.CopySnapshotInput{SourceSnapshotId: source.SnapshotId, SourceRegion: aws.String(sourceRegion), KmsKeyId: copyKey})
				if err != nil {
					t.Fatal(err)
				}
				paused.armed.Store(true)
				runContext, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				cloud := clients.server.Config.Handler.(*stackd.Stack)
				go func() { _, err := cloud.RunDueJobs(runContext, 100); done <- err }()
				select {
				case <-paused.paused:
				case err := <-done:
					t.Fatalf("copy did not reach committed partial payload: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatal("copy did not yield a bounded payload transaction")
				}
				requestContext, requestCancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer requestCancel()
				if _, err := clients.sqs(owner, "test", "").CreateQueue(requestContext, &sqs.CreateQueueInput{QueueName: aws.String("during-snapshot-copy")}); err != nil {
					t.Fatalf("unrelated signed request blocked behind copy: %v", err)
				}
				if !encrypted {
					if _, err := ec2Client(owner, sourceRegion).ResetSnapshotAttribute(requestContext, &ec2.ResetSnapshotAttributeInput{SnapshotId: source.SnapshotId, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission}); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := ec2Client(owner, sourceRegion).DeleteSnapshot(requestContext, &ec2.DeleteSnapshotInput{SnapshotId: source.SnapshotId}); err != nil {
					t.Fatal(err)
				}
				now.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay + ebsdomain.DeletionDelay)
				pending, err := ec2Client(destinationAccount, destinationRegion).DescribeSnapshots(requestContext, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(copied.SnapshotId)}})
				if err != nil || len(pending.Snapshots) != 1 || pending.Snapshots[0].State != ec2types.SnapshotStatePending {
					t.Fatalf("partial copy became public completion: %+v %v", pending, err)
				}
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatalf("interrupted worker = %v", err)
				}
				clients = reopen()
				pending, err = ec2Client(destinationAccount, destinationRegion).DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(copied.SnapshotId)}})
				if err != nil || len(pending.Snapshots) != 1 || pending.Snapshots[0].State != ec2types.SnapshotStatePending {
					t.Fatalf("reopen fabricated completion: %+v %v", pending, err)
				}
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				now.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				blocks, err := ebsClient(destinationAccount, destinationRegion).ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: copied.SnapshotId})
				if err != nil {
					t.Fatal(err)
				}
				if len(blocks.Blocks) != blockCount {
					t.Fatalf("recovered copy blocks = %d, want %d", len(blocks.Blocks), blockCount)
				}
				for _, block := range blocks.Blocks {
					out, err := ebsClient(destinationAccount, destinationRegion).GetSnapshotBlock(t.Context(), &ebs.GetSnapshotBlockInput{SnapshotId: copied.SnapshotId, BlockIndex: block.BlockIndex, BlockToken: block.BlockToken})
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(out.BlockData)
					out.BlockData.Close()
					if err != nil || !bytes.Equal(body, payload(aws.ToInt32(block.BlockIndex))) {
						t.Fatalf("recovered independent block %d differs after source deletion: %v", aws.ToInt32(block.BlockIndex), err)
					}
				}
			})
		}
	}
}

// Exercise real retained KMS authority and native notifications across a lost
// payload worker. In particular, revoking a grant must not make its retirement
// an impossible prerequisite for reclaiming source bytes or running later work.
func TestEBSCopyFinalizationRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range []string{"copy-late", "copy-revoked", "copy-deleted", "volume-revoked", "volume-deleted"} {
			t.Run(backend+"/"+scenario, func(t *testing.T) {
				const owner, region = "111111111111", "us-east-1"
				isVolume := scenario == "volume-revoked" || scenario == "volume-deleted"
				deleted := scenario == "copy-deleted" || scenario == "volume-deleted"
				now := clock.NewManual(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
				var repository ebsdomain.Repository
				var copyPause *snapshotCopyPauseRepository
				var volumePause *pausedVolumeRepository
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: owner, Clock: now}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					repository = config.Storage.EBS
					if previous, ok := repository.(*snapshotCopyPauseRepository); ok {
						repository = previous.Repository
					}
					if previous, ok := repository.(*pausedVolumeRepository); ok {
						repository = previous.Repository
					}
					if isVolume {
						volumePause = &pausedVolumeRepository{Repository: repository, committed: make(chan struct{})}
						config.Storage.EBS = volumePause
					} else {
						copyPause = &snapshotCopyPauseRepository{Repository: repository, paused: make(chan struct{})}
						config.Storage.EBS = copyPause
					}
					return startPublicCloud(t, config)
				})
				ec2Client := func() *ec2.Client {
					return ec2.New(ec2.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(owner, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				direct := func() *ebs.Client {
					return ebs.New(ebs.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(owner, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				queueURL := ebsCopyRecoveryQueue(t, clients, owner, region)
				receive := func() []sqstypes.Message {
					t.Helper()
					messages, err := clients.sqs(owner, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10})
					if err != nil {
						t.Fatal(err)
					}
					return messages.Messages
				}
				sourceKey, err := clients.kms(owner, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{})
				if err != nil {
					t.Fatal(err)
				}
				targetKey, err := clients.kms(owner, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{})
				if err != nil {
					t.Fatal(err)
				}
				source, err := direct().StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), Encrypted: aws.Bool(true), KmsKeyArn: sourceKey.KeyMetadata.Arn})
				if err != nil {
					t.Fatal(err)
				}
				body := bytes.Repeat([]byte{0x97}, ebsdomain.BlockSize)
				digest := sha256.Sum256(body)
				for index := int32(0); index < 3; index++ {
					_, err := direct().PutSnapshotBlock(t.Context(), &ebs.PutSnapshotBlockInput{SnapshotId: source.SnapshotId, BlockIndex: aws.Int32(index), BlockData: bytes.NewReader(body), DataLength: aws.Int32(ebsdomain.BlockSize), Checksum: aws.String(base64.StdEncoding.EncodeToString(digest[:])), ChecksumAlgorithm: ebstypes.ChecksumAlgorithmChecksumAlgorithmSha256})
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err := direct().CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: source.SnapshotId, ChangedBlocksCount: aws.Int32(3)}); err != nil {
					t.Fatal(err)
				}
				now.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				zones, err := ec2Client().DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{})
				if err != nil {
					t.Fatal(err)
				}
				created := now.Now()
				var destination *string
				var paused <-chan struct{}
				if isVolume {
					volume, err := ec2Client().CreateVolume(t.Context(), &ec2.CreateVolumeInput{SnapshotId: source.SnapshotId, AvailabilityZone: zones.AvailabilityZones[0].ZoneName, Encrypted: aws.Bool(true), KmsKeyId: targetKey.KeyMetadata.Arn})
					if err != nil {
						t.Fatal(err)
					}
					destination = volume.VolumeId
					volumePause.armed.Store(true)
					paused = volumePause.committed
					now.Advance(ebsdomain.VolumeCreationDelay)
				} else {
					copied, err := ec2Client().CopySnapshot(t.Context(), &ec2.CopySnapshotInput{SourceSnapshotId: source.SnapshotId, SourceRegion: aws.String(region), KmsKeyId: targetKey.KeyMetadata.Arn, CompletionDurationMinutes: aws.Int32(15)})
					if err != nil {
						t.Fatal(err)
					}
					destination = copied.SnapshotId
					copyPause.armed.Store(true)
					paused = copyPause.paused
				}
				runContext, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				cloud := clients.server.Config.Handler.(*stackd.Stack)
				go func() { _, err := cloud.RunDueJobs(runContext, 100); done <- err }()
				select {
				case <-paused:
				case err := <-done:
					t.Fatalf("payload worker did not reach the interruption boundary: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatal("payload worker did not commit a partial destination")
				}
				if scenario != "copy-late" {
					for _, arn := range []*string{sourceKey.KeyMetadata.Arn, targetKey.KeyMetadata.Arn} {
						grants, err := clients.kms(owner, "test", "").ListGrants(t.Context(), &kms.ListGrantsInput{KeyId: arn})
						if err != nil {
							t.Fatal(err)
						}
						if arn == targetKey.KeyMetadata.Arn && len(grants.Grants) != 1 {
							t.Fatalf("expected one admitted destination grant, got %+v", grants.Grants)
						}
						for _, grant := range grants.Grants {
							if _, err := clients.kms(owner, "test", "").RevokeGrant(t.Context(), &kms.RevokeGrantInput{KeyId: arn, GrantId: grant.GrantId}); err != nil {
								t.Fatal(err)
							}
							_, err := clients.kms(owner, "test", "").RetireGrant(t.Context(), &kms.RetireGrantInput{KeyId: arn, GrantId: grant.GrantId})
							assertAPIError(t, err, "NotFoundException")
						}
					}
				}
				if _, err := ec2Client().DeleteSnapshot(t.Context(), &ec2.DeleteSnapshotInput{SnapshotId: source.SnapshotId}); err != nil {
					t.Fatal(err)
				}
				if deleted {
					if isVolume {
						_, err = ec2Client().DeleteVolume(t.Context(), &ec2.DeleteVolumeInput{VolumeId: destination})
					} else {
						_, err = ec2Client().DeleteSnapshot(t.Context(), &ec2.DeleteSnapshotInput{SnapshotId: destination})
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				following, err := ec2Client().CreateVolume(t.Context(), &ec2.CreateVolumeInput{AvailabilityZone: zones.AvailabilityZones[0].ZoneName, Size: aws.Int32(1)})
				if err != nil {
					t.Fatal(err)
				}
				now.Advance(time.Hour)
				sourceID := ebsdomain.SnapshotKey{Scope: ebsdomain.Scope{Partition: "aws", AccountID: owner, Region: region}, ID: aws.ToString(source.SnapshotId)}
				assertSourceBlocks := func(want int) {
					t.Helper()
					if err := repository.View(t.Context(), func(r ebsdomain.Reader) error {
						blocks, err := r.Blocks(sourceID)
						if err == nil && len(blocks) != want {
							t.Fatalf("retained source blocks = %d, want %d", len(blocks), want)
						}
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
				assertSourceBlocks(3)
				if messages := receive(); len(messages) != 0 {
					t.Fatalf("copy notified before payload finalization: %+v", messages)
				}
				cancel()
				clients = reopen()
				<-done
				recovered := now.Now()
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				assertSourceBlocks(0)
				later, err := ec2Client().DescribeVolumes(t.Context(), &ec2.DescribeVolumesInput{VolumeIds: []string{aws.ToString(following.VolumeId)}})
				if err != nil || len(later.Volumes) != 1 || later.Volumes[0].State != ec2types.VolumeStateAvailable {
					t.Fatalf("earlier retained grant blocked subsequent EBS work: %+v %v", later, err)
				}
				if !isVolume && !deleted {
					state, err := ec2Client().DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(destination)}})
					if err != nil || len(state.Snapshots) != 1 || state.Snapshots[0].State != ec2types.SnapshotStatePending {
						t.Fatalf("copy completion deadline was not based on recovered payload: %+v %v", state, err)
					}
				}
				if messages := receive(); len(messages) != 0 {
					t.Fatalf("copy notified before its committed completion deadline: %+v", messages)
				}
				now.Advance(ebsdomain.CompletionDelay)
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				messages := receive()
				if isVolume || deleted {
					if len(messages) != 0 {
						t.Fatalf("deleted copy or volume emitted copy completion: %+v", messages)
					}
				} else {
					if len(messages) != 1 {
						t.Fatalf("expected one terminal copy notification, got %+v", messages)
					}
					var event struct {
						Time   time.Time `json:"time"`
						Detail struct {
							Result, Cause, StartTime, EndTime, MetCompletionDuration string
							CompletionDurationStartTime                              string
							SnapshotID                                               string `json:"snapshot_id"`
						} `json:"detail"`
					}
					if err := json.Unmarshal([]byte(aws.ToString(messages[0].Body)), &event); err != nil {
						t.Fatal(err)
					}
					end := recovered.Add(ebsdomain.CompletionDelay)
					startStamp, startErr := time.Parse(time.RFC3339Nano, event.Detail.StartTime)
					endStamp, endErr := time.Parse(time.RFC3339Nano, event.Detail.EndTime)
					if startErr != nil || endErr != nil || !startStamp.Equal(created) || !endStamp.Equal(end) || !event.Time.Equal(end) || event.Detail.SnapshotID != "arn:aws:ec2::"+region+":snapshot/"+aws.ToString(destination) {
						t.Fatalf("recovered copy notification lost actual lifecycle times or destination: %+v", event)
					}
					if scenario == "copy-late" {
						if event.Detail.Result != "succeeded" || event.Detail.MetCompletionDuration != "false" || event.Detail.Cause != "" || event.Detail.CompletionDurationStartTime != event.Detail.StartTime {
							t.Fatalf("late time-based copy reported meeting its deadline: %+v", event.Detail)
						}
						_, err := direct().ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: destination})
						assertAPIError(t, err, "ResourceNotFoundException")
					} else if event.Detail.Result != "failed" || event.Detail.Cause == "" || event.Detail.MetCompletionDuration != "" || event.Detail.CompletionDurationStartTime != "" {
						t.Fatalf("revoked grant produced an invalid failure notification: %+v", event.Detail)
					}
					if _, err := clients.sqs(owner, "test", "").DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queueURL, ReceiptHandle: messages[0].ReceiptHandle}); err != nil {
						t.Fatal(err)
					}
				}
				now.Advance(ebsdomain.ReadinessDelay)
				clients = reopen()
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				assertSourceBlocks(0)
				if messages := receive(); len(messages) != 0 {
					t.Fatalf("terminal copy notification was republished after reopen: %+v", messages)
				}
				if isVolume {
					// A failed CreateVolume automatically deletes its destination.
					_, err := ec2Client().DescribeVolumes(t.Context(), &ec2.DescribeVolumesInput{VolumeIds: []string{aws.ToString(destination)}})
					assertAPIError(t, err, "InvalidVolume.NotFound")
				} else if scenario == "copy-late" {
					blocks, err := direct().ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: destination})
					if err != nil || len(blocks.Blocks) != 3 {
						t.Fatalf("late copy did not become independently readable: %+v %v", blocks, err)
					}
					for _, block := range blocks.Blocks {
						out, err := direct().GetSnapshotBlock(t.Context(), &ebs.GetSnapshotBlockInput{SnapshotId: destination, BlockIndex: block.BlockIndex, BlockToken: block.BlockToken})
						if err != nil {
							t.Fatal(err)
						}
						actual, err := io.ReadAll(out.BlockData)
						out.BlockData.Close()
						if err != nil || !bytes.Equal(actual, body) {
							t.Fatalf("late independent payload differs: %v", err)
						}
					}
				} else {
					state, err := ec2Client().DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(destination)}})
					if deleted {
						assertAPIError(t, err, "InvalidSnapshot.NotFound")
					} else if err != nil || len(state.Snapshots) != 1 || state.Snapshots[0].State != ec2types.SnapshotStateError {
						t.Fatalf("revoked copy did not publish terminal failure: %+v %v", state, err)
					}
				}
			})
		}
	}
}

func ebsCopyRecoveryQueue(t *testing.T, clients cloudClients, account, region string) *string {
	t.Helper()
	queues := clients.sqs(account, "test", "")
	queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("copy-recovery-events")})
	if err != nil {
		t.Fatal(err)
	}
	rules := eventbridge.New(eventbridge.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	rule, err := rules.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("copy-recovery-events"), EventPattern: aws.String(`{"source":["aws.ec2"],"detail-type":["EBS Snapshot Notification"],"detail":{"event":["copySnapshot"]}}`)})
	if err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:sqs:" + region + ":" + account + ":copy-recovery-events"
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, arn, aws.ToString(rule.RuleArn))
	if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
		t.Fatal(err)
	}
	accepted, err := rules.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("copy-recovery-events"), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: aws.String(arn)}}})
	if err != nil || accepted.FailedEntryCount != 0 {
		t.Fatalf("register recovery notification target: %+v %v", accepted, err)
	}
	return queue.QueueUrl
}
