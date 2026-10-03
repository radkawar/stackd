package kms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"

	"stackd/clock"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

func TestLifecycleDrainBoundsAndStaleSelection(t *testing.T) {
	epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	manual := clock.NewManual(epoch)
	backend := NewMemoryStorage(nil)
	original := NewWithConfig(Config{Storage: backend, Clock: manual})
	metadata := rootMetadata("111111111111", "us-east-1", "aws")
	client := sdkClient(t, original, metadata)
	created := createSDKKey(t, client)
	if _, err := client.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: created.KeyId, RotationPeriodInDays: aws.Int32(90)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: created.KeyId}); err != nil {
		t.Fatal(err)
	}
	original.Close()
	// Reconstruct without starting the automatic worker so each explicit drain
	// can demonstrate its budget against the real retained rotation schedule.
	s := NewWithConfig(Config{Storage: backend, Clock: manual})
	t.Cleanup(func() { _ = s.Close() })
	if err := manual.Advance(270 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	owner := KeyOwner{Partition: "aws", AccountID: metadata.AccountID}
	for i, due := range []time.Time{epoch.Add(2 * time.Minute), epoch.Add(90 * 24 * time.Hour), epoch.Add(180 * 24 * time.Hour), epoch.Add(270 * 24 * time.Hour)} {
		result, err := s.jobs.RunDue(t.Context(), 1)
		if err != nil || result.Processed != 1 || result.More != (i < 3) {
			t.Fatal("drain exceeded or lost its budget", result, err)
		}
		if err := backend.View(t.Context(), func(tx Reader) error {
			set, err := tx.KeySet(owner, aws.ToString(created.KeyId))
			if err != nil {
				return err
			}
			if len(set.Materials) != i+2 || !set.Materials[len(set.Materials)-1].RotationDate.Equal(due) {
				t.Error("drain skipped deadlines or ran more than one rotation", len(set.Materials))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	source := lifecycleJobs{s}
	var selected scheduler.Job
	if err := backend.View(t.Context(), func(reader Reader) error {
		var found bool
		var err error
		selected, found, err = source.Next(reader.Context())
		if err != nil {
			return err
		}
		if !found || selected.Key != owner.Partition+"/"+owner.AccountID+"/"+aws.ToString(created.KeyId) || !selected.Due.Equal(epoch.Add(360*24*time.Hour)) {
			t.Fatal("next automatic rotation in read-only snapshot", selected, found)
		}
		return nil
	}); err != nil {
		t.Fatal("read-only deadline discovery", err)
	}
	ctx := withAction(awsctx.WithMetadata(t.Context(), metadata), "DisableKeyRotation", nil)
	if err := s.transact(ctx, func(ctx context.Context) *awswire.Error {
		_, err := s.disableKeyRotation(ctx, &kmsapi.DisableKeyRotationInput{KeyId: ptr(kmsapi.KeyIdType(aws.ToString(created.KeyId)))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := manual.Advance(90 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	// A stale job is a read: even an adapter rejecting writes cannot make it fail.
	s.storage = failWrites{backend}
	if err := source.Run(t.Context(), selected); err != nil {
		t.Fatal("canceled rotation wrote state", err)
	}
	if _, found, err := source.Next(t.Context()); err != nil || found {
		t.Fatal("disabled rotation remained scheduled", found, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := source.Next(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("scheduler discovery ignored cancellation", err)
	}
}
