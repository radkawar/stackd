package ec2

import (
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// An image's graceful reboot must not strand ordinary observation after a
// concurrent metadata mutation, or overwrite a newer explicit stop request.
func TestImageSourceReleasePreservesCurrentInstanceIntent(t *testing.T) {
	for _, stop := range []bool{false, true} {
		name := "metadata"
		if stop {
			name = "explicit-stop"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
			s := New(Config{Clock: clock.NewManual(now)})
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
			instanceKey := key(ctx, "i-0123456789abcdef0")
			record := InstanceRecord{Key: instanceKey, Generation: 7, Intent: InstanceIntentObserve, Data: api.Instance{
				InstanceId:      new(api.String(instanceKey.ID)),
				State:           &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))},
				MetadataOptions: &api.InstanceMetadataOptionsResponse{HttpEndpoint: new(api.InstanceMetadataEndpointState("enabled")), HttpTokens: new(api.HttpTokensState("optional")), HttpPutResponseHopLimit: new(api.Integer(1)), InstanceMetadataTags: new(api.InstanceMetadataTagsState("disabled"))},
			}}
			image := ImageRecord{Key: key(ctx, "ami-0123456789abcdef0"), Create: &ImageCreation{InstanceID: instanceKey.ID, InstanceGeneration: record.Generation, Phase: "shutdown-wait"}}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutInstance(record) }); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if stop {
					_, err := s.stopInstances(tx.Context(), tx, &api.StopInstancesRequest{InstanceIds: api.InstanceIdStringList{api.InstanceId(instanceKey.ID)}})
					return err
				}
				_, err := s.modifyInstanceMetadataOptions(tx.Context(), tx, &api.ModifyInstanceMetadataOptionsRequest{InstanceId: new(api.InstanceId(instanceKey.ID)), HttpTokens: new(api.HttpTokensState("required"))})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return s.releaseImageSource(tx, image) }); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(tx Reader) error {
				current, err := tx.Instance(instanceKey)
				if err != nil {
					return err
				}
				if current.NextActionAt.IsZero() {
					t.Fatal("image release orphaned instance reconciliation")
				}
				if stop {
					if current.Intent != InstanceIntentStop || instanceState(current) != "stopping" {
						t.Fatalf("image release replaced explicit stop: %+v", current)
					}
				} else {
					if current.Intent != InstanceIntentObserve || instanceState(current) != "running" || str(current.Data.MetadataOptions.HttpTokens) != "required" {
						t.Fatalf("image release lost current metadata/intent: %+v", current)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
