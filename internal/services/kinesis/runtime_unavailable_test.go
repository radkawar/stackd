package kinesis

import (
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// A stream retained from a run with a record runtime must not enter UPDATING,
// DELETING or register consumers that only the absent engine can complete.
func TestRetainedStreamRejectsEngineEffectsWithoutRuntime(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	key := StreamKey{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "retained"}
	stream := StreamRecord{Key: key, EngineID: "engine", NextPartition: 1, Data: api.StreamDescriptionSummary{
		StreamName: new(api.StreamName(key.Name)), StreamARN: new(api.StreamARN(key.ARN())), StreamStatus: new(api.StreamStatusACTIVE),
		StreamModeDetails: &api.StreamModeDetails{StreamMode: new(api.StreamModePROVISIONED)}, RetentionPeriodHours: new(api.RetentionPeriodHours(24)),
		OpenShardCount: new(api.ShardCountObject(1)), ConsumerCount: new(api.ConsumerCountObject(0)), MaxRecordSizeInKiB: new(api.MaxRecordSizeInKiB(1024)),
		EncryptionType: new(api.EncryptionTypeNONE), EnhancedMonitoring: api.EnhancedMonitoringList{{ShardLevelMetrics: api.MetricsNameList{}}},
	}}
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutStream(stream) }); err != nil {
		t.Fatal(err)
	}
	model, _ := awscatalog.LookupService("kinesis")
	name, arn := new(api.StreamName(key.Name)), new(api.StreamARN(key.ARN()))
	for operation, input := range map[string]any{
		"IncreaseStreamRetentionPeriod": &api.IncreaseStreamRetentionPeriodInput{StreamName: name, RetentionPeriodHours: new(api.RetentionPeriodHours(720))},
		"UpdateMaxRecordSize":           &api.UpdateMaxRecordSizeInput{StreamARN: arn, MaxRecordSizeInKiB: new(api.MaxRecordSizeInKiB(2048))},
		"EnableEnhancedMonitoring":      &api.EnableEnhancedMonitoringInput{StreamName: name, ShardLevelMetrics: api.MetricsNameList{api.MetricsNameINCOMING_BYTES}},
		"RegisterStreamConsumer":        &api.RegisterStreamConsumerInput{StreamARN: arn, ConsumerName: new(api.ConsumerName("reader"))},
		"DeleteStream":                  &api.DeleteStreamInput{StreamName: name},
	} {
		op, ok := model.Operation(operation)
		if !ok {
			t.Fatalf("missing operation %s", operation)
		}
		if _, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}); rejected == nil || rejected.Code != "ServiceUnavailable" {
			t.Errorf("%s admitted without a record runtime: %v", operation, rejected)
		}
	}
	if err := repository.View(ctx, func(r Reader) error {
		current, err := r.Stream(key)
		if err != nil {
			return err
		}
		consumers, err := r.Consumers(key)
		if err != nil {
			return err
		}
		if value(current.Data.StreamStatus) != "ACTIVE" || current.Pending != nil || len(consumers) != 0 {
			t.Fatalf("rejected intent changed the retained stream: %+v consumers=%d", current, len(consumers))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
