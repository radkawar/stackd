package kinesis

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
)

// kafka-go v0.4.49 has no DeleteRecords message. These v1 wire structs use its
// existing codec, version negotiation and transport; Kafka owns prefix deletion.
// Schema: Apache Kafka clients/src/main/resources/common/message/DeleteRecords{Request,Response}.json.
var registerDeleteRecords sync.Once

func registerNativeProtocol() {
	registerDeleteRecords.Do(func() { protocol.Register(&deleteRecordsRequest{}, &deleteRecordsResponse{}) })
}

type deleteRecordsRequest struct {
	Topics    []deleteRecordsTopic `kafka:"min=v1,max=v1"`
	TimeoutMs int32                `kafka:"min=v1,max=v1"`
}

type deleteRecordsTopic struct {
	Name       string                   `kafka:"min=v1,max=v1"`
	Partitions []deleteRecordsPartition `kafka:"min=v1,max=v1"`
}

type deleteRecordsPartition struct {
	PartitionIndex int32 `kafka:"min=v1,max=v1"`
	Offset         int64 `kafka:"min=v1,max=v1"`
}

func (*deleteRecordsRequest) ApiKey() protocol.ApiKey { return protocol.DeleteRecords }

type deleteRecordsResponse struct {
	ThrottleTimeMs int32                      `kafka:"min=v1,max=v1"`
	Topics         []deleteRecordsTopicResult `kafka:"min=v1,max=v1"`
}

type deleteRecordsTopicResult struct {
	Name       string                         `kafka:"min=v1,max=v1"`
	Partitions []deleteRecordsPartitionResult `kafka:"min=v1,max=v1"`
}

type deleteRecordsPartitionResult struct {
	PartitionIndex int32 `kafka:"min=v1,max=v1"`
	LowWatermark   int64 `kafka:"min=v1,max=v1"`
	ErrorCode      int16 `kafka:"min=v1,max=v1"`
}

func (*deleteRecordsResponse) ApiKey() protocol.ApiKey { return protocol.DeleteRecords }

func (l *nativeLog) Trim(ctx context.Context, partition int32, before int64) (err error) {
	ctx, finish := l.operation(ctx, "trim", &err)
	defer finish()
	if partition < 0 || before < 0 {
		return errors.New("kafka trim requires nonnegative partition and offset")
	}
	deadline, _ := ctx.Deadline()
	response, err := l.transport.RoundTrip(ctx, l.client.Addr, &deleteRecordsRequest{
		Topics:    []deleteRecordsTopic{{Name: nativeTopic, Partitions: []deleteRecordsPartition{{PartitionIndex: partition, Offset: before}}}},
		TimeoutMs: int32(max(1, time.Until(deadline).Milliseconds())),
	})
	if err != nil {
		return err
	}
	result := response.(*deleteRecordsResponse)
	for _, topic := range result.Topics {
		if topic.Name != nativeTopic {
			continue
		}
		for _, part := range topic.Partitions {
			if part.PartitionIndex != partition {
				continue
			}
			if part.ErrorCode != 0 {
				return kafka.Error(part.ErrorCode)
			}
			if part.LowWatermark < before {
				return errors.New("kafka deletion did not reach the requested low watermark")
			}
			return nil
		}
	}
	return errors.New("kafka deletion response omitted the requested partition")
}
