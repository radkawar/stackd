package dynamodb

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/dynamodb"
)

type kinesisChangeRecord struct {
	AWSRegion    string                 `json:"awsRegion"`
	EventID      string                 `json:"eventID"`
	EventName    string                 `json:"eventName"`
	UserIdentity *kinesisChangeIdentity `json:"userIdentity"`
	RecordFormat string                 `json:"recordFormat"`
	TableName    string                 `json:"tableName"`
	DynamoDB     kinesisChangeImages    `json:"dynamodb"`
	EventSource  string                 `json:"eventSource"`
}
type kinesisChangeIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
}
type kinesisChangeImages struct {
	ApproximateCreationDateTime          int64            `json:"ApproximateCreationDateTime"`
	ApproximateCreationDateTimePrecision string           `json:"ApproximateCreationDateTimePrecision,omitempty"`
	Keys                                 api.Key          `json:"Keys"`
	NewImage                             api.AttributeMap `json:"NewImage,omitempty"`
	OldImage                             api.AttributeMap `json:"OldImage,omitempty"`
	SizeBytes                            int              `json:"SizeBytes"`
}

func publishKinesisMutation(tx Transaction, pending *MutationCapture, source MutationSource, item MutationItem, after api.AttributeMap) error {
	if len(source.Kinesis) == 0 || len(item.Before) == 0 && len(after) == 0 {
		return nil
	}
	if !pending.Transactional && replicaImagesEqual(item.Before, after) {
		return nil
	}
	event := "MODIFY"
	if len(item.Before) == 0 {
		event = "INSERT"
	} else if len(after) == 0 {
		event = "REMOVE"
	}
	key := kinesisBinaryImage(api.AttributeMap(item.Key))
	before := kinesisBinaryImage(item.Before)
	next := kinesisBinaryImage(after)
	size := itemSize(item.Key) + itemSize(item.Before) + itemSize(after)
	hash := md5.Sum([]byte(replicaKeyID(source.KeySchema, item.Key)))
	partition := strings.ToUpper(hex.EncodeToString(hash[:]))
	for _, consumer := range source.Kinesis {
		if !consumer.CaptureUntil.IsZero() && !pending.At.Before(consumer.CaptureUntil) {
			continue
		}
		record := kinesisChangeRecord{AWSRegion: source.Table.Region, EventID: uuid.NewString(), EventName: event, RecordFormat: "application/json", TableName: source.Table.Name, EventSource: "aws:dynamodb", DynamoDB: kinesisChangeImages{ApproximateCreationDateTime: pending.At.UnixMilli(), Keys: api.Key(key), OldImage: before, NewImage: next, SizeBytes: size}}
		if consumer.Precision == "MICROSECOND" {
			record.DynamoDB.ApproximateCreationDateTime = pending.At.UnixMicro()
			record.DynamoDB.ApproximateCreationDateTimePrecision = "MICROSECOND"
		}
		if pending.TTL {
			record.UserIdentity = &kinesisChangeIdentity{Type: "Service", PrincipalID: "dynamodb.amazonaws.com"}
		}
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err = tx.PutKinesisDelivery(KinesisDelivery{ID: record.EventID, DestinationID: consumer.ID, Table: source.Table, StreamARN: consumer.StreamARN, PartitionKey: partition, Data: data, ParentEventID: pending.ParentEventID, Due: pending.At}); err != nil {
			return err
		}
	}
	return nil
}

// The generated wire encoder contributes the second base64 layer. Attribute
// names and all nonbinary values retain the actual engine's native image.
func kinesisBinaryImage(image api.AttributeMap) api.AttributeMap {
	if image == nil {
		return nil
	}
	out := api.CloneAttributeMap(image)
	for name, v := range out {
		out[name] = kinesisBinaryAttribute(v)
	}
	return out
}
func kinesisBinaryAttribute(v api.AttributeValue) api.AttributeValue {
	if v.B != nil {
		v.B = []byte(base64.StdEncoding.EncodeToString(v.B))
	}
	for i, b := range v.BS {
		v.BS[i] = []byte(base64.StdEncoding.EncodeToString(b))
	}
	for name, child := range v.M {
		v.M[name] = kinesisBinaryAttribute(child)
	}
	for i, child := range v.L {
		v.L[i] = kinesisBinaryAttribute(child)
	}
	return v
}
