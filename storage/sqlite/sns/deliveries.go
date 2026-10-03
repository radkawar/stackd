package sns

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/scheduler"
	domain "stackd/storage/sns"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sns/internal/sqlcgen"
)

func (r reader) Message(k domain.MessageKey) (domain.MessageRecord, error) {
	v, err := r.q.GetMessage(r.ctx, sqlcgen.GetMessageParams{ID: k.ID, Protocol: k.Protocol})
	if err != nil {
		return domain.MessageRecord{}, missing(err)
	}
	attributes, err := r.q.GetMessageAttributes(r.ctx, sqlcgen.GetMessageAttributesParams{MessageID: k.ID, Protocol: k.Protocol})
	if err != nil {
		return domain.MessageRecord{}, err
	}
	out := domain.MessageRecord{
		Key: domain.MessageKey{ID: v.ID, Protocol: v.Protocol}, Topic: domain.TopicKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TopicName},
		Body: v.Body, Subject: v.Subject, Published: v.Published, ParentEventID: v.ParentEventID, RequestID: v.RequestID,
		MessageGroupID:         v.MessageGroupID,
		MessageDeduplicationID: v.MessageDeduplicationID, SequenceNumber: v.SequenceNumber, Structured: v.Structured,
		SignatureVersion: v.SignatureVersion, Signature: v.Signature, SigningKeyID: v.SigningKeyID,
		KMSKeyARN: v.KmsKeyArn, WrappedDataKey: v.WrappedDataKey, EncryptedBody: v.EncryptedBody,
		Type: v.MessageType, Token: v.Token, SubscribeURL: v.SubscribeUrl,
	}
	if len(attributes) > 0 {
		out.Attributes = make(api.MessageAttributeMap, len(attributes))
		for _, a := range attributes {
			// The SQLite driver scans both NULL and a zero-length BLOB as nil.
			if a.HasBinaryValue != 0 && a.BinaryValue == nil {
				a.BinaryValue = []byte{}
			}
			out.Attributes[api.String(a.Name)] = api.MessageAttributeValue{DataType: (*api.String)(a.DataType), StringValue: (*api.String)(a.StringValue), BinaryValue: api.Binary(a.BinaryValue)}
		}
	}
	out.Publisher, err = r.publisher(k)
	if err != nil {
		return domain.MessageRecord{}, err
	}
	if out.KMSKeyARN != "" {
		context, err := r.q.GetMessageEncryptionContext(r.ctx, sqlcgen.GetMessageEncryptionContextParams{MessageID: k.ID, Protocol: k.Protocol})
		if err != nil {
			return domain.MessageRecord{}, err
		}
		out.EncryptionContext = make(map[string]string, len(context))
		for _, field := range context {
			out.EncryptionContext[field.Name] = field.Value
		}
	}
	return out, nil
}

func (w writer) PutMessage(v domain.MessageRecord) error {
	k := v.Topic
	if err := w.q.PutMessage(w.ctx, sqlcgen.PutMessageParams{
		ID: v.Key.ID, Protocol: v.Key.Protocol, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TopicName: k.Name,
		Body: v.Body, Subject: v.Subject, Published: v.Published.UTC(), ParentEventID: v.ParentEventID, RequestID: v.RequestID,
		MessageGroupID:         v.MessageGroupID,
		MessageDeduplicationID: v.MessageDeduplicationID, SequenceNumber: v.SequenceNumber, Structured: v.Structured,
		SignatureVersion: v.SignatureVersion, Signature: v.Signature, SigningKeyID: v.SigningKeyID,
		KmsKeyArn: v.KMSKeyARN, WrappedDataKey: v.WrappedDataKey, EncryptedBody: v.EncryptedBody,
		MessageType: v.Type, Token: v.Token, SubscribeUrl: v.SubscribeURL,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteMessageAttributes(w.ctx, sqlcgen.DeleteMessageAttributesParams{MessageID: v.Key.ID, Protocol: v.Key.Protocol}); err != nil {
		return err
	}
	for name, a := range v.Attributes {
		if err := w.q.PutMessageAttribute(w.ctx, sqlcgen.PutMessageAttributeParams{MessageID: v.Key.ID, Protocol: v.Key.Protocol, Name: string(name), DataType: (*string)(a.DataType), StringValue: (*string)(a.StringValue), BinaryValue: []byte(a.BinaryValue)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteMessageEncryptionContext(w.ctx, sqlcgen.DeleteMessageEncryptionContextParams{MessageID: v.Key.ID, Protocol: v.Key.Protocol}); err != nil {
		return err
	}
	for name, value := range v.EncryptionContext {
		if err := w.q.PutMessageEncryptionContext(w.ctx, sqlcgen.PutMessageEncryptionContextParams{MessageID: v.Key.ID, Protocol: v.Key.Protocol, Name: name, Value: value}); err != nil {
			return err
		}
	}
	if v.KMSKeyARN != "" || v.Publisher.TraceHeader != "" {
		return w.putPublisher(v.Key, v.Publisher)
	}
	return nil
}

func (r reader) Delivery(id string) (domain.DeliveryRecord, error) {
	v, err := r.q.GetDelivery(r.ctx, id)
	if err != nil {
		return domain.DeliveryRecord{}, missing(err)
	}
	return domain.DeliveryRecord{
		ID: v.ID, Message: domain.MessageKey{ID: v.MessageID, Protocol: v.MessageProtocol},
		Subscription: domain.SubscriptionKey{Topic: domain.TopicKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.TopicName}, ID: v.SubscriptionID},
		Due:          v.Due, Version: uint64(v.Version), Attempts: int(v.Attempts), DeadLetter: v.DeadLetter,
		FIFOGroup: v.FifoGroup, FIFOPrevious: v.FifoPrevious, Replayed: v.Replayed,
	}, nil
}

func (r reader) NextDelivery() (scheduler.Job, bool, error) {
	v, err := r.q.NextDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: v.ID, Due: v.Due, Version: uint64(v.Version)}, true, nil
}

func (w writer) PutDelivery(v domain.DeliveryRecord) error {
	return w.q.PutDelivery(w.ctx, sqlcgen.PutDeliveryParams{ID: v.ID, MessageID: v.Message.ID, MessageProtocol: v.Message.Protocol, SubscriptionArn: v.Subscription.ARN(), Due: v.Due.UTC(), Version: sqlite.Uint64(v.Version), Attempts: int64(v.Attempts), DeadLetter: v.DeadLetter, FifoGroup: v.FIFOGroup, FifoPrevious: v.FIFOPrevious, Replayed: v.Replayed})
}

func (w writer) DeleteDelivery(id string) error {
	message, err := w.q.DeleteDelivery(w.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return w.q.CollectMessage(w.ctx, sqlcgen.CollectMessageParams(message))
}

func (r reader) DeliveryTail(sub domain.SubscriptionKey, group string) (string, error) {
	id, err := r.q.DeliveryTail(r.ctx, sqlcgen.DeliveryTailParams{SubscriptionArn: sub.ARN(), FifoGroup: group})
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}
