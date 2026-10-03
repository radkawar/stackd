package eventbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"stackd/internal/awsenvelope"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/inputtransform"
)

// BusKeys separates caller configuration authority from EventBridge's data
// plane identity. All calls run before or after repository transactions.
type BusKeys interface {
	PrepareBusKey(context.Context, BusKey, string, bool) (string, *awswire.Error)
	GenerateBusDataKey(context.Context, BusKey, string) ([]byte, []byte, string, *awswire.Error)
	DecryptBusDataKey(context.Context, BusKey, []byte) ([]byte, *awswire.Error)
	DecryptBusConfiguration(context.Context, BusKey, []byte) ([]byte, *awswire.Error)
}

type busEncryption struct {
	identifier, keyARN, deadLetterARN string
	wrapped                           []byte
	configuration                     []byte
	plain                             []byte
}

// prepareBusEncryption never runs for AWS service events. AWS encrypts these
// with its own key, independently of the bus customer-managed key.
func (s *Service) prepareBusEncryption(ctx context.Context, key BusKey, source, detailType string, authorize bool, invocation string) (*busEncryption, *awswire.Error) {
	var bus BusRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		bus, err = r.Bus(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if authorize {
			return s.authorize(r, "PutEvents", key.ARN(), bus.Tags, map[string][]string{"events:source": {source}, "events:detail-type": {detailType}, "events:eventBusInvocation": {invocation}}, bus.Policy)
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	prepared := &busEncryption{identifier: bus.KmsKeyIdentifier, deadLetterARN: bus.DeadLetterARN, configuration: bus.ConfigurationDataKey}
	if bus.KmsKeyIdentifier == "" || strings.HasPrefix(source, "aws.") {
		return prepared, nil
	}
	if s.busKeys == nil {
		return nil, unsupported("No event bus KMS provider is configured.")
	}
	if material, found := s.busCache.get(bus, s.clock.Now()); found {
		prepared.wrapped, prepared.keyARN, prepared.plain = material.wrapped, material.arn, append([]byte(nil), material.plain[:]...)
		clear(material.plain[:])
		return prepared, nil
	}
	plain, wrapped, arn, rejected := s.busKeys.GenerateBusDataKey(ctx, key, bus.KmsKeyIdentifier)
	if rejected != nil {
		return nil, failure("KMSEncryptionException", rejected.Message)
	}
	s.busCache.put(bus, plain, wrapped, arn, s.clock.Now())
	prepared.wrapped, prepared.keyARN, prepared.plain = wrapped, arn, plain
	return prepared, nil
}

func (p *busEncryption) retain(tx Transaction, event EventRecord, body string) (EventRecord, error) {
	event.Payload, event.KeyARN, event.BusDeadLetterARN = ArchivePayload{}, "", ""
	bus, err := tx.Bus(event.Bus)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return EventRecord{}, err
	}
	event.ConfigurationDataKey, event.ConfigurationKeyARN = bus.ConfigurationDataKey, bus.ConfigurationKeyARN
	if !strings.HasPrefix(event.Source, "aws.") {
		event.BusDeadLetterARN = bus.DeadLetterARN
	}
	if p == nil {
		if bus.KmsKeyIdentifier != "" && !strings.HasPrefix(event.Source, "aws.") {
			return EventRecord{}, failure("ConcurrentModificationException", "Event bus encryption configuration changed during admission.")
		}
		return event, nil
	}
	if bus.KmsKeyIdentifier != p.identifier || bus.DeadLetterARN != p.deadLetterARN || !bytes.Equal(bus.ConfigurationDataKey, p.configuration) {
		return EventRecord{}, failure("ConcurrentModificationException", "Event bus encryption configuration changed during admission.")
	}
	if len(p.plain) == 0 {
		return event, nil
	}
	content, sealErr := awsenvelope.Seal(p.plain, p.wrapped, p.keyARN, map[string]string{"aws:events:event-bus:arn": event.Bus.ARN()}, []byte(body))
	if sealErr != nil {
		return EventRecord{}, sealErr
	}
	event.Payload = ArchivePayload{Content: content, DataKey: p.wrapped}
	event.KeyARN, event.BusDeadLetterARN = p.keyARN, p.deadLetterARN
	event.Detail = ""
	return event, nil
}

func (s *Service) openBusEvent(ctx context.Context, event EventRecord, delivery DeliveryRecord) (EventRecord, DeliveryRecord, *awswire.Error) {
	if len(event.Payload.DataKey) != 0 {
		if s.busKeys == nil {
			return event, delivery, unsupported("No event bus KMS provider is configured.")
		}
		plain, rejected := s.busKeys.DecryptBusDataKey(ctx, event.Bus, event.Payload.DataKey)
		if rejected != nil {
			return event, delivery, rejected
		}
		defer clear(plain)
		body, err := awsenvelope.Open(plain, event.Payload.DataKey, event.KeyARN, map[string]string{"aws:events:event-bus:arn": event.Bus.ARN()}, event.Payload.Content)
		if err != nil {
			return event, delivery, failure("InternalException", "Unable to decrypt encrypted event.", 500)
		}
		var document eventDocument
		if err := json.Unmarshal(body, &document); err != nil {
			return event, delivery, failure("InternalException", "Invalid encrypted event.", 500)
		}
		event.Detail = string(document.Detail)
	}
	if len(delivery.TargetConfiguration) != 0 {
		aead, rejected := s.configurationCipher(ctx, BusRecord{Key: event.Bus, ConfigurationDataKey: event.ConfigurationDataKey}, false)
		if rejected != nil {
			return event, delivery, rejected
		}
		target, err := openTargetConfiguration(TargetRecord{EncryptedConfiguration: delivery.TargetConfiguration}, aead)
		if err != nil {
			return event, delivery, wireError(err)
		}
		delivery.MessageGroupID = target.MessageGroupID
		delivery.EcsParameters, delivery.KinesisParameters = target.EcsParameters, target.KinesisParameters
		delivery.HttpParameters = target.HttpParameters
		if delivery.ArchiveID == "" && (target.Input.Input != nil || target.Input.InputPath != nil || target.Input.Transformer != nil) {
			projection, err := inputtransform.Compile(target.Input)
			if err != nil {
				return event, delivery, wireError(err)
			}
			body, err := eventBody(event)
			if err != nil {
				return event, delivery, wireError(err)
			}
			projected, err := projection.Apply([]byte(body), inputtransform.Context{RuleARN: delivery.RuleARN, RuleName: target.Rule.Name, IngestionTime: event.Accepted})
			delivery.Input, delivery.HasInput = string(projected), true
			if err != nil {
				if errors.Is(err, inputtransform.ErrInvalidJSON) {
					return event, delivery, failure("INVALID_JSON", "Invalid input for target.")
				}
				return event, delivery, wireError(err)
			}
		}
	}
	return event, delivery, nil
}

// Encrypted failures retain the original wrapped key and ciphertext, not a
// plaintext copy or a payload re-encrypted under the bus's current key.
func encryptedBusDeadLetter(event EventRecord) (EventRecord, error) {
	detail, err := json.Marshal(struct {
		BusARN  string `json:"event-bus-arn"`
		KeyARN  string `json:"kms-key-arn"`
		Payload string `json:"encrypted-payload"`
	}{event.Bus.ARN(), event.KeyARN, base64.StdEncoding.EncodeToString(event.Payload.Content)})
	if err != nil {
		return EventRecord{}, err
	}
	event.Source, event.DetailType, event.Detail = "aws.events", "Encrypted Events", string(detail)
	event.Resources = nil
	return event, nil
}
