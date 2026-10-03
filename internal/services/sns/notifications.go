package sns

import (
	"encoding/base64"
	"encoding/json"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
)

type notificationAttribute struct {
	Type  string `json:"Type"`
	Value string `json:"Value"`
}

// Protocols share these notification fields; signing, subscription URL spelling
// and optional-field presence follow each transport's native envelope.
type notificationContent struct {
	Type             string `json:"Type"`
	MessageID        string `json:"MessageId"`
	TopicARN         string `json:"TopicArn"`
	Message          string `json:"Message"`
	Timestamp        string `json:"Timestamp"`
	SignatureVersion string `json:"SignatureVersion,omitempty"`
	Signature        string `json:"Signature,omitempty"`
}

type notification struct {
	notificationContent
	SigningCertURL    string                           `json:"SigningCertURL,omitempty"`
	Subject           *string                          `json:"Subject,omitempty"`
	UnsubscribeURL    string                           `json:"UnsubscribeURL"`
	MessageAttributes map[string]notificationAttribute `json:"MessageAttributes,omitempty"`
	SequenceNumber    string                           `json:"SequenceNumber,omitempty"`
	Replayed          string                           `json:"Replayed,omitempty"`
}

type lambdaNotification struct {
	notificationContent
	SigningCertURL    string                           `json:"SigningCertUrl"`
	Subject           *string                          `json:"Subject"`
	UnsubscribeURL    string                           `json:"UnsubscribeUrl"`
	MessageAttributes map[string]notificationAttribute `json:"MessageAttributes"`
}

type lambdaConfirmation struct {
	notificationContent
	Token          string `json:"Token"`
	SubscribeURL   string `json:"SubscribeUrl"`
	SigningCertURL string `json:"SigningCertUrl"`
}

type lambdaNotificationRecord[T any] struct {
	EventVersion         string  `json:"EventVersion"`
	EventSubscriptionARN *string `json:"EventSubscriptionArn"`
	EventSource          string  `json:"EventSource"`
	SNS                  T       `json:"Sns"`
}

func lambdaEnvelope[T any](subscriptionARN *string, message T) any {
	return struct {
		Records []lambdaNotificationRecord[T] `json:"Records"`
	}{Records: []lambdaNotificationRecord[T]{{EventVersion: "1.0", EventSubscriptionARN: subscriptionARN, EventSource: "aws:sns", SNS: message}}}
}

func (s *Service) deliveryPayload(message MessageRecord, sub SubscriptionRecord, deadLetter, replayed bool) (string, api.MessageAttributeMap, *awswire.Error) {
	if message.Type != "" {
		confirmation := struct {
			notificationContent
			Token          string `json:"Token"`
			SubscribeURL   string `json:"SubscribeURL"`
			SigningCertURL string `json:"SigningCertURL"`
		}{notificationContent: notificationContent{Type: message.Type, MessageID: message.Key.ID, TopicARN: message.Topic.ARN(), Message: message.Body, Timestamp: notificationTimestamp(message.Published), SignatureVersion: message.SignatureVersion, Signature: message.Signature}, Token: message.Token, SubscribeURL: message.SubscribeURL, SigningCertURL: s.certificateURL(message.SigningKeyID)}
		var document any
		if !deadLetter && sub.Protocol == "lambda" {
			document = lambdaEnvelope(nil, lambdaConfirmation{notificationContent: confirmation.notificationContent, Token: message.Token, SubscribeURL: message.SubscribeURL, SigningCertURL: confirmation.SigningCertURL})
		} else {
			document = confirmation
		}
		encoded, err := json.Marshal(document)
		return string(encoded), nil, wireError(err)
	}
	if !deadLetter && sub.RawMessageDelivery && (sub.Protocol == "http" || sub.Protocol == "https" || sub.Protocol == "firehose") {
		return message.Body, nil, nil
	}
	if sub.Protocol == "sqs" && sub.RawMessageDelivery {
		if len(message.Attributes) > 10 {
			return "", nil, failure("InvalidParameter", "Raw SQS delivery supports at most 10 message attributes.")
		}
		return message.Body, message.Attributes, nil
	}
	content := notificationContent{Type: "Notification", MessageID: message.Key.ID, TopicARN: message.Topic.ARN(), Message: message.Body, Timestamp: notificationTimestamp(message.Published), SignatureVersion: message.SignatureVersion, Signature: message.Signature}
	certificate := s.certificateURL(message.SigningKeyID)
	if message.SequenceNumber != "" || !deadLetter && sub.Protocol == "firehose" {
		content.SignatureVersion, content.Signature, certificate = "", "", ""
	}
	attributes := make(map[string]notificationAttribute, len(message.Attributes))
	for name, attribute := range message.Attributes {
		v := notificationAttribute{Type: value(attribute.DataType), Value: value(attribute.StringValue)}
		if v.Type == "Binary" {
			v.Value = base64.StdEncoding.EncodeToString(attribute.BinaryValue)
		}
		if !deadLetter && sub.Protocol == "lambda" && (v.Type == "Number" || v.Type == "String.Array") {
			v.Type = "String"
		}
		attributes[string(name)] = v
	}
	unsubscribe := s.unsubscribeURL(sub.Key)
	var document any
	if !deadLetter && sub.Protocol == "lambda" {
		subscriptionARN := sub.Key.ARN()
		document = lambdaEnvelope(&subscriptionARN, lambdaNotification{notificationContent: content, SigningCertURL: certificate, Subject: message.Subject, UnsubscribeURL: unsubscribe, MessageAttributes: attributes})
	} else {
		sequence := message.SequenceNumber
		if message.Structured {
			sequence = ""
		}
		replayedValue := ""
		if replayed {
			replayedValue = "true"
		}
		document = notification{notificationContent: content, SigningCertURL: certificate, Subject: message.Subject, UnsubscribeURL: unsubscribe, MessageAttributes: attributes, SequenceNumber: sequence, Replayed: replayedValue}
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", nil, wireError(err)
	}
	if !deadLetter && sub.Protocol == "firehose" {
		return string(encoded) + "\n", nil, nil
	}
	return string(encoded), nil, nil
}
