package awsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream/eventstreamapi"

	"stackd/internal/awscatalog"
)

// checkEventStream supports JSON document events, modeled exceptions, and single
// raw blob eventPayloads. Other bindings must acquire their own implementation.
func checkEventStream(service awscatalog.Service, stream awscatalog.Shape) error {
	if service.Protocol != awscatalog.RestJSON && service.Protocol != awscatalog.AWSJSON11 {
		return fmt.Errorf("%w: %s event stream %s", ErrUnsupportedBinding, service.Protocol, stream.ID)
	}
	for _, event := range stream.Members {
		shape, ok := service.Shape(event.Target)
		if !ok {
			return fmt.Errorf("missing generated shape %s", event.Target)
		}
		if shape.Kind != "structure" {
			return fmt.Errorf("%w: event %s", ErrUnsupportedBinding, shape.ID)
		}
		for _, member := range shape.Members {
			if member.EventHeader || !documentMember(member, true) {
				return fmt.Errorf("%w: event member %s.%s", ErrUnsupportedBinding, shape.ID, member.Name)
			}
			if member.EventPayload {
				target, ok := service.Shape(member.Target)
				if !ok || target.Kind != "blob" || target.MediaType != "" || len(shape.Members) != 1 {
					return fmt.Errorf("%w: event payload %s.%s", ErrUnsupportedBinding, shape.ID, member.Name)
				}
			}
		}
	}
	return nil
}

// encodeJSONEventStreamResponse recognizes the streaming union by its model
// trait, not HTTPPayload: AWS JSON has no HTTP payload member binding.
func encodeJSONEventStreamResponse(service awscatalog.Service, operation awscatalog.Operation, output any) (HTTPResponse, bool, error) {
	shape, ok := service.Shape(operation.Output)
	if !ok {
		return HTTPResponse{}, false, nil
	}
	var stream *awscatalog.Member
	for i := range shape.Members {
		member := &shape.Members[i]
		target, _ := service.Shape(member.Target)
		if target.Streaming && target.Kind == "union" {
			if stream != nil {
				return HTTPResponse{}, true, fmt.Errorf("%w: multiple output event streams", ErrUnsupportedBinding)
			}
			stream = member
		}
	}
	if stream == nil {
		return HTTPResponse{}, false, nil
	}
	target, _ := service.Shape(stream.Target)
	if err := checkEventStream(service, target); err != nil {
		return HTTPResponse{}, true, err
	}
	fields, err := smithyFields(reflect.ValueOf(output), shape.ID)
	if err != nil {
		return HTTPResponse{}, true, err
	}
	document := make(map[string]json.RawMessage, len(shape.Members)-1)
	var events reflect.Value
	for _, member := range shape.Members {
		field, ok := fields[member.Name]
		if !ok {
			return HTTPResponse{}, true, fmt.Errorf("output %s missing generated member %s", shape.ID, member.Name)
		}
		if member.Name == stream.Name {
			events = indirectHTTPValue(field)
			if events.Kind() != reflect.Chan || events.IsNil() || events.Type().ChanDir() == reflect.SendDir || events.Type().Elem().Kind() != reflect.Struct {
				return HTTPResponse{}, true, outputTypeError(member.Target, events)
			}
			continue
		}
		encoded, err := encodeJSONMember(service, member, field, documentPosition{response: true})
		if err != nil {
			return HTTPResponse{}, true, err
		}
		if encoded != nil {
			document[memberJSONName(member)] = encoded
		}
	}
	initial, err := json.Marshal(document)
	if err != nil {
		return HTTPResponse{}, true, err
	}
	return HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/vnd.amazon.eventstream"}},
		Stream:     encodeEventStream(service, target, events, initial),
	}, true, nil
}

func encodeEventStream(service awscatalog.Service, shape awscatalog.Shape, events reflect.Value, initial []byte) func(context.Context, http.ResponseWriter) error {
	return func(ctx context.Context, writer http.ResponseWriter) error {
		controller := http.NewResponseController(writer)
		// A real net/http transport supports write deadlines. Expiring the deadline
		// interrupts a write or flush blocked on a disconnected/slow consumer.
		// Wait for a running callback before returning ownership of the writer.
		interrupted := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(interrupted)
			_ = controller.SetWriteDeadline(time.Now())
		})
		defer func() {
			if !stop() {
				<-interrupted
			}
		}()
		encoder := eventstream.NewEncoder()
		writeMessage := func(message eventstream.Message) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			err := encoder.Encode(writer, message)
			if err == nil {
				err = controller.Flush()
			}
			if canceled := ctx.Err(); canceled != nil {
				return canceled
			}
			return err
		}
		if initial != nil {
			if err := writeMessage(eventstream.Message{
				Headers: eventMessageHeaders(eventstreamapi.EventMessageType, eventstreamapi.EventTypeHeader, "initial-response", "application/x-amz-json-1.1"),
				Payload: initial,
			}); err != nil {
				return err
			}
		}
		cases := []reflect.SelectCase{
			{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())},
			{Dir: reflect.SelectRecv, Chan: events},
		}
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			chosen, value, open := reflect.Select(cases)
			if chosen == 0 {
				return ctx.Err()
			}
			if !open {
				return ctx.Err()
			}
			message, err := encodeEventMessage(service, shape, value)
			if err != nil {
				return err
			}
			if err := writeMessage(message); err != nil {
				return err
			}
			if message.Headers.Get(eventstreamapi.MessageTypeHeader).String() == eventstreamapi.ExceptionMessageType {
				return nil
			}
		}
	}
}

func encodeEventMessage(service awscatalog.Service, stream awscatalog.Shape, value reflect.Value) (eventstream.Message, error) {
	fields, err := smithyFields(value, stream.ID)
	if err != nil {
		return eventstream.Message{}, err
	}
	var selected *awscatalog.Member
	var event reflect.Value
	for i := range stream.Members {
		member := &stream.Members[i]
		field, ok := fields[member.Name]
		if !ok {
			return eventstream.Message{}, fmt.Errorf("output %s missing generated member %s", stream.ID, member.Name)
		}
		if nilValue(field) {
			continue
		}
		if selected != nil {
			return eventstream.Message{}, fmt.Errorf("output union %s must have one member", stream.ID)
		}
		selected, event = member, field
	}
	if selected == nil {
		return eventstream.Message{}, fmt.Errorf("output union %s must have one member", stream.ID)
	}
	shape, _ := service.Shape(selected.Target)
	contentType := "application/json"
	if service.Protocol == awscatalog.AWSJSON11 {
		contentType = "application/x-amz-json-1.1"
	}
	var payload []byte
	if len(shape.Members) == 1 && shape.Members[0].EventPayload {
		member := shape.Members[0]
		fields, err := smithyFields(event, shape.ID)
		if err != nil {
			return eventstream.Message{}, err
		}
		field, ok := fields[member.Name]
		if !ok {
			return eventstream.Message{}, fmt.Errorf("output %s missing generated member %s", shape.ID, member.Name)
		}
		if !nilValue(field) {
			field = indirectHTTPValue(field)
			if field.Kind() != reflect.Slice || field.Type().Elem().Kind() != reflect.Uint8 {
				return eventstream.Message{}, outputTypeError(member.Target, field)
			}
			payload = field.Bytes()
		}
		contentType = "application/octet-stream"
	} else {
		payload, err = encodeValue(service, shape.ID, event, selected.TimestampFormat, documentPosition{response: true})
		if err != nil {
			return eventstream.Message{}, err
		}
	}
	messageType, typeHeader := eventstreamapi.EventMessageType, eventstreamapi.EventTypeHeader
	if shape.Error.Fault != "" {
		messageType, typeHeader = eventstreamapi.ExceptionMessageType, eventstreamapi.ExceptionTypeHeader
	}
	return eventstream.Message{
		Headers: eventMessageHeaders(messageType, typeHeader, selected.Name, contentType),
		Payload: payload,
	}, nil
}

func eventMessageHeaders(messageType, typeHeader, name, contentType string) eventstream.Headers {
	return eventstream.Headers{
		{Name: eventstreamapi.MessageTypeHeader, Value: eventstream.StringValue(messageType)},
		{Name: typeHeader, Value: eventstream.StringValue(name)},
		{Name: eventstreamapi.ContentTypeHeader, Value: eventstream.StringValue(contentType)},
	}
}
