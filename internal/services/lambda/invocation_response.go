package lambda

import (
	"bytes"
	"context"
	"sync"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func encodeResponse(ctx context.Context, model awscatalog.Service, operation awscatalog.Operation, output any) (awsapi.HTTPResponse, *awswire.Error) {
	var response awsapi.HTTPResponse
	var err error
	if out, ok := output.(interface {
		encodeHTTP(awscatalog.Service, awscatalog.Operation) (awsapi.HTTPResponse, error)
	}); ok {
		response, err = out.encodeHTTP(model, operation)
	} else {
		response, err = awsapi.EncodeHTTPResponse(model, operation, output)
	}
	if err != nil {
		return awsapi.HTTPResponse{}, failure("ServiceException", "Unable to encode Lambda response.", 500)
	}
	response.Header.Set("X-Amzn-Requestid", awsctx.FromContext(ctx).RequestID)
	return response, nil
}

// Invocation transport metadata is not part of the modeled JSON/blob output.
// The execution owner retains one output for synchronous and asynchronous callers.
type invocationOutput struct {
	api.InvokeOutput
	streamed           bool
	runtimeContentType string
}

func (out *invocationOutput) encodeHTTP(model awscatalog.Service, operation awscatalog.Operation) (awsapi.HTTPResponse, error) {
	response, err := awsapi.EncodeHTTPResponse(model, operation, &out.InvokeOutput)
	if err != nil {
		return response, err
	}
	if response.StatusCode == 202 || response.StatusCode == 204 {
		response.Header.Del("Content-Type")
	} else if out.streamed && len(out.Payload) != 0 && out.FunctionError == nil {
		response.Header.Set("Content-Type", "application/octet-stream")
	} else {
		response.Header.Set("Content-Type", "application/json")
	}
	return response, nil
}

func (out *invocationOutput) modeledOutput() any { return &out.InvokeOutput }

// The runtime produces chunks; a separate consumer owns final output delivery.
// A slow client cannot hold an execution lease after the response phase ends.
type invocationStream struct {
	ctx             context.Context
	cancel          context.CancelFunc
	output          api.InvokeWithResponseStreamOutput
	contentType     string
	streamed        bool
	bufferedPayload []byte
	events          chan api.InvokeWithResponseStreamResponseEvent
	response        chan executionResponse
	completed       chan executionResponse
	published       sync.Once
}

func (s *Service) invokeWithResponseStream(ctx context.Context, in *api.InvokeWithResponseStreamInput) (*invocationStream, *awswire.Error) {
	stream := newInvocationStream(ctx)
	if _, wire := s.submitInvocation(ctx, streamingInvocationInput(in), stream, invocationOptions{}); wire != nil {
		stream.cancel()
		return nil, wire
	}
	return stream, nil
}

func newInvocationStream(ctx context.Context) *invocationStream {
	ctx, cancel := context.WithCancel(ctx)
	events := make(chan api.InvokeWithResponseStreamResponseEvent, 1)
	return &invocationStream{
		ctx: ctx, cancel: cancel, events: events, completed: make(chan executionResponse, 1),
		output: api.InvokeWithResponseStreamOutput{EventStream: events, StatusCode: new(api.Integer(200)), ResponseStreamContentType: new(api.String("application/vnd.amazon.eventstream"))},
	}
}

// Both API shapes submit the same invocation command. Native streaming calls
// ignore InvocationType, including DryRun and Event; submitInvocation owns that
// difference. Keep the original header for API event projection.
func streamingInvocationInput(in *api.InvokeWithResponseStreamInput) *api.InvokeInput {
	if in == nil {
		return nil
	}
	out := &api.InvokeInput{FunctionName: in.FunctionName, Qualifier: in.Qualifier, Payload: in.Payload, ClientContext: in.ClientContext, LogType: in.LogType, TenantId: in.TenantId}
	if in.InvocationType != nil {
		out.InvocationType = new(api.InvocationType(*in.InvocationType))
	}
	return out
}

func (s *invocationStream) encodeHTTP(model awscatalog.Service, operation awscatalog.Operation) (awsapi.HTTPResponse, error) {
	response, err := awsapi.EncodeHTTPResponse(model, operation, &s.output)
	if err == nil && s.contentType != "" {
		response.Header.Set("X-Amzn-Remapped-Content-Type", s.contentType)
	}
	return response, err
}

func (s *invocationStream) modeledOutput() any { return &s.output }

func (s *invocationStream) publish(contentType string, streamed bool, payload []byte, wire *awswire.Error) {
	s.published.Do(func() {
		s.contentType = contentType
		s.streamed = streamed
		if !streamed {
			s.bufferedPayload = payload
		}
		s.response <- executionResponse{output: &invocationOutput{InvokeOutput: api.InvokeOutput{StatusCode: s.output.StatusCode, ExecutedVersion: s.output.ExecutedVersion}}, wire: wire}
	})
}

func (s *invocationStream) write(ctx context.Context, contentType string, payload []byte) error {
	s.publish(contentType, true, nil, nil)
	if len(payload) == 0 || s.ctx.Err() != nil {
		return nil
	}
	// The typed channel transfers ownership. The backend reuses its read buffer.
	event := api.InvokeWithResponseStreamResponseEvent{PayloadChunk: &api.InvokeResponseStreamUpdate{Payload: api.Blob(bytes.Clone(payload))}}
	select {
	case s.events <- event:
		return nil
	case <-s.ctx.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *invocationStream) finish() {
	defer s.cancel()
	defer close(s.events)
	result := <-s.completed
	if result.wire != nil {
		s.publish("", false, nil, result.wire)
	} else {
		s.publish(result.output.runtimeContentType, result.output.streamed, result.output.Payload, nil)
		for payload := []byte(result.output.Payload); len(payload) != 0; {
			n := min(len(payload), 32<<10)
			_ = s.write(s.ctx, result.output.runtimeContentType, payload[:n])
			payload = payload[n:]
		}
	}
	complete := &api.InvokeWithResponseStreamCompleteEvent{}
	if result.output != nil {
		complete.LogResult = result.output.LogResult
	}
	if result.wire != nil {
		// A backend failure after bytes were accepted cannot replace HTTP status.
		complete.ErrorCode = new(api.String(result.wire.Code))
		complete.ErrorDetails = new(api.String(result.wire.Message))
	}
	select {
	case s.events <- api.InvokeWithResponseStreamResponseEvent{InvokeComplete: complete}:
	case <-s.ctx.Done():
	}
}
