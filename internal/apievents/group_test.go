package apievents

import (
	"context"
	"reflect"
	"testing"
	"time"

	"stackd/internal/awsctx"
	"stackd/journal"
)

type outcomeSinkFunc func(context.Context, journal.Envelope, journal.APICallCompleted) error

func (f outcomeSinkFunc) AppendAPICallCompleted(ctx context.Context, scope journal.Envelope, call journal.APICallCompleted) error {
	return f(ctx, scope, call)
}

type outcomeGroupFunc func(context.Context, func(context.Context) error) error

func (f outcomeGroupFunc) Do(ctx context.Context, fn func(context.Context) error) error {
	return f(ctx, fn)
}

func TestGroupedRecorderSnapshotsMutableInputBeforeHandoff(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	group := outcomeGroupFunc(func(ctx context.Context, fn func(context.Context) error) error {
		close(entered)
		<-release
		return fn(ctx)
	})
	type callerKey struct{}
	ctx := context.WithValue(t.Context(), callerKey{}, "original caller")
	metadata := awsctx.Metadata{
		RequestID: "request", ParentEventID: "parent", AccountID: "111111111111",
		PrincipalARN: "arn:aws:iam::111111111111:user/caller", SourceIP: "192.0.2.10", UserAgent: "fixture",
	}
	ctx = awsctx.WithMetadata(ctx, metadata)
	scope := journal.Envelope{At: time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC), Partition: "aws", AccountID: metadata.AccountID, Region: "us-east-1"}
	call := journal.APICallCompleted{
		EventID: "event", EventSource: "s3.amazonaws.com", EventName: "GetObject", Category: journal.CategoryData, ReadOnly: true,
		Identity:          journal.APIIdentity{Type: "IAMUser", AccountID: metadata.AccountID, PrincipalID: "caller"},
		RequestParameters: []byte(`{"bucket":"original"}`), ResponseElements: []byte(`{"result":"original"}`),
		Resources:           []journal.APIResource{{Type: "AWS::S3::Object", Name: "original"}},
		EventResources:      []journal.APIEventResource{{Type: "AWS::S3::Object", ARN: "arn:aws:s3:::fixture/original"}},
		AdditionalEventData: []byte(`{"extra":"original"}`), ServiceEventDetails: []byte(`{"detail":"original"}`),
	}
	wantCall := journal.APICallCompleted{
		EventID: "event", EventSource: "s3.amazonaws.com", EventName: "GetObject", Category: journal.CategoryData, ReadOnly: true,
		Identity:        journal.APIIdentity{Type: "IAMUser", AccountID: metadata.AccountID, PrincipalID: "caller"},
		SourceIPAddress: metadata.SourceIP, UserAgent: metadata.UserAgent,
		RequestParameters: []byte(`{"bucket":"original"}`), ResponseElements: []byte(`{"result":"original"}`),
		Resources:           []journal.APIResource{{Type: "AWS::S3::Object", Name: "original"}},
		EventResources:      []journal.APIEventResource{{Type: "AWS::S3::Object", ARN: "arn:aws:s3:::fixture/original"}},
		AdditionalEventData: []byte(`{"extra":"original"}`), ServiceEventDetails: []byte(`{"detail":"original"}`),
	}
	var gotCall journal.APICallCompleted
	var gotScope journal.Envelope
	var gotValue any
	sink := outcomeSinkFunc(func(ctx context.Context, scope journal.Envelope, call journal.APICallCompleted) error {
		gotCall, gotScope, gotValue = call, scope, ctx.Value(callerKey{})
		return nil
	})
	recorder := NewGrouped(sink, group)
	result := make(chan error, 1)
	go func() { result <- recorder.Record(ctx, scope, call) }()
	<-entered
	for _, bytes := range [][]byte{call.RequestParameters, call.ResponseElements, call.AdditionalEventData, call.ServiceEventDetails} {
		for i := range bytes {
			bytes[i] = 'x'
		}
	}
	call.Resources[0].Name = "changed"
	call.EventResources[0].ARN = "changed"
	call.EventName = "changed"
	scope.AccountID = "222222222222"
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotCall, wantCall) {
		t.Fatalf("group retained caller-owned mutable input:\n got %#v\nwant %#v", gotCall, wantCall)
	}
	if gotScope.AccountID != metadata.AccountID || gotScope.RequestID != metadata.RequestID || gotScope.ParentEventID != metadata.ParentEventID || gotScope.ActorARN != metadata.PrincipalARN || gotValue != "original caller" {
		t.Fatalf("group lost original scope/context: %#v, %v", gotScope, gotValue)
	}
}
