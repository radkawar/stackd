package dynamodb

import (
	"context"
	"net/http"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/dynamodbstreams"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Streams is the second protocol frontend of the DynamoDB resource owner.
type Streams struct{ s *Service }

func (s *Service) Streams() *Streams { return &Streams{s: s} }
func (*Streams) Operations() []string {
	return []string{"DescribeStream", "GetRecords", "GetShardIterator", "ListStreams"}
}
func (p *Streams) RequestError(action string, err error) *awswire.Error {
	return p.s.RequestError(action, err)
}
func (p *Streams) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, rejected *awswire.Error) error {
	return p.record(ctx, string(r.Operation.Name), r.Input, nil, rejected)
}
func (p *Streams) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerError", "Missing generated DynamoDB Streams request binding.", 500))
		return
	}
	out, rejected := p.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("dynamodbstreams")
	body, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (p *Streams) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	switch in := decoded.Input.(type) {
	case *api.ListStreamsInput:
		return p.ListStreams(ctx, in)
	case *api.DescribeStreamInput:
		return p.DescribeStream(ctx, in)
	case *api.GetShardIteratorInput:
		return p.GetShardIterator(ctx, in)
	case *api.GetRecordsInput:
		return p.GetRecords(ctx, in)
	default:
		return nil, failure("UnknownOperationException", "The requested DynamoDB Streams operation is not recognized.")
	}
}
func (p *Streams) record(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if p.s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("dynamodbstreams")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: true}
	if action == "GetRecords" || action == "GetShardIterator" {
		projection.Category = journal.CategoryData
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventSource = "dynamodb.amazonaws.com"
	call.APIVersion = "2012-08-10"
	call.EventID = apievents.EventID(ctx)
	a := auditCall{service: p.s, ctx: ctx, model: model}
	var resource string
	switch v := in.(type) {
	case *api.ListStreamsInput:
		a.resource(value(v.TableName), "")
	case *api.DescribeStreamInput:
		resource = value(v.StreamArn)
	case *api.GetShardIteratorInput:
		resource = value(v.StreamArn)
	case *api.GetRecordsInput:
		if v != nil {
			it, err := decodeStreamIterator(value(v.ShardIterator))
			if err == nil && it.Scope == scopeFor(ctx) {
				resource = it.StreamARN
			}
		}
	}
	a.resource(resource, "")
	call.EventResources = a.resources
	for _, r := range a.resources {
		call.Resources = append(call.Resources, journal.APIResource{Type: r.Type, Name: r.ARN})
	}
	scope := scopeFor(ctx)
	if len(a.resourceScopes) > 0 {
		scope = a.resourceScopes[0]
	}
	return p.s.recorder.Record(ctx, journal.Envelope{At: p.s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
