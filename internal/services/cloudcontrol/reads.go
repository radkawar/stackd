package cloudcontrol

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	api "stackd/internal/awsapi/cloudcontrol"
	"stackd/internal/services/cloudformation"
)

func (s *Service) get(ctx context.Context, in *api.GetResourceInput) (*api.GetResourceOutput, error) {
	_, reader, err := s.handler(text(in.TypeName), text(in.TypeVersionId))
	if err != nil {
		return nil, err
	}
	commandCtx, err := s.roleContext(ctx, "", text(in.RoleArn))
	if err != nil {
		return nil, err
	}
	r := cloudformation.ResourceRequest{Type: text(in.TypeName), PhysicalID: text(in.Identifier), Scope: scopeFor(ctx), CloudControl: true}
	properties, err := reader.Read(commandCtx, r)
	if err != nil {
		return nil, readError(err)
	}
	identifier, err := cloudformation.ResourceIdentifier(r.Type, properties)
	if err != nil {
		return nil, err
	}
	return &api.GetResourceOutput{TypeName: in.TypeName, ResourceDescription: &api.ResourceDescription{Identifier: new(api.Identifier(identifier)), Properties: new(api.Properties(encode(properties)))}}, nil
}
func (s *Service) list(ctx context.Context, in *api.ListResourcesInput) (*api.ListResourcesOutput, error) {
	_, reader, err := s.handler(text(in.TypeName), text(in.TypeVersionId))
	if err != nil {
		return nil, err
	}
	if in.ResourceModel != nil {
		p, err := document(text(in.ResourceModel))
		if err != nil {
			return nil, err
		}
		if len(p) > 0 {
			return nil, failure("UnsupportedActionException", "Resource-model list filters are not implemented for this resource type.")
		}
	}
	commandCtx, err := s.roleContext(ctx, "", text(in.RoleArn))
	if err != nil {
		return nil, err
	}
	rows, err := reader.List(commandCtx, cloudformation.ResourceRequest{Type: text(in.TypeName), Scope: scopeFor(ctx), CloudControl: true})
	if err != nil {
		return nil, readError(err)
	}
	slices.SortFunc(rows, func(a, b cloudformation.ResourceDescription) int { return cmp.Compare(a.Identifier, b.Identifier) })
	rows, next, err := page(scopeFor(ctx), "ListResources", []any{in.TypeName, in.RoleArn, in.ResourceModel}, text(in.NextToken), in.MaxResults, rows, func(v cloudformation.ResourceDescription) string { return v.Identifier })
	if err != nil {
		return nil, err
	}
	out := &api.ListResourcesOutput{TypeName: in.TypeName, ResourceDescriptions: api.ResourceDescriptions{}}
	if next != "" {
		out.NextToken = new(api.HandlerNextToken(next))
	}
	for _, v := range rows {
		out.ResourceDescriptions = append(out.ResourceDescriptions, api.ResourceDescription{Identifier: new(api.Identifier(v.Identifier)), Properties: new(api.Properties(encode(v.Properties)))})
	}
	return out, nil
}
func (s *Service) find(r Reader, token string) (RequestRecord, error) {
	op, err := r.Request(token)
	if errors.Is(err, ErrNotFound) || err == nil && (op.Scope != scopeFor(r.Context()) || !s.clock.Now().Before(op.Created.Add(7*24*time.Hour))) {
		return RequestRecord{}, failure("RequestTokenNotFoundException", "Request token does not exist or has expired.")
	}
	return op, err
}
func (s *Service) status(ctx context.Context, in *api.GetResourceRequestStatusInput) (*api.GetResourceRequestStatusOutput, error) {
	var op RequestRecord
	err := s.repository.View(ctx, func(r Reader) error { var err error; op, err = s.find(r, text(in.RequestToken)); return err })
	if err != nil {
		return nil, err
	}
	return &api.GetResourceRequestStatusOutput{ProgressEvent: progress(op)}, nil
}
func (s *Service) requests(ctx context.Context, in *api.ListResourceRequestsInput) (*api.ListResourceRequestsOutput, error) {
	var rows []RequestRecord
	err := s.repository.View(ctx, func(r Reader) error { var err error; rows, err = r.Requests(scopeFor(ctx)); return err })
	if err != nil {
		return nil, err
	}
	rows = slices.DeleteFunc(rows, func(v RequestRecord) bool {
		if !s.clock.Now().Before(v.Created.Add(7 * 24 * time.Hour)) {
			return true
		}
		filter := in.ResourceRequestStatusFilter
		return filter != nil && (len(filter.Operations) > 0 && !slices.Contains(filter.Operations, api.Operation(v.Operation)) || len(filter.OperationStatuses) > 0 && !slices.Contains(filter.OperationStatuses, api.OperationStatus(v.Status)))
	})
	rows, next, err := page(scopeFor(ctx), "ListResourceRequests", in.ResourceRequestStatusFilter, text(in.NextToken), in.MaxResults, rows, func(v RequestRecord) string { return v.Token })
	if err != nil {
		return nil, err
	}
	out := &api.ListResourceRequestsOutput{ResourceRequestStatusSummaries: api.ResourceRequestStatusSummaries{}}
	if next != "" {
		out.NextToken = new(api.NextToken(next))
	}
	for _, v := range rows {
		out.ResourceRequestStatusSummaries = append(out.ResourceRequestStatusSummaries, *progress(v))
	}
	return out, nil
}
func (s *Service) cancel(ctx context.Context, in *api.CancelResourceRequestInput) (*api.CancelResourceRequestOutput, error) {
	var op RequestRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		op, err = s.find(tx, text(in.RequestToken))
		if err != nil {
			return err
		}
		if op.Status != "PENDING" && op.Status != "IN_PROGRESS" {
			return failure("ValidationException", "Request is already in status "+op.Status)
		}
		// Cancellation prevents further handler calls; it does not compensate
		// committed owner effects or terminate service-owned asynchronous work.
		op.Status = "CANCEL_IN_PROGRESS"
		op.Revision++
		op.EventTime = s.clock.Now()
		op.Due = op.EventTime
		if err := tx.PutRequest(op); err != nil {
			return err
		}
		return s.recordMutation(tx.Context(), progress(op))
	})
	if err != nil {
		return nil, err
	}
	return &api.CancelResourceRequestOutput{ProgressEvent: progress(op)}, nil
}
func page[T any](scope Scope, operation string, filter any, token string, maximum *api.MaxResults, rows []T, key func(T) string) ([]T, string, error) {
	size := 20
	if maximum != nil {
		size = int(*maximum)
	}
	if size < 1 || size > 100 {
		return nil, "", failure("ValidationException", "MaxResults must be between 1 and 100.")
	}
	binding := requestHash([]any{scope, operation, filter})
	after := ""
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		var cursor []string
		if err != nil || json.Unmarshal(raw, &cursor) != nil || len(cursor) != 2 || cursor[0] != binding {
			return nil, "", failure("ValidationException", "Invalid NextToken.")
		}
		after = cursor[1]
	}
	start := 0
	for start < len(rows) && key(rows[start]) <= after {
		start++
	}
	end := min(start+size, len(rows))
	next := ""
	if end < len(rows) {
		raw, _ := json.Marshal([]string{binding, key(rows[end-1])})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return rows[start:end], next, nil
}
