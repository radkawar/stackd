// Package ssmfrontend dispatches generated public SSM requests to their named
// state owners. Parameter Store does not acquire document or fleet state.
package ssmfrontend

import (
	"context"
	"net/http"
	"slices"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/services/ssm"
	"stackd/internal/services/ssmcommands"
	"stackd/internal/services/ssmdocuments"
)

type owner interface {
	Operations() []string
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	RecordRequestError(context.Context, awsapi.DecodedRequest, *awswire.Error) error
}
type Service struct {
	parameters *ssm.Service
	documents  *ssmdocuments.Service
	commands   *ssmcommands.Service
	owners     map[string]owner
}

func New(parameters *ssm.Service, documents *ssmdocuments.Service, commands *ssmcommands.Service) *Service {
	s := &Service{parameters: parameters, documents: documents, commands: commands, owners: map[string]owner{}}
	for _, provider := range []owner{parameters, documents, commands} {
		for _, action := range provider.Operations() {
			// Shared tagging operations default to Parameter Store. Their generated
			// ResourceType selects the document owner below, including rejected input.
			if _, exists := s.owners[action]; !exists {
				s.owners[action] = provider
			}
		}
	}
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.owners))
	for action := range s.owners {
		out = append(out, action)
	}
	slices.Sort(out)
	return out
}
func (s *Service) requestOwner(request awsapi.DecodedRequest) owner {
	var resourceType *api.ResourceTypeForTagging
	switch in := request.Input.(type) {
	case *api.AddTagsToResourceRequest:
		if in != nil {
			resourceType = in.ResourceType
		}
	case *api.RemoveTagsFromResourceRequest:
		if in != nil {
			resourceType = in.ResourceType
		}
	case *api.ListTagsForResourceRequest:
		if in != nil {
			resourceType = in.ResourceType
		}
	}
	if resourceType != nil && *resourceType == "Document" {
		return s.documents
	}
	if provider, ok := s.owners[string(request.Operation.Name)]; ok {
		return provider
	}
	return s.parameters
}
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	return s.requestOwner(request).ExecuteCommand(ctx, request)
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.requestOwner(request).RecordRequestError(ctx, request, rejected)
}
func (s *Service) RequestError(action string, err error) *awswire.Error {
	return s.parameters.RequestError(action, err)
}

// RequestErrorInput retains modeled authenticated input for native audit even
// when ordinary Smithy validation rejects it. It never admits the operation.
func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	input, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ssm")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}

// PrivateOperation is consulted only after the gateway's signature, scope and
// body checks, before public Smithy dispatch.
func (s *Service) PrivateOperation(r *http.Request) (string, bool) {
	return "UpdateInstanceInformation", ssmcommands.HandlesAgentRequest(r)
}
func (s *Service) ServePrivateOperation(w http.ResponseWriter, r *http.Request) {
	s.commands.ServeAgentHTTP(w, r)
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, &awswire.Error{Code: "InternalServerError", Message: "Missing generated request binding.", StatusCode: 500})
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("ssm")
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, &awswire.Error{Code: "InternalServerError", Message: "Unable to encode SSM response.", StatusCode: 500})
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
