package ssmdocuments

import (
	"context"
	"encoding/json"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// recordSuccess reads private audit metadata from the same document transaction,
// never from a fabricated public Smithy response member.
func (s *Service) recordSuccess(tx Transaction, action string, in, out any) error {
	if s.recorder == nil {
		return nil
	}
	var name string
	switch request := in.(type) {
	case *api.CreateDocumentRequest:
		name = value(request.Name)
	case *api.UpdateDocumentRequest:
		name = value(request.Name)
	}
	var id string
	if name != "" {
		key, err := documentKey(tx.Context(), name)
		if err != nil {
			return err
		}
		record, err := tx.Document(key)
		if err != nil {
			return err
		}
		id = record.DocumentID
	}
	return s.record(tx.Context(), action, in, out, nil, id)
}

// Document management captures redact submitted content, omit resource rows,
// and retain only mutation response wrappers. API state and errors are unchanged.
func (s *Service) record(ctx context.Context, action string, in, out any, rejected *awswire.Error, documentID string) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ssm")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
		"Content": {Mode: awsapi.RedactValueField},
	}}}
	switch action {
	case "GetDocument", "DescribeDocument", "ListDocuments", "ListDocumentVersions", "ListTagsForResource", "DescribeDocumentPermission":
		projection.ReadOnly = true
	case "CreateDocument", "UpdateDocument":
		projection.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"DocumentDescription.CreatedDate": {TimeLayout: time.RFC3339},
		}}
	case "UpdateDocumentDefaultVersion":
		projection.Response = &awsapi.DocumentProjection{}
	}
	if request, ok := in.(*api.CreateDocumentRequest); ok && request != nil && value(request.DocumentType) == "Command" {
		projection.Request.Fields["DocumentType"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	if rejected == nil && (action == "CreateDocument" || action == "UpdateDocument") {
		var response map[string]json.RawMessage
		if err = json.Unmarshal(call.ResponseElements, &response); err != nil {
			return err
		}
		var description map[string]json.RawMessage
		if err = json.Unmarshal(response["documentDescription"], &description); err != nil {
			return err
		}
		description["documentId"], err = json.Marshal(documentID)
		if err != nil {
			return err
		}
		response["documentDescription"], err = json.Marshal(description)
		if err != nil {
			return err
		}
		call.ResponseElements, err = json.Marshal(response)
		if err != nil {
			return err
		}
	}
	if rejected != nil && rejected.Code == "ThrottlingException" && (action == "CreateDocument" || action == "UpdateDocument" || action == "DeleteDocument") {
		// Observed frontend throttles precede parameter binding.
		call.RequestParameters = nil
	} else if action == "GetDocument" && len(call.RequestParameters) > 0 {
		// This native audit default is not a public GetDocument input member.
		var request map[string]json.RawMessage
		if err = json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if request != nil {
			request["allowInvalidContent"] = json.RawMessage("false")
			call.RequestParameters, err = json.Marshal(request)
			if err != nil {
				return err
			}
		}
	}
	sc := scopeFor(ctx)
	call.EventID = apievents.EventID(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
