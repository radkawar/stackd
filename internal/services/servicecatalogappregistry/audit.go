package servicecatalogappregistry

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/servicecatalogappregistry"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
)

var applicationIDPattern = regexp.MustCompile(`^[a-z0-9]{26}$`)

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("servicecatalogappregistry")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	readOnly := strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List")
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnly, Request: awsapi.DocumentProjection{PreserveNames: true}}
	if !readOnly {
		projection.Response = &awsapi.DocumentProjection{PreserveNames: true}
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	// Exact native rejection fixtures establish this source, URI-label encoding,
	// resource projection, and operation-specific error body casing.
	call.EventSource = "servicecatalog-appregistry.amazonaws.com"
	call.ErrorMessage = ""
	if action == "GetConfiguration" {
		call.RequestParameters = nil
	} else if len(call.RequestParameters) > 0 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(call.RequestParameters, &fields); err != nil {
			return err
		}
		for _, key := range []string{"application", "attributeGroup", "resource", "resourceArn"} {
			if raw, ok := fields[key]; ok {
				var label string
				if json.Unmarshal(raw, &label) == nil {
					fields[key], err = json.Marshal(url.QueryEscape(label))
					if err != nil {
						return err
					}
				}
			}
		}
		call.RequestParameters, err = json.Marshal(fields)
		if err != nil {
			return err
		}
	}
	if rejected != nil {
		if rejected.Code == "AccessDeniedException" {
			call.ErrorCode = "AccessDenied"
		}
		if !readOnly {
			if rejected.Code == "AccessDeniedException" && strings.HasPrefix(action, "Create") {
				call.ResponseElements, err = json.Marshal(struct{ Message string }{rejected.Message})
			} else {
				call.ResponseElements, err = json.Marshal(struct {
					Message string `json:"message"`
				}{rejected.Message})
			}
			if err != nil {
				return err
			}
		}
	}
	application, attribute := auditTargets(in)
	scope := scopeFor(ctx)
	if application != "" || attribute != "" {
		err = s.repository.View(ctx, func(r Reader) error {
			if attribute != "" {
				arn := auditARN(scope, "attribute-groups", attribute)
				if row, ok, err := r.AttributeGroup(scope, attribute); err != nil {
					return err
				} else if ok {
					arn = row.ARN
				}
				call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: scope.AccountID, Type: "AWS::ServiceCatalogAppRegistry::AttributeGroup", ARN: arn})
			}
			if application != "" {
				arn := auditARN(scope, "applications", application)
				if row, ok, err := r.Application(scope, application); err != nil {
					return err
				} else if ok {
					arn = row.ARN
				}
				call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: scope.AccountID, Type: "AWS::ServiceCatalogAppRegistry::Application", ARN: arn})
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	call.EventID = apievents.EventID(ctx)
	return s.recorder.Record(ctx, journal.Envelope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, At: s.clock.Now()}, call)
}
func auditARN(scope Scope, kind, id string) string {
	if strings.HasPrefix(id, "arn:") {
		return id
	}
	if !applicationIDPattern.MatchString(id) {
		id = "*"
	}
	return resourceARN(scope, kind, id)
}
func auditTargets(input any) (application, attribute string) {
	switch in := input.(type) {
	case *api.GetApplicationRequest:
		if in != nil {
			application = value(in.Application)
		}
	case *api.GetAttributeGroupRequest:
		if in != nil {
			attribute = value(in.AttributeGroup)
		}
	case *api.GetAssociatedResourceRequest:
		if in != nil {
			application = value(in.Application)
		}
	case *api.AssociateResourceRequest:
		if in != nil {
			application = value(in.Application)
		}
	case *api.DisassociateResourceRequest:
		if in != nil {
			application = value(in.Application)
		}
	case *api.AssociateAttributeGroupRequest:
		if in != nil {
			application, attribute = value(in.Application), value(in.AttributeGroup)
		}
	case *api.DisassociateAttributeGroupRequest:
		if in != nil {
			application, attribute = value(in.Application), value(in.AttributeGroup)
		}
	case *api.ListAssociatedResourcesRequest:
		if in != nil {
			application = value(in.Application)
		}
	case *api.ListAssociatedAttributeGroupsRequest:
		if in != nil {
			application = value(in.Application)
		}
	case *api.ListAttributeGroupsForApplicationRequest:
		if in != nil {
			application = value(in.Application)
		}
	}
	return
}
