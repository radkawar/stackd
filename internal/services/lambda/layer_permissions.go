package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/google/uuid"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func loadLayerPermissionDocument(r LayerReader, key LayerVersionKey) (LayerPolicy, permissionDocument, error) {
	current, err := r.LayerPolicy(key)
	if errors.Is(err, ErrNotFound) {
		return LayerPolicy{Key: key, PrincipalIDs: map[string]string{}}, permissionDocument{Version: "2012-10-17", ID: "default", Statements: []permissionStatement{}}, nil
	}
	if err != nil {
		return LayerPolicy{}, permissionDocument{}, err
	}
	var document permissionDocument
	err = json.Unmarshal([]byte(current.Document), &document)
	return current, document, err
}
func (s *Service) addLayerVersionPermission(ctx context.Context, in *api.AddLayerVersionPermissionInput) (*api.AddLayerVersionPermissionOutput, *awswire.Error) {
	key, wire := layerVersionKey(ctx, value(in.LayerName), in.VersionNumber)
	if wire != nil {
		return nil, wire
	}
	principal, wire := permissionPrincipal(key.Partition, value(in.Principal))
	if wire != nil {
		return nil, wire
	}
	statement := permissionStatement{Sid: value(in.StatementId), Effect: "Allow", Principal: principal, Action: value(in.Action), Resource: key.ARN()}
	if in.OrganizationId != nil {
		statement.Condition = map[string]map[string]string{"StringEquals": {"aws:PrincipalOrgID": value(in.OrganizationId)}}
	}
	out := &api.AddLayerVersionPermissionOutput{}
	owner, wire := layerPermissionOwnerFor(ctx)
	if wire != nil {
		return nil, wire
	}
	permissionKey := LayerPermissionKey{LayerVersionKey: key, StatementID: statement.Sid}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := loadLayer(tx, key); err != nil {
			return err
		}
		current, document, err := loadLayerPermissionDocument(tx, key)
		if err != nil {
			return err
		}
		if wire := s.authorizeLayer(tx, "AddLayerVersionPermission", key, map[string][]string{"lambda:Principal": {value(in.Principal)}}); wire != nil {
			return wire
		}
		for _, existing := range document.Statements {
			if existing.Sid == statement.Sid {
				if owner != (LayerPermissionOwner{}) {
					if err := requireLayerPermissionOwner(tx, permissionKey, owner); err != nil {
						return err
					}
					if s.binder == nil {
						return unsupported("The configured authorizer does not support resource policy principal rendering.")
					}
					encoded, err := json.Marshal(permissionDocument{Version: "2012-10-17", ID: "default", Statements: []permissionStatement{existing}})
					if err != nil {
						return err
					}
					rendered, err := s.binder.RenderResourcePolicy(tx.Context(), authorization.BoundPolicy{Document: string(encoded), PrincipalIDs: current.PrincipalIDs})
					if err != nil {
						return err
					}
					var recovered permissionDocument
					if err := json.Unmarshal([]byte(rendered), &recovered); err != nil {
						return err
					}
					principals, err := permissionPrincipalValues(key.Partition, recovered.Statements[0].Principal)
					if err != nil {
						return err
					}
					requested, err := permissionPrincipalValues(key.Partition, statement.Principal)
					if err != nil {
						return err
					}
					// The request was already authorized in its original form.
					// Do not turn account-ID conditions into root-ARN conditions
					// merely because storage canonicalizes the same principal.
					if !slices.Equal(principals, requested) {
						if wire := s.authorizeLayer(tx, "AddLayerVersionPermission", key, map[string][]string{"lambda:Principal": principals}); wire != nil {
							return wire
						}
					}
					encoded, err = json.Marshal(recovered.Statements[0])
					if err != nil {
						return err
					}
					out.Statement = new(api.String(string(encoded)))
					out.RevisionId = new(api.String(current.Revision))
					return s.recordCall(tx.Context(), "AddLayerVersionPermission", in, out, nil)
				}
				return failure("ResourceConflictException", "The statement id ("+statement.Sid+") provided already exists. Please provide a new statement id, or remove the existing statement.", 409)
			}
		}
		if wire := policyRevision(in.RevisionId, current.Revision); wire != nil {
			return wire
		}
		if s.binder == nil {
			return unsupported("The configured authorizer does not support resource policy principal binding.")
		}
		encoded, err := json.Marshal(permissionDocument{Version: "2012-10-17", ID: "default", Statements: []permissionStatement{statement}})
		if err != nil {
			return err
		}
		bound, err := s.binder.BindResourcePolicy(tx.Context(), string(encoded), authorization.ResourcePolicyOptions{})
		if err != nil {
			return failure("InvalidParameterValueException", err.Error(), 400)
		}
		canonical, err := policy.RewriteResourcePrincipals([]byte(bound.Document), bound.PrincipalIDs)
		if err != nil {
			return err
		}
		var added permissionDocument
		if err := json.Unmarshal(canonical, &added); err != nil {
			return err
		}
		document.Statements = append(document.Statements, added.Statements[0])
		if current.PrincipalIDs == nil {
			current.PrincipalIDs = map[string]string{}
		}
		for _, id := range bound.PrincipalIDs {
			current.PrincipalIDs[id] = id
		}
		encoded, err = json.Marshal(document)
		if err != nil {
			return err
		}
		current.Document = string(encoded)
		rendered, err := s.binder.RenderResourcePolicy(tx.Context(), authorization.BoundPolicy{Document: current.Document, PrincipalIDs: current.PrincipalIDs})
		if err != nil {
			return err
		}
		if len(rendered) > functionPolicyLimit {
			return failure("PolicyLengthExceededException", "The final policy size is bigger than the limit (20480).", 400)
		}
		current.Revision = uuid.NewString()
		if err := tx.PutLayerPolicy(current); err != nil {
			return err
		}
		if owner != (LayerPermissionOwner{}) {
			if err := tx.PutLayerPermissionOwner(permissionKey, owner); err != nil {
				return err
			}
		}
		encoded, err = json.Marshal(statement)
		if err != nil {
			return err
		}
		out.Statement = new(api.String(string(encoded)))
		out.RevisionId = new(api.String(current.Revision))
		return s.recordCall(tx.Context(), "AddLayerVersionPermission", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) getLayerVersionPolicy(ctx context.Context, in *api.GetLayerVersionPolicyInput) (*api.GetLayerVersionPolicyOutput, *awswire.Error) {
	key, wire := layerVersionKey(ctx, value(in.LayerName), in.VersionNumber)
	if wire != nil {
		return nil, wire
	}
	out := &api.GetLayerVersionPolicyOutput{}
	err := s.repository.View(ctx, func(r Reader) error {
		if _, err := loadLayer(r, key); err != nil {
			return err
		}
		if wire := s.authorizeLayer(r, "GetLayerVersionPolicy", key, nil); wire != nil {
			return wire
		}
		current, err := r.LayerPolicy(key)
		if errors.Is(err, ErrNotFound) {
			return failure("ResourceNotFoundException", "The resource you requested does not exist.", 404)
		}
		if err != nil {
			return err
		}
		if s.binder == nil {
			return unsupported("The configured authorizer does not support resource policy principal rendering.")
		}
		rendered, err := s.binder.RenderResourcePolicy(r.Context(), authorization.BoundPolicy{Document: current.Document, PrincipalIDs: current.PrincipalIDs})
		if err != nil {
			return err
		}
		out.Policy = new(api.String(rendered))
		out.RevisionId = new(api.String(current.Revision))
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) removeLayerVersionPermission(ctx context.Context, in *api.RemoveLayerVersionPermissionInput) (*api.RemoveLayerVersionPermissionOutput, *awswire.Error) {
	key, wire := layerVersionKey(ctx, value(in.LayerName), in.VersionNumber)
	if wire != nil {
		return nil, wire
	}
	permissionKey := LayerPermissionKey{LayerVersionKey: key, StatementID: value(in.StatementId)}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := tx.LayerVersion(key); err != nil {
			if !errors.Is(err, ErrNotFound) {
				return err
			}
			return failure("ResourceNotFoundException", "Layer version "+key.ARN()+" does not exist.", 404)
		}
		current, document, err := loadLayerPermissionDocument(tx, key)
		if err != nil {
			return err
		}
		index := slices.IndexFunc(document.Statements, func(v permissionStatement) bool { return v.Sid == value(in.StatementId) })
		conditions := map[string][]string{}
		if index >= 0 {
			// Layer statements originate only from single-principal AddLayerVersionPermission.
			principals, err := s.permissionConditionPrincipals(tx.Context(), key.Partition, document.Statements[index], FunctionPolicy{Document: current.Document, PrincipalIDs: current.PrincipalIDs})
			if err != nil {
				return err
			}
			if len(principals) > 0 {
				conditions["lambda:Principal"] = principals
			}
		}
		if wire := s.authorizeLayer(tx, "RemoveLayerVersionPermission", key, conditions); wire != nil {
			return wire
		}
		if current.Document == "" {
			return failure("ResourceNotFoundException", "No policy is associated with the given resource.", 404)
		}
		if index < 0 {
			return failure("ResourceNotFoundException", "Statement "+value(in.StatementId)+" is not found in resource policy.", 404)
		}
		if wire := policyRevision(in.RevisionId, current.Revision); wire != nil {
			return wire
		}
		if err := tx.DeleteLayerPermissionOwner(permissionKey); err != nil {
			return err
		}
		document.Statements = slices.Delete(document.Statements, index, index+1)
		if len(document.Statements) == 0 {
			if err := tx.DeleteLayerPolicy(key); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), "RemoveLayerVersionPermission", in, nil, nil)
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			return err
		}
		parsed, err := policy.ParseResource(encoded)
		if err != nil {
			return err
		}
		remaining := map[string]string{}
		for _, principal := range parsed.AWSPrincipals() {
			if id, ok := current.PrincipalIDs[principal]; ok {
				remaining[principal] = id
			}
		}
		current.Document, current.Revision, current.PrincipalIDs = string(encoded), uuid.NewString(), remaining
		if err := tx.PutLayerPolicy(current); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "RemoveLayerVersionPermission", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.RemoveLayerVersionPermissionOutput{}, nil
}
