package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

const functionPolicyLimit = 20 * 1024

var permissionAccount = regexp.MustCompile(`^[0-9]{12}$`)
var permissionService = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.amazonaws\.com(\.cn)?$`)

type permissionStatement struct {
	// Retained statements may contain arrays, NotAction/NotResource and typed
	// condition values supplied by PutResourcePolicy. Mutations preserve them.
	raw       json.RawMessage
	Sid       string                       `json:"Sid"`
	Effect    string                       `json:"Effect"`
	Principal json.RawMessage              `json:"Principal"`
	Action    string                       `json:"Action"`
	Resource  string                       `json:"Resource"`
	Condition map[string]map[string]string `json:"Condition,omitempty"`
}

type permissionDocument struct {
	Version    string                `json:"Version"`
	ID         string                `json:"Id,omitempty"`
	Statements []permissionStatement `json:"Statement"`
}

func (s *permissionStatement) UnmarshalJSON(data []byte) error {
	var fields struct {
		Sid       string
		Principal json.RawMessage
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*s = permissionStatement{raw: slices.Clone(data), Sid: fields.Sid, Principal: fields.Principal}
	return nil
}

func (s permissionStatement) MarshalJSON() ([]byte, error) {
	if s.raw != nil {
		return s.raw, nil
	}
	type constructedStatement permissionStatement
	return json.Marshal(constructedStatement(s))
}

func (d *permissionDocument) UnmarshalJSON(data []byte) error {
	var fields struct {
		Version   string
		ID        string `json:"Id"`
		Statement json.RawMessage
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*d = permissionDocument{Version: fields.Version, ID: fields.ID}
	if len(fields.Statement) > 0 && fields.Statement[0] == '{' {
		d.Statements = make([]permissionStatement, 1)
		return json.Unmarshal(fields.Statement, &d.Statements[0])
	}
	return json.Unmarshal(fields.Statement, &d.Statements)
}

func (s *Service) registerPermissions() {
	register(s, "AddPermission", s.addPermission)
	register(s, "GetPolicy", s.getPolicy)
	register(s, "RemovePermission", s.removePermission)
}

func permissionKey(ctx context.Context, name, qualifier, action string) (FunctionReference, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, name, qualifier)
	if wire != nil {
		return ref, wire
	}
	if ref.Qualifier == "$LATEST" {
		if action == "AddPermission" {
			return FunctionReference{}, failure("InvalidParameterValueException", "We currently do not support adding policies for $LATEST.", 400)
		}
		return FunctionReference{}, failure("ResourceNotFoundException", "The resource you requested does not exist.", 404)
	}
	return ref, nil
}

func (s *Service) authorizeFunction(r Reader, action string, ref FunctionReference, function FunctionRecord, extra map[string][]string) *awswire.Error {
	current, err := r.FunctionPolicy(ref)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return wireError(err)
	}
	return s.authorizeReferencedFunctionPolicy(r, action, ref, function, current, extra)
}

func (s *Service) authorizeReferencedFunctionPolicy(r Reader, action string, ref FunctionReference, function FunctionRecord, current FunctionPolicy, extra map[string][]string) *awswire.Error {
	// Native qualified tag conditions follow the current base tags, including
	// after publication and alias creation. Only the authorization projection
	// sees those tags; immutable deployment records never acquire a snapshot.
	if function.Version != 0 {
		base, err := r.Function(ref.FunctionKey)
		if err != nil {
			return wireError(err)
		}
		function.Tags = base.Tags
	}
	return s.authorizeFunctionPolicy(r.Context(), function, ref.ARN(), action, current, extra)
}

func (s *Service) authorizeFunctionPolicy(ctx context.Context, function FunctionRecord, arn, action string, current FunctionPolicy, extra map[string][]string) *awswire.Error {
	conditions := tagConditions(function.Tags, nil)
	if action == "InvokeFunction" {
		conditions["lambda:InvokedViaFunctionUrl"] = []string{"false"}
		if sourceARN, _ := ctx.Value(eventSourceARNKey{}).(string); sourceARN != "" {
			conditions["aws:SourceArn"] = []string{sourceARN}
		}
	}
	for key, values := range extra {
		conditions[key] = values
	}
	return s.authorizer.Authorize(ctx, authorization.Request{
		Action: "lambda:" + action, ResourceARN: arn, ResourceAccountID: function.Key.Account,
		ResourcePolicies: []authorization.BoundPolicy{{Document: current.Document, PrincipalIDs: current.PrincipalIDs}}, Context: conditions,
	})
}

func loadPermissionDocument(r PolicyReader, key FunctionReference) (FunctionPolicy, permissionDocument, error) {
	current, err := r.FunctionPolicy(key)
	if errors.Is(err, ErrNotFound) {
		return FunctionPolicy{Key: key, PrincipalIDs: map[string]string{}}, permissionDocument{Version: "2012-10-17", ID: "default", Statements: []permissionStatement{}}, nil
	}
	if err != nil {
		return FunctionPolicy{}, permissionDocument{}, err
	}
	var document permissionDocument
	if err := json.Unmarshal([]byte(current.Document), &document); err != nil {
		return FunctionPolicy{}, permissionDocument{}, err
	}
	return current, document, nil
}

func policyRevision(expected *api.String, actual string) *awswire.Error {
	if expected != nil && string(*expected) != actual {
		return failure("PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetPolicy API to retrieve the latest Revision Id", 412)
	}
	return nil
}

func permissionPrincipal(partition, reference string) (json.RawMessage, *awswire.Error) {
	var principal any
	switch {
	case reference == "*":
		principal = "*"
	case permissionAccount.MatchString(reference):
		principal = map[string]string{"AWS": "arn:" + partition + ":iam::" + reference + ":root"}
	case permissionService.MatchString(reference):
		principal = map[string]string{"Service": reference}
	case strings.HasPrefix(reference, "arn:"):
		parts := strings.SplitN(reference, ":", 6)
		if len(parts) != 6 || parts[1] != partition || parts[2] != "iam" || parts[3] != "" || !permissionAccount.MatchString(parts[4]) || (parts[5] != "root" && !strings.HasPrefix(parts[5], "user/") && !strings.HasPrefix(parts[5], "role/")) {
			return nil, failure("InvalidParameterValueException", "The provided principal was invalid. Specify an AWS account, service, IAM user, or IAM role.", 400)
		}
		principal = map[string]string{"AWS": reference}
	default:
		return nil, failure("InvalidParameterValueException", "The provided principal was invalid. Please check the principal and try again.", 400)
	}
	encoded, err := json.Marshal(principal)
	if err != nil {
		return nil, wireError(err)
	}
	return encoded, nil
}

func (s *Service) addPermission(ctx context.Context, in *api.AddPermissionInput) (*api.AddPermissionOutput, *awswire.Error) {
	if in.FunctionUrlAuthType != nil && value(in.Action) != "lambda:InvokeFunctionUrl" {
		return nil, failure("InvalidParameterValueException", "FunctionUrlAuthType is only supported for lambda:InvokeFunctionUrl.", 400)
	}
	if in.InvokedViaFunctionUrl != nil && value(in.Action) != "lambda:InvokeFunction" {
		return nil, failure("InvalidParameterValueException", "InvokedViaFunctionUrl is only supported for lambda:InvokeFunction.", 400)
	}
	if in.EventSourceToken != nil {
		return nil, unsupported("Alexa event-source token authorization is not implemented.")
	}
	key, wire := permissionKey(ctx, value(in.FunctionName), value(in.Qualifier), "AddPermission")
	if wire != nil {
		return nil, wire
	}
	principal, wire := permissionPrincipal(key.Partition, value(in.Principal))
	if wire != nil {
		return nil, wire
	}
	statement := permissionStatement{Sid: value(in.StatementId), Effect: "Allow", Principal: principal, Action: value(in.Action), Resource: key.ARN(), Condition: map[string]map[string]string{}}
	if in.SourceArn != nil {
		statement.Condition["ArnLike"] = map[string]string{"AWS:SourceArn": value(in.SourceArn)}
	}
	if in.SourceAccount != nil || in.PrincipalOrgID != nil || in.FunctionUrlAuthType != nil {
		equals := map[string]string{}
		if in.SourceAccount != nil {
			equals["AWS:SourceAccount"] = value(in.SourceAccount)
		}
		if in.PrincipalOrgID != nil {
			equals["aws:PrincipalOrgID"] = value(in.PrincipalOrgID)
		}
		if in.FunctionUrlAuthType != nil {
			equals["lambda:FunctionUrlAuthType"] = value(in.FunctionUrlAuthType)
		}
		statement.Condition["StringEquals"] = equals
	}
	if in.InvokedViaFunctionUrl != nil {
		statement.Condition["Bool"] = map[string]string{"lambda:InvokedViaFunctionUrl": strconv.FormatBool(bool(*in.InvokedViaFunctionUrl))}
	}
	var output string
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := loadFunction(tx, key)
		if err != nil {
			return err
		}
		current, document, err := loadPermissionDocument(tx, key)
		if err != nil {
			return err
		}
		if wire := s.authorizeReferencedFunctionPolicy(tx, "AddPermission", key, function, current, map[string][]string{"lambda:Principal": {value(in.Principal)}}); wire != nil {
			return wire
		}
		for _, existing := range document.Statements {
			if existing.Sid == statement.Sid {
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
		bound, err := s.binder.BindResourcePolicy(tx.Context(), string(encoded), authorization.ResourcePolicyOptions{AllowFederatedPrincipals: true})
		if err != nil {
			return failure("InvalidParameterValueException", err.Error(), 400)
		}
		// Bind only the new statement. Rebinding the existing policy would grant
		// a recreated IAM ARN the permissions of its deleted predecessor.
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
		if err := tx.PutFunctionPolicy(current); err != nil {
			return err
		}
		encoded, err = json.Marshal(statement)
		output = string(encoded)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "AddPermission", in, &api.AddPermissionOutput{Statement: new(api.String(output))}, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.AddPermissionOutput{Statement: new(api.String(output))}, nil
}

func (s *Service) getPolicy(ctx context.Context, in *api.GetPolicyInput) (*api.GetPolicyOutput, *awswire.Error) {
	key, wire := permissionKey(ctx, value(in.FunctionName), value(in.Qualifier), "GetPolicy")
	if wire != nil {
		return nil, wire
	}
	out := &api.GetPolicyOutput{}
	err := s.repository.View(ctx, func(r Reader) error {
		function, err := loadFunction(r, key)
		if err != nil {
			return err
		}
		current, err := r.FunctionPolicy(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if wire := s.authorizeReferencedFunctionPolicy(r, "GetPolicy", key, function, current, nil); wire != nil {
			return wire
		}
		if errors.Is(err, ErrNotFound) {
			return failure("ResourceNotFoundException", "The resource you requested does not exist.", 404)
		}
		if s.binder == nil {
			return unsupported("The configured authorizer does not support resource policy principal rendering.")
		}
		rendered, err := s.binder.RenderResourcePolicy(r.Context(), authorization.BoundPolicy{Document: current.Document, PrincipalIDs: current.PrincipalIDs})
		if err != nil {
			return err
		}
		out.Policy, out.RevisionId = new(api.String(rendered)), new(api.String(current.Revision))
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) removePermission(ctx context.Context, in *api.RemovePermissionInput) (*api.RemovePermissionOutput, *awswire.Error) {
	key, wire := permissionKey(ctx, value(in.FunctionName), value(in.Qualifier), "RemovePermission")
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := loadFunction(tx, key)
		if err != nil {
			return err
		}
		current, document, err := loadPermissionDocument(tx, key)
		if err != nil {
			return err
		}
		index := slices.IndexFunc(document.Statements, func(statement permissionStatement) bool { return statement.Sid == value(in.StatementId) })
		conditions := map[string][]string{}
		if index >= 0 {
			principals, err := s.permissionConditionPrincipals(tx.Context(), key.Partition, document.Statements[index], current)
			if err != nil {
				return err
			}
			if principals != nil {
				conditions["lambda:Principal"] = principals
			}
		}
		if wire := s.authorizeReferencedFunctionPolicy(tx, "RemovePermission", key, function, current, conditions); wire != nil {
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
		document.Statements = slices.Delete(document.Statements, index, index+1)
		if len(document.Statements) == 0 {
			if err := tx.DeleteFunctionPolicy(key); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), "RemovePermission", in, nil, nil)
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
		if err := tx.PutFunctionPolicy(current); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "RemovePermission", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.RemovePermissionOutput{}, nil
}

func (s *Service) permissionConditionPrincipals(ctx context.Context, partition string, statement permissionStatement, current FunctionPolicy) ([]string, error) {
	if s.binder == nil {
		return nil, unsupported("The configured authorizer does not support resource policy principal rendering.")
	}
	encoded, err := json.Marshal(permissionDocument{Version: "2012-10-17", ID: "default", Statements: []permissionStatement{statement}})
	if err != nil {
		return nil, err
	}
	rendered, err := s.binder.RenderResourcePolicy(ctx, authorization.BoundPolicy{Document: string(encoded), PrincipalIDs: current.PrincipalIDs})
	if err != nil {
		return nil, err
	}
	var document permissionDocument
	if err := json.Unmarshal([]byte(rendered), &document); err != nil {
		return nil, err
	}
	return permissionPrincipalValues(partition, document.Statements[0].Principal)
}

func permissionPrincipalValues(partition string, principal json.RawMessage) ([]string, error) {
	if len(principal) == 0 {
		return nil, nil
	}
	if string(principal) == `"*"` {
		return []string{"*"}, nil
	}
	var kinds map[string]json.RawMessage
	if err := json.Unmarshal(principal, &kinds); err != nil {
		return nil, err
	}
	if len(kinds) > 1 {
		// Native mixed-kind metadata is non-null, but matches no string
		// alternatives. The IAM owner retains that presence distinction.
		return []string{}, nil
	}
	for kind, raw := range kinds {
		if kind != "AWS" && kind != "Service" {
			// Native legacy RemovePermission cannot process a federated
			// principal, although full-document Put/Delete support it.
			return nil, failure("ServiceException", "An error occurred and the request cannot be processed.", 500)
		}
		var values []string
		if len(raw) > 0 && raw[0] == '"' {
			var single string
			if err := json.Unmarshal(raw, &single); err != nil {
				return nil, err
			}
			values = []string{single}
		} else if err := json.Unmarshal(raw, &values); err != nil {
			return nil, err
		}
		if kind == "AWS" {
			for i, reference := range values {
				if permissionAccount.MatchString(reference) {
					values[i] = "arn:" + partition + ":iam::" + reference + ":root"
				}
			}
		}
		slices.Sort(values)
		values = slices.Compact(values)
		if len(values) == 1 {
			return values, nil
		}
		// Native emits a present empty string for a non-singleton AWS
		// selector, not multiple ARN context values.
		return append(values[:0], ""), nil
	}
	return nil, nil
}
