package eventbridge

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

// Accounts supplies the current partition-scoped account authority for full
// policies. Shorthand PutPermission deliberately accepts syntactic account IDs.
type Accounts interface {
	AccountExists(context.Context, string, string) (bool, error)
}

var organizationID = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)

func (s *Service) registerPermissions() {
	register(s, "PutPermission", s.putPermission)
	register(s, "RemovePermission", s.removePermission)
}

func (s *Service) putPermission(ctx context.Context, in *api.PutPermissionInput) (out *api.PutPermissionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "PutPermission", in, &out, &rejected, false)
	out = &api.PutPermissionOutput{}
	key, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	full := in.Policy != nil
	var incoming permissionPolicy
	if full {
		if in.Action != nil || in.Principal != nil || in.StatementId != nil || in.Condition != nil {
			return nil, failure("ValidationException", "Action, Principal, StatementId and Condition could not be combined with Policy parameter.")
		}
	} else {
		var err error
		incoming, err = shorthandPermission(in, key)
		if err != nil {
			return nil, wireError(err)
		}
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "PutPermission", key.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		bus, err := s.bus(tx, key)
		if err != nil {
			return err
		}
		if full {
			incoming, err = validatePermissionPolicy(value(in.Policy), key)
			if err != nil {
				return err
			}
		}
		if !full && value(in.Principal) != "*" {
			known, err := s.permissionAccountExists(tx.Context(), key.Partition, value(in.Principal))
			if err != nil {
				return err
			}
			if known {
				data, err := json.Marshal(incoming)
				if err != nil {
					return err
				}
				canonical, err := policy.RewriteResourcePrincipals(data, map[string]string{value(in.Principal): "arn:" + key.Partition + ":iam::" + value(in.Principal) + ":root"})
				if err != nil {
					return err
				}
				incoming, err = readPermissionPolicy(string(canonical))
				if err != nil {
					return err
				}
			}
		}
		document := incoming
		if !full && bus.Policy.Document != "" {
			document, err = readPermissionPolicy(bus.Policy.Document)
			if err != nil {
				return err
			}
			statement := incoming.Statements[0]
			replaced := false
			for i, previous := range document.Statements {
				if permissionSID(previous) == value(in.StatementId) {
					document.Statements[i], replaced = statement, true
					break
				}
			}
			if !replaced {
				document.Statements = append(document.Statements, statement)
			}
		}
		data, err := json.Marshal(document)
		if err != nil {
			return err
		}
		if string(data) == bus.Policy.Document {
			// AWS preserves bindings and modification time for an unchanged
			// policy, including bindings to deleted IAM identities.
			return s.recordCall(tx.Context(), "PutPermission", in, out, nil)
		}
		if len(data) > 10240 {
			return failure("PolicyLengthExceededException", "Policy size would be larger than the maximum allowed.")
		}
		bound := authorization.BoundPolicy{Document: string(data)}
		if full {
			if err := s.validatePermissionAccounts(tx.Context(), key.Partition, incoming.Principals); err != nil {
				return err
			}
			if s.binder == nil {
				return unsupported("Event bus policy principal binding is not configured.")
			}
			bound, err = s.binder.BindResourcePolicy(tx.Context(), bound.Document, authorization.ResourcePolicyOptions{})
			if err != nil {
				if errors.Is(err, authorization.ErrInvalidPrincipal) {
					return failure("ValidationException", "Policy contains an invalid principal")
				}
				return err
			}
		} else {
			bound.PrincipalIDs, err = retainedPermissionBindings(bound.Document, bus.Policy.PrincipalIDs)
			if err != nil {
				return err
			}
		}
		bus.Policy, bus.Modified = bound, s.clock.Now()
		if err := tx.PutBus(bus); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutPermission", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) removePermission(ctx context.Context, in *api.RemovePermissionInput) (out *api.RemovePermissionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "RemovePermission", in, &out, &rejected, false)
	out = &api.RemovePermissionOutput{}
	all := in.RemoveAllPermissions != nil && bool(*in.RemoveAllPermissions)
	if all && in.StatementId != nil {
		return nil, failure("ValidationException", "StatementId could not be combined with All parameter.")
	}
	if !all && in.StatementId == nil {
		return nil, failure("ValidationException", "Parameter(s) StatementId must be specified.")
	}
	key, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "RemovePermission", key.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		bus, err := s.bus(tx, key)
		if err != nil {
			return err
		}
		if all {
			if bus.Policy.Document == "" {
				return s.recordCall(tx.Context(), "RemovePermission", in, out, nil)
			}
			bus.Policy = authorization.BoundPolicy{}
		} else {
			document, err := readPermissionPolicy(bus.Policy.Document)
			if err != nil {
				return err
			}
			found := false
			for i, statement := range document.Statements {
				if permissionSID(statement) == value(in.StatementId) {
					document.Statements = append(document.Statements[:i], document.Statements[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				return failure("ResourceNotFoundException", "Statement with the provided id does not exist.")
			}
			bus.Policy = authorization.BoundPolicy{PrincipalIDs: bus.Policy.PrincipalIDs}
			if len(document.Statements) != 0 {
				data, err := json.Marshal(document)
				if err != nil {
					return err
				}
				bus.Policy.Document = string(data)
			}
			bus.Policy.PrincipalIDs, err = retainedPermissionBindings(bus.Policy.Document, bus.Policy.PrincipalIDs)
			if err != nil {
				return err
			}
		}
		bus.Modified = s.clock.Now()
		if err := tx.PutBus(bus); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "RemovePermission", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func shorthandPermission(in *api.PutPermissionInput, key BusKey) (permissionPolicy, error) {
	if in.Action == nil || in.Principal == nil || in.StatementId == nil {
		return permissionPolicy{}, failure("ValidationException", "Parameter(s) Action, Principal and StatementId must be specified.")
	}
	if value(in.Action) != "events:PutEvents" {
		return permissionPolicy{}, failure("ValidationException", "Provided value in parameter 'action' is not supported.")
	}
	var principal any = value(in.Principal)
	if principal != "*" {
		principal = map[string]string{"AWS": value(in.Principal)}
	}
	statement := map[string]any{"Sid": value(in.StatementId), "Effect": "Allow", "Principal": principal, "Action": "events:PutEvents", "Resource": key.ARN()}
	if c := in.Condition; c != nil {
		if value(c.Type) != "StringEquals" {
			return permissionPolicy{}, failure("ValidationException", "Provided value in parameter 'condition.type' is not supported.")
		}
		if value(c.Key) != "aws:PrincipalOrgID" {
			return permissionPolicy{}, failure("ValidationException", "Provided value in parameter 'condition.key' is not supported.")
		}
		if !organizationID.MatchString(value(c.Value)) {
			return permissionPolicy{}, failure("ValidationException", "Provided value in parameter 'condition.value' is invalid.")
		}
		statement["Condition"] = map[string]any{"StringEquals": map[string]string{"aws:PrincipalOrgID": value(c.Value)}}
	}
	data, err := json.Marshal(statement)
	return permissionPolicy{Version: "2012-10-17", Statements: []json.RawMessage{data}}, err
}

func (s *Service) validatePermissionAccounts(ctx context.Context, partition string, principals []string) error {
	for _, principal := range principals {
		if !strings.HasSuffix(principal, ":root") {
			continue
		}
		parts := strings.SplitN(principal, ":", 6)
		account := parts[4]
		exists, err := s.permissionAccountExists(ctx, parts[1], account)
		if err != nil {
			return err
		}
		if !exists || parts[1] != partition {
			return failure("ValidationException", "Policy contains an invalid principal")
		}
	}
	return nil
}

func (s *Service) permissionAccountExists(ctx context.Context, partition, account string) (bool, error) {
	if s.accounts != nil {
		return s.accounts.AccountExists(ctx, partition, account)
	}
	scope := scopeFor(ctx)
	return partition == scope.Partition && account == scope.Account, nil
}

func retainedPermissionBindings(document string, previous map[string]string) (map[string]string, error) {
	if document == "" || len(previous) == 0 {
		return nil, nil
	}
	parsed, err := policy.ParseResource([]byte(document))
	if err != nil {
		return nil, err
	}
	retained := maps.Clone(previous)
	principals := parsed.AWSPrincipals()
	for arn := range retained {
		if !slices.Contains(principals, arn) {
			delete(retained, arn)
		}
	}
	return retained, nil
}
