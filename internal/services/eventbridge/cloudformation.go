package eventbridge

import (
	"context"
	"encoding/json"
	"errors"

	"stackd/internal/authorization"
)

type cloudFormationOwner struct{ Kind, Owner, StatementID string }
type cloudFormationOwnerKey struct{}

// WithCloudFormationOwner binds internal controller provenance to a real owner
// record; no public request field can supply this context.
func WithCloudFormationOwner(ctx context.Context, kind, owner, statementID string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{kind, owner, statementID})
}
func cloudFormationClaim(ctx context.Context, kind string) string {
	o, _ := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if o.Kind == kind {
		return o.Owner
	}
	return ""
}
func cloudFormationCheck(ctx context.Context, kind, stored string) error {
	if owner := cloudFormationClaim(ctx, kind); owner != "" && stored != owner {
		return failure("ResourceAlreadyExistsException", "Resource is not owned by this CloudFormation incarnation.")
	}
	return nil
}
func cloudFormationBusCheck(ctx context.Context, bus BusRecord) error {
	if cloudFormationClaim(ctx, "EventBus") != "" && bus.Key.Scope != scopeFor(ctx) {
		return failure("ValidationException", "CloudFormation event bus must belong to the current account, partition and Region.")
	}
	return cloudFormationCheck(ctx, "EventBus", bus.CFNOwner)
}

func cloudFormationPolicy(tx Transaction, bus *BusRecord, incoming *permissionPolicy, remove bool) error {
	owner, _ := tx.Context().Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if owner.Kind != "EventBusPolicy" {
		return nil
	}
	if owner.Owner != "" && bus.Key.Scope != scopeFor(tx.Context()) {
		return failure("ValidationException", "CloudFormation event bus policy must belong to the current account, partition and Region.")
	}
	document, err := readPermissionPolicy(bus.Policy.Document)
	if err != nil {
		return err
	}
	exists := false
	for _, statement := range document.Statements {
		if permissionSID(statement) == owner.StatementID {
			exists = true
			break
		}
	}
	if exists && owner.Owner != "" && bus.PolicyStatementOwners[owner.StatementID].CFNOwner != owner.Owner {
		return failure("ResourceAlreadyExistsException", "Event bus statement belongs to another CloudFormation incarnation.")
	}
	if remove {
		return nil
	}
	if incoming != nil {
		if len(incoming.Statements) != 1 || permissionSID(incoming.Statements[0]) != owner.StatementID {
			return failure("ValidationException", "Statement must contain the configured StatementId.")
		}
		next := make([]json.RawMessage, 0, len(document.Statements)+1)
		for _, statement := range document.Statements {
			if permissionSID(statement) != owner.StatementID {
				next = append(next, statement)
			}
		}
		incoming.Statements = append(next, incoming.Statements[0])
	}
	if owner.Owner != "" {
		if bus.PolicyStatementOwners == nil {
			bus.PolicyStatementOwners = map[string]PolicyStatementOwner{}
		}
		bus.PolicyStatementOwners[owner.StatementID] = PolicyStatementOwner{CFNOwner: owner.Owner}
	}
	return nil
}

// CloudFormationEventBusPolicyOwned checks current native admission IAM before
// reading the exact scoped statement's private incarnation for create recovery.
func (s *Service) CloudFormationEventBusPolicyOwned(ctx context.Context, name, sid, owner string) error {
	key, rejected := busKey(ctx, name)
	if rejected != nil {
		return rejected
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "PutPermission", key.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if key.Scope != scopeFor(tx.Context()) {
			return failure("ValidationException", "CloudFormation event bus policy must belong to the current account, partition and Region.")
		}
		bus, err := tx.Bus(key)
		if err != nil {
			return err
		}
		document, err := readPermissionPolicy(bus.Policy.Document)
		if err != nil {
			return err
		}
		for _, statement := range document.Statements {
			if permissionSID(statement) == sid {
				if owner == "" || bus.PolicyStatementOwners[sid].CFNOwner != owner {
					return failure("ResourceAlreadyExistsException", "Event bus statement belongs to another CloudFormation incarnation.")
				}
				return nil
			}
		}
		return failure("ResourceNotFoundException", "Statement with the provided id does not exist.")
	})
	if err != nil {
		return wireError(err)
	}
	return nil
}

// CloudFormationResourceOwned is a scoped, authorized metadata read. Public
// resource reads continue to omit these private incarnation fields.
func (s *Service) CloudFormationResourceOwned(ctx context.Context, kind, name, owner string) error {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		switch kind {
		case "EventBus":
			v, err := s.bus(tx, BusKey{Scope: scopeFor(ctx), Name: name})
			if err != nil {
				return err
			}
			if err = s.authorize(tx, "DescribeEventBus", v.Key.ARN(), v.Tags, nil, v.Policy); err != nil {
				return err
			}
			if owner == "" || v.CFNOwner != owner {
				return failure("ResourceAlreadyExistsException", "Event bus belongs to another incarnation.")
			}
		case "Archive":
			v, err := readArchive(tx, ArchiveKey{Scope: scopeFor(ctx), Name: name})
			if err != nil {
				return err
			}
			if err = s.authorizeArchive(tx, "DescribeArchive", v.Key); err != nil {
				return err
			}
			if v.CFNOwner != owner {
				return failure("ResourceAlreadyExistsException", "Archive belongs to another incarnation.")
			}
		case "Connection":
			v, err := readConnection(tx, ConnectionKey{Scope: scopeFor(ctx), Name: name})
			if err != nil {
				return err
			}
			if err = s.authorizeConnection(tx, "DescribeConnection", v); err != nil {
				return err
			}
			if v.CFNOwner != owner {
				return failure("ResourceAlreadyExistsException", "Connection belongs to another incarnation.")
			}
		case "ApiDestination":
			v, err := readAPIDestination(tx, APIDestinationKey{Scope: scopeFor(ctx), Name: name}, "describe")
			if err != nil {
				return err
			}
			if err = s.authorizeAPIDestination(tx, "DescribeApiDestination", v); err != nil {
				return err
			}
			if v.CFNOwner != owner {
				return failure("ResourceAlreadyExistsException", "Api destination belongs to another incarnation.")
			}
		default:
			return errors.New("unknown EventBridge incarnation kind")
		}
		return nil
	})
	if err != nil {
		return wireError(err)
	}
	return nil
}

// cloudFormationRuleCheck fences controller rule writes to the private
// incarnation admitted with the native row in the caller's exact scope.
// Ordinary native writes carry no claim and preserve the stored owner.
func cloudFormationRuleCheck(ctx context.Context, rule RuleRecord, exists bool) error {
	if cloudFormationClaim(ctx, "Rule") == "" {
		return nil
	}
	if rule.Key.Bus.Scope != scopeFor(ctx) {
		return failure("ValidationException", "CloudFormation event rule must belong to the current account, partition and Region.")
	}
	if !exists {
		return nil
	}
	return cloudFormationCheck(ctx, "Rule", rule.CFNOwner)
}

// CloudFormationRuleOwned checks current native DescribeRule IAM before
// reading the exact scoped rule's private incarnation for create recovery.
func (s *Service) CloudFormationRuleOwned(ctx context.Context, busName, name, owner string) error {
	bus, rejected := busKey(ctx, busName)
	if rejected != nil {
		return rejected
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		rule, err := tx.Rule(RuleKey{Bus: bus, Name: name})
		if err != nil {
			return err
		}
		if err := s.authorizeRule(tx, "DescribeRule", rule, nil); err != nil {
			return err
		}
		if bus.Scope != scopeFor(tx.Context()) {
			return failure("ValidationException", "CloudFormation event rule must belong to the current account, partition and Region.")
		}
		if owner == "" || rule.CFNOwner != owner {
			return failure("ResourceAlreadyExistsException", "Event rule belongs to another CloudFormation incarnation.")
		}
		return nil
	})
	if err != nil {
		return wireError(err)
	}
	return nil
}

type cloudFormationBusPolicyReplacementKey struct{}

// WithCloudFormationBusPolicyReplacement marks whole-policy writes from the
// EventBus adapter, including Cloud Control, without granting ownership or IAM.
func WithCloudFormationBusPolicyReplacement(ctx context.Context) context.Context {
	return context.WithValue(ctx, cloudFormationBusPolicyReplacementKey{}, true)
}

// Whole-policy controller writes cannot own independently claimed statements.
// Ordinary native writes retain surviving Sid claims and clear deleted Sids.
func cloudFormationBusPolicyReplaceable(ctx context.Context, bus BusRecord) error {
	replacement, _ := ctx.Value(cloudFormationBusPolicyReplacementKey{}).(bool)
	if !replacement && cloudFormationClaim(ctx, "EventBus") == "" {
		return nil
	}
	if len(bus.PolicyStatementOwners) != 0 {
		return failure("ValidationException", "Cannot replace an event bus policy while independently owned EventBusPolicy statements exist.")
	}
	return nil
}

type cloudFormationBusPolicyUpdate struct {
	Document string
	Remove   bool
}
type cloudFormationBusPolicyUpdateKey struct{}

// WithCloudFormationBusPolicyUpdate carries the pending inline policy to native
// bus configuration/tag transactions, so their writes fence private statements
// and recheck current permission IAM before changing any neighboring state.
func WithCloudFormationBusPolicyUpdate(ctx context.Context, document string, remove bool) context.Context {
	ctx = WithCloudFormationBusPolicyReplacement(ctx)
	return context.WithValue(ctx, cloudFormationBusPolicyUpdateKey{}, cloudFormationBusPolicyUpdate{Document: document, Remove: remove})
}

func (s *Service) cloudFormationBusPolicyUpdateCheck(tx Transaction, bus BusRecord) error {
	change, present := tx.Context().Value(cloudFormationBusPolicyUpdateKey{}).(cloudFormationBusPolicyUpdate)
	if !present {
		return nil
	}
	action := "PutPermission"
	if change.Remove {
		action = "RemovePermission"
	}
	if err := s.authorize(tx, action, bus.Key.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
		return err
	}
	if !change.Remove {
		if _, err := validatePermissionPolicy(change.Document, bus.Key); err != nil {
			return err
		}
	}
	return cloudFormationBusPolicyReplaceable(tx.Context(), bus)
}

func retainPermissionStatementOwners(bus *BusRecord, document permissionPolicy) {
	for sid := range bus.PolicyStatementOwners {
		found := false
		for _, statement := range document.Statements {
			if permissionSID(statement) == sid {
				found = true
				break
			}
		}
		if !found {
			delete(bus.PolicyStatementOwners, sid)
		}
	}
}
