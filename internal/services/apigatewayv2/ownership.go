package apigatewayv2

import (
	"context"
	"errors"
	"strings"
)

// ResourceOwner identifies one CloudFormation logical resource incarnation.
// Ownership is retained on the authoritative resource row, independently of tags.
type ResourceOwner struct {
	StackID   string
	LogicalID string
	Token     string
}

type resourceOwnerContextKey struct{}

// WithResourceOwner fences target mutations and reads, and recovers creates for
// this incarnation. Ordinary reads and lists require no owner.
func WithResourceOwner(ctx context.Context, owner ResourceOwner) context.Context {
	return context.WithValue(ctx, resourceOwnerContextKey{}, owner)
}

// ResourceOwnerFromContext reports the owner bound by WithResourceOwner.
// A bound but incomplete owner is rejected by command registration.
func ResourceOwnerFromContext(ctx context.Context) (ResourceOwner, bool) {
	owner, ok := ctx.Value(resourceOwnerContextKey{}).(ResourceOwner)
	return owner, ok
}

type ownedResource interface {
	resourceOwner() ResourceOwner
}

func (v APIRecord) resourceOwner() ResourceOwner           { return v.Owner }
func (v IntegrationRecord) resourceOwner() ResourceOwner   { return v.Owner }
func (v AuthorizerRecord) resourceOwner() ResourceOwner    { return v.Owner }
func (v RouteRecord) resourceOwner() ResourceOwner         { return v.Owner }
func (v RouteResponseRecord) resourceOwner() ResourceOwner { return v.Owner }
func (v StageRecord) resourceOwner() ResourceOwner         { return v.Owner }
func (v DeploymentRecord) resourceOwner() ResourceOwner    { return v.Owner }

// Recovery runs inside the command's transaction after authorization and before
// ID allocation. It returns the persisted row, never reapplies create input.
func recoverOwnedResource[T ownedResource, K any](r Reader, key K, list func(K) ([]T, error)) (T, bool, error) {
	var found T
	owner, bound := ResourceOwnerFromContext(r.Context())
	if !bound {
		return found, false, nil
	}
	rows, err := list(key)
	if err != nil {
		return found, false, err
	}
	matched := false
	for i := range rows {
		if rows[i].resourceOwner() != owner {
			continue
		}
		if matched {
			return found, false, ownershipConflict()
		}
		found, matched = rows[i], true
	}
	return found, matched, nil
}

func ownershipConflict() error {
	return failure("ConflictException", "Resource does not match the CloudFormation incarnation", 409)
}

func resourceOwnerTransaction(tx Transaction, action string) (Transaction, error) {
	owner, bound := ResourceOwnerFromContext(tx.Context())
	if !bound {
		return tx, nil
	}
	if owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return nil, bad("CloudFormation resource ownership requires StackID, LogicalID and Token")
	}
	var kind string
	switch action {
	case "CreateApi", "GetApi", "UpdateApi", "DeleteApi":
		kind = "Api"
	case "CreateIntegration", "GetIntegration", "UpdateIntegration", "DeleteIntegration":
		kind = "Integration"
	case "CreateAuthorizer", "GetAuthorizer", "UpdateAuthorizer", "DeleteAuthorizer":
		kind = "Authorizer"
	case "CreateRoute", "GetRoute", "UpdateRoute", "DeleteRoute":
		kind = "Route"
	case "CreateRouteResponse", "GetRouteResponse", "UpdateRouteResponse", "DeleteRouteResponse":
		kind = "RouteResponse"
	case "CreateStage", "GetStage", "UpdateStage", "DeleteStage", "DeleteAccessLogSettings", "DeleteRouteSettings", "ResetAuthorizersCache":
		kind = "Stage"
	case "CreateDeployment", "GetDeployment", "UpdateDeployment", "DeleteDeployment":
		kind = "Deployment"
	case "TagResource", "UntagResource":
		kind = "Tagged"
	}
	if kind == "" {
		return tx, nil
	}
	return &ownerTransaction{Transaction: tx, owner: owner, kind: kind, creating: strings.HasPrefix(action, "Create")}, nil
}

type ownerTransaction struct {
	Transaction
	owner    ResourceOwner
	kind     string
	creating bool
}

// Derived deployment/stage writes retain their own owner. They are consequences
// of an already fenced draft mutation, not resources owned by that draft's CFN
// context. In particular automatic deployments must remain unclaimed.
func derivedResourceTransaction(tx Transaction) Transaction {
	if fenced, ok := tx.(*ownerTransaction); ok {
		return fenced.Transaction
	}
	return tx
}

func (tx *ownerTransaction) writeOwner(kind string, existing ResourceOwner, err error) (ResourceOwner, error) {
	if errors.Is(err, ErrNotFound) && tx.creating && tx.kind == kind {
		return tx.owner, nil
	}
	if err != nil {
		return ResourceOwner{}, err
	}
	if tx.creating && tx.kind == kind || existing != tx.owner {
		return ResourceOwner{}, ownershipConflict()
	}
	return existing, nil
}

func (tx *ownerTransaction) deleteOwner(existing ResourceOwner, err error) error {
	if err != nil {
		return err
	}
	if existing != tx.owner {
		return ownershipConflict()
	}
	return nil
}

func (tx *ownerTransaction) readOwner(kind string, owner ResourceOwner, err error) error {
	if err != nil {
		return err
	}
	target := tx.kind == kind || tx.kind == "Tagged" && (kind == "Api" || kind == "Stage")
	if !tx.creating && target && owner != tx.owner {
		return ownershipConflict()
	}
	return nil
}

func (tx *ownerTransaction) API(key APIKey) (APIRecord, error) {
	row, err := tx.Transaction.API(key)
	return row, tx.readOwner("Api", row.Owner, err)
}
func (tx *ownerTransaction) Integration(key ResourceKey) (IntegrationRecord, error) {
	row, err := tx.Transaction.Integration(key)
	return row, tx.readOwner("Integration", row.Owner, err)
}
func (tx *ownerTransaction) Authorizer(key ResourceKey) (AuthorizerRecord, error) {
	row, err := tx.Transaction.Authorizer(key)
	return row, tx.readOwner("Authorizer", row.Owner, err)
}
func (tx *ownerTransaction) Route(key ResourceKey) (RouteRecord, error) {
	row, err := tx.Transaction.Route(key)
	return row, tx.readOwner("Route", row.Owner, err)
}
func (tx *ownerTransaction) RouteResponse(key ResourceKey) (RouteResponseRecord, error) {
	row, err := tx.Transaction.RouteResponse(key)
	return row, tx.readOwner("RouteResponse", row.Owner, err)
}
func (tx *ownerTransaction) Stage(key ResourceKey) (StageRecord, error) {
	row, err := tx.Transaction.Stage(key)
	return row, tx.readOwner("Stage", row.Owner, err)
}
func (tx *ownerTransaction) Deployment(key ResourceKey) (DeploymentRecord, error) {
	row, err := tx.Transaction.Deployment(key)
	return row, tx.readOwner("Deployment", row.Owner, err)
}

func (tx *ownerTransaction) PutAPI(v APIRecord) error {
	old, err := tx.Transaction.API(v.Key)
	v.Owner, err = tx.writeOwner("Api", old.Owner, err)
	if err != nil {
		return err
	}
	return tx.Transaction.PutAPI(v)
}
func (tx *ownerTransaction) DeleteAPI(key APIKey) error {
	old, err := tx.Transaction.API(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteAPI(key)
}
func (tx *ownerTransaction) PutIntegration(v IntegrationRecord) error {
	old, err := tx.Transaction.Integration(v.Key)
	v.Owner, err = tx.writeOwner("Integration", old.Owner, err)
	if err != nil {
		return err
	}
	return tx.Transaction.PutIntegration(v)
}
func (tx *ownerTransaction) DeleteIntegration(key ResourceKey) error {
	old, err := tx.Transaction.Integration(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteIntegration(key)
}
func (tx *ownerTransaction) PutAuthorizer(v AuthorizerRecord) error {
	old, err := tx.Transaction.Authorizer(v.Key)
	v.Owner, err = tx.writeOwner("Authorizer", old.Owner, err)
	if err != nil {
		return err
	}
	return tx.Transaction.PutAuthorizer(v)
}
func (tx *ownerTransaction) DeleteAuthorizer(key ResourceKey) error {
	old, err := tx.Transaction.Authorizer(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteAuthorizer(key)
}
func (tx *ownerTransaction) PutRoute(v RouteRecord) error {
	old, err := tx.Transaction.Route(v.Key)
	v.Owner, err = tx.writeOwner("Route", old.Owner, err)
	if err != nil {
		return err
	}
	return tx.Transaction.PutRoute(v)
}
func (tx *ownerTransaction) DeleteRoute(key ResourceKey) error {
	old, err := tx.Transaction.Route(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteRoute(key)
}
func (tx *ownerTransaction) PutRouteResponse(v RouteResponseRecord) error {
	old, err := tx.Transaction.RouteResponse(v.Key)
	v.Owner, err = tx.writeOwner("RouteResponse", old.Owner, err)
	if err != nil {
		return err
	}
	return tx.Transaction.PutRouteResponse(v)
}
func (tx *ownerTransaction) DeleteRouteResponse(key ResourceKey) error {
	old, err := tx.Transaction.RouteResponse(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteRouteResponse(key)
}
func (tx *ownerTransaction) PutStage(v StageRecord) error {
	old, err := tx.Transaction.Stage(v.Key)
	v.Owner, err = tx.writeOwner("Stage", old.Owner, err)
	if err != nil {
		return err
	}
	return tx.Transaction.PutStage(v)
}
func (tx *ownerTransaction) DeleteStage(key ResourceKey) error {
	old, err := tx.Transaction.Stage(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteStage(key)
}
func (tx *ownerTransaction) DeleteStageAuthorizerCache(key ResourceKey) error {
	old, err := tx.Transaction.Stage(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteStageAuthorizerCache(key)
}
func (tx *ownerTransaction) PutDeployment(v DeploymentRecord) error {
	old, err := tx.Transaction.Deployment(v.Key)
	v.Owner, err = tx.writeOwner("Deployment", old.Owner, err)
	if err != nil {
		return err
	}
	return tx.Transaction.PutDeployment(v)
}
func (tx *ownerTransaction) DeleteDeployment(key ResourceKey) error {
	old, err := tx.Transaction.Deployment(key)
	if err := tx.deleteOwner(old.Owner, err); err != nil {
		return err
	}
	return tx.Transaction.DeleteDeployment(key)
}
