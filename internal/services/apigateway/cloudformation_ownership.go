package apigateway

import (
	"context"
	"errors"
)

// Ownership is retained on the service-owned row, independently of stack state.
// It is deliberately absent from the public API model.
type Ownership struct{ StackID, LogicalID, Incarnation string }

type ownershipContext struct {
	Kind             string
	Claim            Ownership
	Enforce, Release bool
	Rows             map[string]Ownership
}
type ownershipContextKey struct{}

// WithResourceOwnership binds the internal resource adapter to its row incarnation.
// rows receives claims from real authorized GET/list operations for recovery.
func WithResourceOwnership(ctx context.Context, kind string, claim Ownership, enforce, release bool, rows map[string]Ownership) context.Context {
	return context.WithValue(ctx, ownershipContextKey{}, &ownershipContext{kind, claim, enforce, release, rows})
}

type ownershipTransaction struct {
	Transaction
	binding *ownershipContext
}

func bindOwnership(tx Transaction) Transaction {
	if b, ok := tx.Context().Value(ownershipContextKey{}).(*ownershipContext); ok {
		return &ownershipTransaction{tx, b}
	}
	return tx
}
func (t *ownershipTransaction) observe(kind, id string, scope Scope, claim Ownership) error {
	if kind != t.binding.Kind {
		return nil
	}
	if scope != scopeFor(t.Context()) {
		return ErrNotFound
	}
	if t.binding.Rows != nil {
		t.binding.Rows[id] = claim
	}
	if t.binding.Enforce && claim != t.binding.Claim {
		return conflict("CloudFormation resource incarnation is not owned by this request")
	}
	return nil
}
func (t *ownershipTransaction) collect(kind, id string, scope Scope, claim Ownership) error {
	if kind != t.binding.Kind {
		return nil
	}
	if scope != scopeFor(t.Context()) {
		return ErrNotFound
	}
	if t.binding.Rows != nil {
		t.binding.Rows[id] = claim
	}
	return nil
}
func (t *ownershipTransaction) stamp(kind string, claim *Ownership) {
	if kind != t.binding.Kind {
		return
	}
	if t.binding.Release {
		*claim = Ownership{}
	} else {
		*claim = t.binding.Claim
	}
}
func (t *ownershipTransaction) API(k APIKey) (APIRecord, error) {
	v, err := t.Transaction.API(k)
	if err == nil {
		err = t.observe("RestApi", k.ID, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) APIs(k Scope) ([]APIRecord, error) {
	rows, err := t.Transaction.APIs(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("RestApi", k.ID, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutAPI(v APIRecord) error {
	t.stamp("RestApi", &v.Ownership)
	return t.Transaction.PutAPI(v)
}
func (t *ownershipTransaction) Resource(k ResourceKey) (ResourceRecord, error) {
	v, err := t.Transaction.Resource(k)
	if err == nil {
		err = t.observe("Resource", k.ID+"/"+k.ResourceID, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) Resources(k APIKey) ([]ResourceRecord, error) {
	rows, err := t.Transaction.Resources(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("Resource", k.ID+"/"+k.ResourceID, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutResource(v ResourceRecord) error {
	t.stamp("Resource", &v.Ownership)
	return t.Transaction.PutResource(v)
}
func (t *ownershipTransaction) Method(k MethodKey) (MethodRecord, error) {
	v, err := t.Transaction.Method(k)
	if err == nil {
		err = t.observe("Method", k.ID+"/"+k.ResourceID+"/"+k.HTTPMethod, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) Methods(k APIKey) ([]MethodRecord, error) {
	rows, err := t.Transaction.Methods(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("Method", k.ID+"/"+k.ResourceID+"/"+k.HTTPMethod, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutMethod(v MethodRecord) error {
	t.stamp("Method", &v.Ownership)
	return t.Transaction.PutMethod(v)
}
func (t *ownershipTransaction) Authorizer(k AuthorizerKey) (AuthorizerRecord, error) {
	v, err := t.Transaction.Authorizer(k)
	if err == nil {
		err = t.observe("Authorizer", k.ID+"/"+k.AuthorizerID, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) Authorizers(k APIKey) ([]AuthorizerRecord, error) {
	rows, err := t.Transaction.Authorizers(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("Authorizer", k.ID+"/"+k.AuthorizerID, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutAuthorizer(v AuthorizerRecord) error {
	t.stamp("Authorizer", &v.Ownership)
	return t.Transaction.PutAuthorizer(v)
}
func (t *ownershipTransaction) Deployment(k DeploymentKey) (DeploymentRecord, error) {
	v, err := t.Transaction.Deployment(k)
	if err == nil {
		err = t.observe("Deployment", k.ID+"/"+k.DeploymentID, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) Deployments(k APIKey) ([]DeploymentRecord, error) {
	rows, err := t.Transaction.Deployments(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("Deployment", k.ID+"/"+k.DeploymentID, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutDeployment(v DeploymentRecord) error {
	t.stamp("Deployment", &v.Ownership)
	return t.Transaction.PutDeployment(v)
}
func (t *ownershipTransaction) Stage(k StageKey) (StageRecord, error) {
	v, err := t.Transaction.Stage(k)
	if err == nil && t.binding.Kind == "Deployment" && v.Ownership != (Ownership{}) && v.Ownership != t.binding.Claim {
		err = conflict("Deployment stage is owned by another resource incarnation")
	}
	if err == nil {
		err = t.observe("Stage", k.ID+"/"+k.Name, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) Stages(k APIKey) ([]StageRecord, error) {
	rows, err := t.Transaction.Stages(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("Stage", k.ID+"/"+k.Name, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutStage(v StageRecord) error {
	if t.binding.Kind == "Deployment" {
		existing, err := t.Transaction.Stage(v.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil {
			if existing.Ownership != (Ownership{}) && existing.Ownership != t.binding.Claim {
				return conflict("Deployment stage is owned by another resource incarnation")
			}
			v.Ownership = existing.Ownership
		} else {
			// StageName may move a native stage, but only an absent stage is admitted
			// by this deployment and can participate in its rollback or deletion.
			v.Ownership = t.binding.Claim
		}
	}
	t.stamp("Stage", &v.Ownership)
	return t.Transaction.PutStage(v)
}
func (t *ownershipTransaction) ClientKey(k ClientKey) (ClientKeyRecord, error) {
	v, err := t.Transaction.ClientKey(k)
	if err == nil {
		err = t.observe("ApiKey", k.ID, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) ClientKeys(k Scope) ([]ClientKeyRecord, error) {
	rows, err := t.Transaction.ClientKeys(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("ApiKey", k.ID, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutClientKey(v ClientKeyRecord) error {
	t.stamp("ApiKey", &v.Ownership)
	return t.Transaction.PutClientKey(v)
}
func (t *ownershipTransaction) UsagePlan(k PlanKey) (UsagePlanRecord, error) {
	v, err := t.Transaction.UsagePlan(k)
	if err == nil {
		err = t.observe("UsagePlan", k.ID, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) UsagePlans(k Scope) ([]UsagePlanRecord, error) {
	rows, err := t.Transaction.UsagePlans(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		k := v.Key
		if err := t.collect("UsagePlan", k.ID, k.Scope, v.Ownership); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *ownershipTransaction) PutUsagePlan(v UsagePlanRecord) error {
	t.stamp("UsagePlan", &v.Ownership)
	return t.Transaction.PutUsagePlan(v)
}
func (t *ownershipTransaction) Account(k Scope) (AccountRecord, error) {
	v, err := t.Transaction.Account(k)
	if err == nil {
		err = t.observe("Account", k.Region, k, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) PutAccount(v AccountRecord) error {
	if t.binding.Kind == "Account" {
		existing, err := t.Transaction.Account(v.Scope)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && existing.Ownership != (Ownership{}) && existing.Ownership != t.binding.Claim {
			return conflict("Regional account settings are owned by another resource incarnation")
		}
	}
	t.stamp("Account", &v.Ownership)
	return t.Transaction.PutAccount(v)
}
func (t *ownershipTransaction) UsagePlanMembership(k PlanKey, id string) (UsagePlanMembership, error) {
	v, err := t.Transaction.UsagePlanMembership(k, id)
	if err == nil {
		err = t.observe("UsagePlanKey", k.ID+"/"+id, k.Scope, v.Ownership)
	}
	return v, err
}
func (t *ownershipTransaction) PutUsagePlanMembership(v UsagePlanMembership) error {
	t.stamp("UsagePlanKey", &v.Ownership)
	return t.Transaction.PutUsagePlanMembership(v)
}
func (t *ownershipTransaction) UsagePlanKeys(k PlanKey) ([]ClientKeyRecord, error) {
	rows, err := t.Transaction.UsagePlanKeys(k)
	if err != nil {
		return nil, err
	}
	if t.binding.Kind == "UsagePlanKey" {
		for _, row := range rows {
			v, err := t.Transaction.UsagePlanMembership(k, row.Key.ID)
			if err != nil {
				return nil, err
			}
			if err := t.collect("UsagePlanKey", k.ID+"/"+row.Key.ID, k.Scope, v.Ownership); err != nil {
				return nil, err
			}
		}
	}
	return rows, nil
}
