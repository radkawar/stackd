package apigateway

import (
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/apigateway"
)

func usagePlanKeyOutput(key ClientKeyRecord) *api.UsagePlanKey {
	return &api.UsagePlanKey{Id: ptr(key.Key.ID), Name: (*api.String)(key.Name), Type: ptr("API_KEY"), Value: ptr(key.Value)}
}

// attachUsagePlanKey admits both public associations and CSV-imported keys. The
// caller owns authorization; referenced records are already scoped and resolved.
func (s *Service) attachUsagePlanKey(tx Transaction, plan UsagePlanRecord, key ClientKeyRecord) error {
	if _, err := tx.UsagePlanMembership(plan.Key, key.Key.ID); err == nil {
		return conflict("API key is already associated with this usage plan")
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := usagePlanStageConflict(tx, plan, key.Key); err != nil {
		return err
	}
	return tx.PutUsagePlanMembership(UsagePlanMembership{Plan: plan.Key, ClientKeyID: key.Key.ID, Created: s.clock.Now()})
}

// The same constraint applies when attaching a key and when adding stages to a
// plan that already has keys. Distinct APIs with the same stage name do not clash.
func usagePlanStageConflict(r Reader, plan UsagePlanRecord, key ClientKey) error {
	if len(plan.Stages) == 0 {
		return nil
	}
	plans, err := r.UsagePlansForKey(key)
	if err != nil {
		return err
	}
	for _, other := range plans {
		if other.Key == plan.Key {
			continue
		}
		for _, stage := range plan.Stages {
			if slices.ContainsFunc(other.Stages, func(v UsagePlanStage) bool { return v.Key == stage.Key }) {
				return conflict("API key is already associated with a usage plan for API stage " + stage.Key.ID + ":" + stage.Key.Name)
			}
		}
	}
	return nil
}

func (s *Service) createUsagePlanKey(tx Transaction, in *api.CreateUsagePlanKeyRequest) (*api.UsagePlanKey, error) {
	plan, err := s.usagePlan(tx, value(in.UsagePlanId), "POST", "/keys")
	if err != nil {
		return nil, err
	}
	if value(in.KeyType) != "API_KEY" {
		return nil, bad("Invalid key type; expected API_KEY")
	}
	key, err := tx.ClientKey(ClientKey{Scope: plan.Key.Scope, ID: value(in.KeyId)})
	if err != nil {
		return nil, err
	}
	if err := s.attachUsagePlanKey(tx, plan, key); err != nil {
		return nil, err
	}
	return usagePlanKeyOutput(key), nil
}

func (s *Service) getUsagePlanKey(tx Transaction, in *api.GetUsagePlanKeyRequest) (*api.UsagePlanKey, error) {
	plan, err := s.usagePlan(tx, value(in.UsagePlanId), "GET", "/keys/"+value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if _, err := tx.UsagePlanMembership(plan.Key, value(in.KeyId)); err != nil {
		return nil, err
	}
	key, err := tx.ClientKey(ClientKey{Scope: plan.Key.Scope, ID: value(in.KeyId)})
	if err != nil {
		return nil, err
	}
	return usagePlanKeyOutput(key), nil
}

func (s *Service) getUsagePlanKeys(tx Transaction, in *api.GetUsagePlanKeysRequest) (*api.UsagePlanKeys, error) {
	plan, err := s.usagePlan(tx, value(in.UsagePlanId), "GET", "/keys")
	if err != nil {
		return nil, err
	}
	rows, err := tx.UsagePlanKeys(plan.Key)
	if err != nil {
		return nil, err
	}
	query := value(in.NameQuery)
	if query != "" {
		rows = slices.DeleteFunc(rows, func(key ClientKeyRecord) bool { return key.Name == nil || !strings.HasPrefix(*key.Name, query) })
	}
	rows, next, err := page(rows, plan.Key.Scope, "usageplans/"+plan.Key.ID+"/keys?name="+query, in.Limit, in.Position, func(key ClientKeyRecord) string { return key.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.UsagePlanKeys{Items: make(api.ListOfUsagePlanKey, 0, len(rows)), Position: next}
	for _, key := range rows {
		out.Items = append(out.Items, *usagePlanKeyOutput(key))
	}
	return out, nil
}

func (s *Service) deleteUsagePlanKey(tx Transaction, in *api.DeleteUsagePlanKeyRequest) (*api.Unit, error) {
	plan, err := s.usagePlan(tx, value(in.UsagePlanId), "DELETE", "/keys/"+value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if _, err := tx.UsagePlanMembership(plan.Key, value(in.KeyId)); err != nil {
		return nil, err
	}
	if err := tx.DeleteUsagePlanMembership(plan.Key, value(in.KeyId)); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}
