package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"stackd/internal/services/cloudformation"
)

func cfnLambdaAliasRouting(p cloudformation.Properties) (map[string]float64, error) {
	weights := map[string]float64{}
	raw, found := p["RoutingConfig"]
	if !found {
		return weights, nil
	}
	object, ok := cfnComputeObject(raw)
	if !ok {
		return nil, fmt.Errorf("RoutingConfig must be an object")
	}
	var config struct {
		AdditionalVersionWeights []struct {
			FunctionVersion string
			FunctionWeight  *json.Number
		}
	}
	if err := cfnMessagingDecode(object, &config); err != nil {
		return nil, err
	}
	if len(config.AdditionalVersionWeights) > 1 {
		return nil, fmt.Errorf("AdditionalVersionWeights permits at most one secondary version")
	}
	for _, entry := range config.AdditionalVersionWeights {
		if entry.FunctionVersion == "" || entry.FunctionWeight == nil {
			return nil, fmt.Errorf("routing entries require FunctionVersion and FunctionWeight")
		}
		weight, err := entry.FunctionWeight.Float64()
		if err != nil || math.IsNaN(weight) || math.IsInf(weight, 0) || weight < 0 || weight > 1 {
			return nil, fmt.Errorf("FunctionWeight must be between zero and one")
		}
		weights[entry.FunctionVersion] = weight
	}
	return weights, nil
}

func (h cfnLambdaAlias) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	requested, present, err := cfnLambdaProvisioned(r.Properties)
	if err != nil {
		return false, err
	}
	_, previous := r.Previous["ProvisionedConcurrencyConfig"]
	if !present && !previous {
		return true, nil
	}
	function, name, err := cfnLambdaQualifiedIdentity(r)
	if err != nil {
		return false, err
	}
	ctx = cfnLambdaAliasContext(ctx, r)
	return cfnLambdaStabilizeProvisioned(ctx, h.commands, function, name, requested, present, previous)
}
