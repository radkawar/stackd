package authorization

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"stackd/iam/policy"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

// AuthorizeResourceControls checks only resource-owner RCPs. The caller supplies
// authenticated condition context; this grants no identity or resource access.
// Signed requests use Authorize. STS also uses this boundary after validating
// an external federation identity, before publishing its role credentials.
func (e *Evaluator) AuthorizeResourceControls(ctx context.Context, accountID string, request policy.Request) *awswire.Error {
	if err := ctx.Err(); err != nil {
		return denied("Authorization canceled: " + err.Error())
	}
	if !catalog.AppliesResourceControlPolicy(request.Action) {
		return nil
	}
	request.Context = maps.Clone(request.Context)
	if request.Context == nil {
		request.Context = make(map[string][]string)
	}
	set, err := e.resourceControlContext(ctx, accountID, request.Context)
	if err != nil {
		return denied("Unable to resolve resource controls: " + err.Error())
	}
	return authorizeResourceControlSet(set, request)
}

func (e *Evaluator) resourceControlContext(ctx context.Context, accountID string, values map[string][]string) (ResourceControlSet, error) {
	var set ResourceControlSet
	source, ok := e.controls.(ResourceControlSource)
	if ok {
		var err error
		set, err = source.ResourceControlPolicies(ctx, accountID)
		if err != nil {
			return set, err
		}
	}
	for key, value := range map[string]string{"aws:resourceorgid": set.OrganizationID, "aws:resourceorgpaths": set.OrganizationPath} {
		if supplied, exists := values[key]; exists && (value == "" || !slices.Equal(supplied, []string{value})) {
			return set, fmt.Errorf("service context cannot override verified %s", key)
		}
		if value != "" {
			values[key] = []string{value}
		}
	}
	return set, nil
}

func authorizeResourceControlSet(set ResourceControlSet, request policy.Request) *awswire.Error {
	if !catalog.AppliesResourceControlPolicy(request.Action) {
		return nil
	}
	result, err := policy.AuthorizeResourceControls(request, set.Levels)
	if err != nil {
		return evaluationFailure(err)
	}
	if result.Decision != policy.Allow {
		return denied(result.Reason)
	}
	return nil
}
