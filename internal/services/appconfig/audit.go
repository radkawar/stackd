package appconfig

import (
	"context"
	"stackd/journal"
)

type dataResourceKey struct{}
type dataResource struct{ ARN string }

// setDataResource receives identities resolved by the command's scoped repository
// read. It never projects user-supplied names or opaque polling tokens as ARNs.
func setDataResource(ctx context.Context, application, environment, profile string) {
	if resource, ok := ctx.Value(dataResourceKey{}).(*dataResource); ok {
		resource.ARN = envARN(scopeFor(ctx), application, environment) + "/configuration/" + profile
	}
}
func (s *Service) dataEventResources(ctx context.Context, _, _ any) ([]journal.APIEventResource, error) {
	resource, ok := ctx.Value(dataResourceKey{}).(*dataResource)
	if !ok || resource.ARN == "" {
		return nil, nil
	}
	return []journal.APIEventResource{{AccountID: scopeFor(ctx).AccountID, Type: "AWS::AppConfig::Configuration", ARN: resource.ARN}}, nil
}
