package appconfig

import (
	"context"

	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

// ListTaggingResources reads live AppConfig identities and their current tags in
// the caller's transaction. It includes never-tagged resources; the tagging
// owner, not AppConfig, applies its previously-tagged membership rules.
func (s *Service) ListTaggingResources(ctx context.Context) ([]tagging.Resource, error) {
	var resources []tagging.Resource
	err := s.repository.View(ctx, func(r Reader) error {
		scope := scopeFor(r.Context())
		appendResource := func(resource, kind string) error {
			tags, err := r.Tags(scope, resource)
			if err != nil {
				return err
			}
			resources = append(resources, tagging.Resource{ARN: resource, ResourceType: "appconfig:" + kind, Tags: tags})
			return nil
		}
		applications, err := r.Applications(scope)
		if err != nil {
			return err
		}
		for _, application := range applications {
			if err := appendResource(appARN(scope, application.ID), "application"); err != nil {
				return err
			}
			if err := applicationTaggingResources(r, scope, application.ID, appendResource); err != nil {
				return err
			}
		}
		strategies, err := r.Strategies(scope)
		if err != nil {
			return err
		}
		for _, strategy := range strategies {
			if err := appendResource(strategyARN(scope, strategy.ID), "deploymentstrategy"); err != nil {
				return err
			}
		}
		extensions, err := r.Extensions(scope)
		if err != nil {
			return err
		}
		for _, extension := range extensions {
			if err := appendResource(extension.ARN, "extension"); err != nil {
				return err
			}
		}
		associations, err := r.Associations(scope)
		if err != nil {
			return err
		}
		for _, association := range associations {
			if err := appendResource(association.ARN, "extensionassociation"); err != nil {
				return err
			}
		}
		return nil
	})
	return resources, err
}

func applicationTaggingResources(r Reader, scope Scope, application string, appendResource func(string, string) error) error {
	environments, err := r.Environments(scope, application)
	if err != nil {
		return err
	}
	for _, environment := range environments {
		if err := appendResource(envARN(scope, application, environment.ID), "application/environment"); err != nil {
			return err
		}
		deployments, err := r.Deployments(scope, application, environment.ID)
		if err != nil {
			return err
		}
		for _, deployment := range deployments {
			if err := appendResource(deploymentARN(scope, application, environment.ID, deployment.Number), "application/environment/deployment"); err != nil {
				return err
			}
		}
	}
	profiles, err := r.Profiles(scope, application)
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		if err := appendResource(profileARN(scope, application, profile.ID), "application/configurationprofile"); err != nil {
			return err
		}
	}
	definitions, err := r.ExperimentDefinitions(scope, application)
	if err != nil {
		return err
	}
	for _, definition := range definitions {
		if err := appendResource(experimentDefinitionARN(scope, application, definition.ID), "application/experimentdefinition"); err != nil {
			return err
		}
		runs, err := r.ExperimentRuns(scope, application, definition.ID)
		if err != nil {
			return err
		}
		for _, run := range runs {
			if err := appendResource(experimentRunARN(scope, application, definition.ID, run.Number), "application/experimentdefinition/experimentrun"); err != nil {
				return err
			}
		}
	}
	return nil
}
