package servicecatalogappregistry

import (
	"maps"
	"slices"

	api "stackd/internal/awsapi/servicecatalogappregistry"
	"stackd/internal/awsctx"
)

func applicationOutput(a Application) *api.Application {
	out := &api.Application{Id: new(api.ApplicationId(a.ID)), Arn: new(api.ApplicationArn(a.ARN)), Name: new(api.Name(a.Name)), CreationTime: new(api.Timestamp(a.Created)), LastUpdateTime: new(api.Timestamp(a.Modified)), Tags: tagsOutput(a.Tags), ApplicationTag: api.ApplicationTagDefinition{"awsApplication": api.TagValue(a.TagGroupARN)}}
	if a.Description != "" {
		out.Description = new(api.Description(a.Description))
	}
	return out
}
func applicationSummary(a Application) api.ApplicationSummary {
	v := applicationOutput(a)
	return api.ApplicationSummary{Id: v.Id, Arn: v.Arn, Name: v.Name, Description: v.Description, CreationTime: v.CreationTime, LastUpdateTime: v.LastUpdateTime}
}
func (s *Service) createApplication(tx Transaction, in *api.CreateApplicationRequest) (*api.CreateApplicationResponse, error) {
	tags, err := tagsInput(in.Tags)
	if err != nil {
		return nil, err
	}
	fingerprint, err := createFingerprint(struct {
		Name, Description string
		Tags              map[string]string
	}{value(in.Name), value(in.Description), tags})
	if err != nil {
		return nil, err
	}
	rows, err := tx.Applications(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	var replay *Application
	for _, a := range rows {
		if a.ClientToken == value(in.ClientToken) {
			replay = &a
			break
		}
	}
	scope := scopeFor(tx.Context())
	var a Application
	if replay != nil {
		a = *replay
	} else {
		id, err := identifier()
		if err != nil {
			return nil, err
		}
		a = Application{Scope: scope, ID: id, ARN: applicationARN(scope, id), Name: value(in.Name), Description: value(in.Description), ClientToken: value(in.ClientToken), CloudFormationClaim: parentClaim(tx.Context()), CreateFingerprint: fingerprint, Created: s.clock.Now(), Modified: s.clock.Now(), Tags: tags}
	}
	if err := s.authorize(tx.Context(), "CreateApplication", a.ARN, nil, tags, slices.Sorted(maps.Keys(tags))); err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		if err := s.authorize(tx.Context(), "TagResource", a.ARN, nil, tags, slices.Sorted(maps.Keys(tags))); err != nil {
			return nil, err
		}
	}
	if replay != nil {
		if claim := parentClaim(tx.Context()); claim != "" && a.CloudFormationClaim != claim {
			return nil, failure("ConflictException", "The client token belongs to an independent application.")
		}
		if a.CreateFingerprint != fingerprint {
			return nil, failure("ConflictException", "The client token is already associated with a different request.")
		}
		return &api.CreateApplicationResponse{Application: applicationOutput(a)}, nil
	}
	for _, existing := range rows {
		if existing.Name == a.Name {
			return nil, failure("ConflictException", "An application with this name already exists.")
		}
	}
	if s.groups == nil || s.roles == nil {
		return nil, failure("NotImplementedException", "Application creation requires Resource Groups and current IAM service-role authority.")
	}
	ctx, err := s.roles.Context(awsctx.WithViaService(tx.Context(), "servicecatalog-appregistry.amazonaws.com"), a.ARN, true)
	if err != nil {
		return nil, err
	}
	a.GroupARN, a.TagGroupARN, err = s.groups.CreateApplicationGroups(ctx, a.ARN, a.Name, a.Description, a.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.PutApplication(a); err != nil {
		return nil, err
	}
	return &api.CreateApplicationResponse{Application: applicationOutput(a)}, nil
}
func (s *Service) getApplication(tx Transaction, in *api.GetApplicationRequest) (*api.GetApplicationResponse, error) {
	a, err := s.loadApplication(tx, value(in.Application), "GetApplication")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Associations(a.ARN)
	if err != nil {
		return nil, err
	}
	v := applicationOutput(a)
	return &api.GetApplicationResponse{Id: v.Id, Arn: v.Arn, Name: v.Name, Description: v.Description, CreationTime: v.CreationTime, LastUpdateTime: v.LastUpdateTime, Tags: v.Tags, ApplicationTag: v.ApplicationTag, AssociatedResourceCount: new(api.AssociationCount(len(rows))), Integrations: &api.Integrations{ResourceGroup: groupIntegration(a.GroupARN), ApplicationTagResourceGroup: groupIntegration(a.TagGroupARN)}}, nil
}
func groupIntegration(arn string) *api.ResourceGroup {
	return &api.ResourceGroup{Arn: new(api.Arn(arn)), State: new(api.ResourceGroupStateCREATE_COMPLETE)}
}
func (s *Service) updateApplication(tx Transaction, in *api.UpdateApplicationRequest) (*api.UpdateApplicationResponse, error) {
	a, err := s.loadApplication(tx, value(in.Application), "UpdateApplication")
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		return nil, failure("ValidationException", "Updating the application name is not supported.")
	}
	if in.Description != nil {
		a.Description = value(in.Description)
	}
	a.Modified = s.clock.Now()
	if s.groups == nil || s.roles == nil {
		return nil, failure("NotImplementedException", "Application update requires Resource Groups and current IAM service-role authority.")
	}
	ctx, err := s.roles.Context(tx.Context(), a.ARN, true)
	if err != nil {
		return nil, err
	}
	if err := s.groups.UpdateApplicationGroups(ctx, a.ARN, a.Description); err != nil {
		return nil, err
	}
	if err := tx.PutApplication(a); err != nil {
		return nil, err
	}
	return &api.UpdateApplicationResponse{Application: applicationOutput(a)}, nil
}
func (s *Service) deleteApplication(tx Transaction, in *api.DeleteApplicationRequest) (*api.DeleteApplicationResponse, error) {
	a, err := s.loadApplication(tx, value(in.Application), "DeleteApplication")
	if err != nil {
		return nil, err
	}
	links, err := tx.AttributeGroupAssociations(a.ARN)
	if err != nil {
		return nil, err
	}
	resources, err := tx.Associations(a.ARN)
	if err != nil {
		return nil, err
	}
	if len(links) > 0 || len(resources) > 0 {
		return nil, failure("ConflictException", "Disassociate all resources and attribute groups before deleting the application.")
	}
	if s.groups == nil || s.roles == nil {
		return nil, failure("NotImplementedException", "Application deletion requires Resource Groups and current IAM service-role authority.")
	}
	ctx, err := s.roles.Context(tx.Context(), a.ARN, false)
	if err != nil {
		return nil, err
	}
	if err := s.groups.DeleteApplicationGroups(ctx, a.ARN); err != nil {
		return nil, err
	}
	if err := tx.DeleteApplication(a.Scope, a.ARN); err != nil {
		return nil, err
	}
	out := applicationSummary(a)
	return &api.DeleteApplicationResponse{Application: &out}, nil
}
func (s *Service) listApplications(tx Transaction, in *api.ListApplicationsRequest) (*api.ListApplicationsResponse, error) {
	if err := s.authorize(tx.Context(), "ListApplications", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	rows, err := tx.Applications(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		observeClaim(tx.Context(), a.ID, a.CloudFormationClaim)
	}
	page, next, err := paginate(tx.Context(), "ListApplications", "", in.NextToken, in.MaxResults, rows, func(a Application) string { return a.ARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListApplicationsResponse{Applications: api.ApplicationSummaries{}, NextToken: next}
	for _, a := range page {
		out.Applications = append(out.Applications, applicationSummary(a))
	}
	return out, nil
}
