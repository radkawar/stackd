package resourcegroups

import (
	"context"
	"encoding/json"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/resourcegroups"
)

const applicationGroupType = "AWS::ResourceGroups::ApplicationGroup"
const registryGroupType = "AWS::AppRegistry::Application"
const stackGroupType = "AWS::CloudFormation::Stack"
const applicationTagKey = "awsApplication"

// CreateApplicationGroups is called only by the authenticated AppRegistry owner.
// It joins the application transaction; neither group can commit independently.
func (s *Service) CreateApplicationGroups(ctx context.Context, applicationARN, name, description, id string) (legacyARN, tagARN string, err error) {
	scope := scopeFor(ctx)
	tagName := name[:min(len(name), 150)] + "/" + id
	legacyARN = groupARN(scope, "AWS_AppRegistry_Application-"+name)
	tagARN = groupARN(scope, tagName)
	err = s.repository.Update(ctx, func(tx Transaction) error {
		groups := []Group{
			{Scope: scope, ARN: legacyARN, Name: "AWS_AppRegistry_Application-" + name, Description: description, Created: s.clock.Now(), ManagedType: registryGroupType, ApplicationARN: applicationARN, SourceARN: applicationARN, SourceName: name, Tags: map[string]string{"EnableAWSServiceCatalogAppRegistry": "true"}},
			{Scope: scope, ARN: tagARN, Name: tagName, DisplayName: name, Description: description, Created: s.clock.Now(), ManagedType: applicationGroupType, ApplicationARN: applicationARN, SourceARN: applicationARN, SourceName: name, Tags: map[string]string{"EnableAWSServiceCatalogAppRegistry": "true"}},
		}
		query, _ := json.Marshal(resourceQuery{ResourceTypeFilters: []string{"AWS::S3::Bucket", "AWS::SQS::Queue", "AWS::SSM::Parameter", "AWS::CloudFormation::Stack"}, TagFilters: []tagFilter{{Key: applicationTagKey, Values: []string{tagARN}}}})
		groups[1].Query = &api.ResourceQuery{Type: new(api.QueryTypeTAG_FILTERS_1_0), Query: new(api.Query(query))}
		for _, g := range groups {
			if _, exists, err := tx.Group(scope, g.ARN); err != nil {
				return err
			} else if exists {
				return failure("BadRequestException", "An application-owned group with this name already exists.")
			}
			if err := s.authorize(tx.Context(), "CreateGroup", nil, g.Tags, []string{"EnableAWSServiceCatalogAppRegistry"}); err != nil {
				return err
			}
			if err := tx.PutGroup(g); err != nil {
				return err
			}
		}
		return nil
	})
	return
}
func (s *Service) UpdateApplicationGroups(ctx context.Context, applicationARN, description string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Groups(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, g := range rows {
			if g.ApplicationARN == applicationARN && g.ManagedType != stackGroupType {
				if err := s.authorize(tx.Context(), "UpdateGroup", &g, nil, nil); err != nil {
					return err
				}
				g.Description = description
				if err := tx.PutGroup(g); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
func (s *Service) DeleteApplicationGroups(ctx context.Context, applicationARN string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Groups(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, g := range rows {
			if g.ApplicationARN != applicationARN {
				continue
			}
			if err := s.authorize(tx.Context(), "DeleteGroup", &g, nil, nil); err != nil {
				return err
			}
			if g.ManagedType == applicationGroupType && s.applicationResources != nil {
				live, err := s.applicationResources.List(tx.Context())
				if err != nil {
					return err
				}
				for _, r := range live {
					if r.Tags[applicationTagKey] == g.ARN {
						return failure("BadRequestException", "Remove application tags before deleting the application.")
					}
				}
			}
			if err := tx.DeleteGroup(g.Scope, g.ARN); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Service) AssociateApplicationStack(ctx context.Context, applicationARN, parentARN string, stack ApplicationResource) (string, error) {
	arn := groupARN(scopeFor(ctx), "AWS_CloudFormation_Stack-"+stack.Name)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if existing, ok, err := tx.Group(scopeFor(ctx), arn); err != nil {
			return err
		} else if ok {
			if existing.ApplicationARN != applicationARN || existing.SourceARN != stack.ARN {
				return failure("BadRequestException", "The stack is already associated with an application.")
			}
			return nil
		}
		g := Group{Scope: scopeFor(ctx), ARN: arn, Name: "AWS_CloudFormation_Stack-" + stack.Name, Created: s.clock.Now(), ManagedType: stackGroupType, ApplicationARN: applicationARN, SourceARN: stack.ARN, SourceName: stack.Name, ParentARN: parentARN, Tags: map[string]string{"EnableAWSServiceCatalogAppRegistry": "true"}}
		if err := s.authorize(tx.Context(), "CreateGroup", nil, g.Tags, []string{"EnableAWSServiceCatalogAppRegistry"}); err != nil {
			return err
		}
		return tx.PutGroup(g)
	})
	return arn, err
}
func (s *Service) DisassociateApplicationCollection(ctx context.Context, applicationARN, resourceARN string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Groups(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, g := range rows {
			if g.ApplicationARN == applicationARN && g.ParentARN != "" && (g.SourceARN == resourceARN || g.ARN == resourceARN) {
				if err := s.authorize(tx.Context(), "DeleteGroup", &g, nil, nil); err != nil {
					return err
				}
				if err := tx.DeleteGroup(g.Scope, g.ARN); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ApplyApplicationTags authorizes the delegated caller, not the managed-group role.
// The outer AppRegistry attempt atomically includes every owner tag and grouping.
func (s *Service) ApplyApplicationTags(ctx context.Context, groupARN string, resources []ApplicationResource, remove bool) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		g, ok, err := tx.Group(scopeFor(ctx), groupARN)
		if err != nil {
			return err
		}
		if !ok || g.ManagedType != applicationGroupType {
			return failure("NotFoundException", "The application group does not exist.")
		}
		action := "AssociateResource"
		tagAction := "tag:TagResources"
		if remove {
			action = "DisassociateResource"
			tagAction = "tag:UntagResources"
		}
		if err := s.authorize(tx.Context(), action, &g, nil, nil); err != nil {
			return err
		}
		for _, a := range []string{"tag:GetResources", tagAction} {
			if rejected := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: a, ResourceARN: "*"}); rejected != nil {
				return rejected
			}
		}
		for _, r := range resources {
			if err := s.changeApplicationMember(tx, g, r, remove); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Service) changeApplicationMember(tx Transaction, g Group, r ApplicationResource, remove bool) error {
	if s.applicationResources == nil {
		return failure("NotImplementedException", "Application grouping requires current resource owners.")
	}
	action := "GROUP"
	if remove {
		action = "UNGROUP"
		if r.Tags[applicationTagKey] == g.ARN {
			if err := s.applicationResources.Untag(tx.Context(), r, []string{applicationTagKey}); err != nil {
				return err
			}
		}
	} else {
		if err := s.applicationResources.Tag(tx.Context(), r, map[string]string{applicationTagKey: g.ARN}); err != nil {
			return err
		}
	}
	live, ok, err := s.applicationResources.Resolve(tx.Context(), r.ARN)
	if err != nil {
		return err
	}
	if !ok || live.Incarnation != r.Incarnation {
		return failure("ResourceGroupsValidationException", "The resource incarnation changed.")
	}
	status := groupingStatus(g.ARN, action, live)
	if status == "FAILED" {
		return failure("ResourceGroupsValidationException", "The resource owner did not apply the requested application tag transition.")
	}
	return tx.PutGrouping(Grouping{GroupARN: g.ARN, ResourceARN: r.ARN, ResourceType: r.Type, Incarnation: r.Incarnation, Action: action, Status: status, Updated: s.clock.Now()})
}
func groupConfiguration(g Group) *api.GroupConfiguration {
	parameters := api.GroupParameterList{}
	if g.ManagedType != applicationGroupType {
		parameters = append(parameters, api.GroupConfigurationParameter{Name: new(api.GroupConfigurationParameterName("Name")), Values: api.GroupConfigurationParameterValueList{api.GroupConfigurationParameterValue(g.SourceName)}}, api.GroupConfigurationParameter{Name: new(api.GroupConfigurationParameterName("Arn")), Values: api.GroupConfigurationParameterValueList{api.GroupConfigurationParameterValue(g.SourceARN)}})
	}
	return &api.GroupConfiguration{Status: new(api.GroupConfigurationStatusUPDATE_COMPLETE), Configuration: api.GroupConfigurationList{{Type: new(api.GroupConfigurationType(g.ManagedType)), Parameters: parameters}}}
}
