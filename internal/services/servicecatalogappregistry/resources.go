package servicecatalogappregistry

import (
	"context"
	"slices"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/servicecatalogappregistry"
	"stackd/internal/awsctx"
	"stackd/internal/services/resourcegroups"
)

func options(apply bool) api.Options {
	if apply {
		return api.Options{api.AssociationOptionAPPLY_APPLICATION_TAG}
	}
	return api.Options{api.AssociationOptionSKIP_APPLICATION_TAG}
}
func parseOptions(in api.Options) (bool, error) {
	if len(in) > 1 {
		return false, failure("ValidationException", "Specify one association option.")
	}
	if len(in) == 0 {
		return false, nil
	}
	switch in[0] {
	case api.AssociationOptionAPPLY_APPLICATION_TAG:
		return true, nil
	case api.AssociationOptionSKIP_APPLICATION_TAG:
		return false, nil
	default:
		return false, failure("ValidationException", "Invalid association option.")
	}
}
func (s *Service) associationApplication(r Reader, id, action, kind, resource string) (Application, error) {
	a, ok, err := r.Application(scopeFor(r.Context()), id)
	if err != nil {
		return a, err
	}
	arn := a.ARN
	if !ok {
		arn = applicationARN(scopeFor(r.Context()), id)
	}
	conditions := map[string][]string{"servicecatalog:ResourceType": {kind}, "servicecatalog:Resource": {resource}}
	for k, v := range a.Tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	if denied := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "servicecatalog:" + action, ResourceARN: arn, Context: conditions}); denied != nil {
		return a, denied
	}
	if !ok {
		return a, failure("ResourceNotFoundException", "Application not found.")
	}
	return a, fenceParent(r.Context(), a.ID, a.ARN, a.CloudFormationClaim)
}
func (s *Service) associateResource(tx Transaction, in *api.AssociateResourceRequest) (*api.AssociateResourceResponse, error) {
	kind, ref := value(in.ResourceType), value(in.Resource)
	var config Configuration
	var err error
	if kind == "RESOURCE_TAG_VALUE" {
		config, err = tx.Configuration(scopeFor(tx.Context()))
		if err != nil {
			return nil, err
		}
		if config.TagKey == "" {
			return nil, failure("ValidationException", "No tag key configured for account "+scopeFor(tx.Context()).AccountID+".")
		}
	}
	a, err := s.associationApplication(tx, value(in.Application), "AssociateResource", kind, ref)
	if err != nil {
		return nil, err
	}
	apply, err := parseOptions(in.Options)
	if err != nil {
		return nil, err
	}
	if s.resources == nil || s.groups == nil || s.roles == nil {
		return nil, failure("NotImplementedException", "Resource association requires current resources, Resource Groups and AppRegistry IAM role authority.")
	}
	ctx := awsctx.WithViaService(tx.Context(), "servicecatalog-appregistry.amazonaws.com")
	var root resourcegroups.ApplicationResource
	var members []resourcegroups.ApplicationResource
	switch kind {
	case "CFN_STACK":
		if apply {
			root, members, err = s.resources.StackResources(ctx, ref)
			if err != nil {
				return nil, err
			}
		} else {
			var found bool
			root, found, err = s.resources.Resolve(ctx, ref)
			if err != nil {
				return nil, err
			}
			if !found || root.Type != "AWS::CloudFormation::Stack" {
				return nil, failure("ResourceNotFoundException", "The live CloudFormation stack does not exist.")
			}
		}
		if err := s.authorizeStack(ctx, root.ARN, "cloudformation:DescribeStacks"); err != nil {
			return nil, err
		}
	case "RESOURCE_TAG_VALUE":
		root = resourcegroups.ApplicationResource{Name: ref, Type: "AWS::ResourceGroups::Group"}
	default:
		return nil, failure("ValidationException", "Unsupported resource type.")
	}
	rows, err := tx.Associations(a.ARN)
	if err != nil {
		return nil, err
	}
	claim := edgeClaim(tx.Context())
	for _, row := range rows {
		if row.ResourceType == kind && (row.ResourceARN == root.ARN || row.ResourceName == ref) {
			// Only the exact creating incarnation replays; any other edge is independent.
			if claim != "" && row.CloudFormationClaim == claim {
				return &api.AssociateResourceResponse{ApplicationArn: new(api.ApplicationArn(a.ARN)), ResourceArn: new(api.Arn(row.ResourceARN)), Options: options(row.ApplyTag)}, nil
			}
			return nil, failure("ConflictException", "The resource is already associated with the application.")
		}
	}
	role, err := s.roles.Context(ctx, a.ARN, false)
	if err != nil {
		return nil, err
	}
	if kind == "CFN_STACK" {
		if _, err = s.groups.AssociateApplicationStack(role, a.ARN, a.GroupARN, root); err != nil {
			return nil, err
		}
		members = append([]resourcegroups.ApplicationResource{root}, members...)
	} else {
		root.ARN, err = s.groups.AssociateApplicationTagValue(role, a.ARN, a.GroupARN, config.TagKey, ref)
		if err != nil {
			return nil, err
		}
		root.Incarnation = root.ARN
		members, err = s.groups.ApplicationTagValueResources(ctx, root.ARN)
		if err != nil {
			return nil, err
		}
	}
	if apply {
		if err := s.groups.ApplyApplicationTags(ctx, a.TagGroupARN, members, false); err != nil {
			return nil, err
		}
	}
	row := Association{ApplicationARN: a.ARN, ResourceARN: root.ARN, ResourceName: root.Name, ResourceType: kind, Incarnation: root.Incarnation, CloudFormationClaim: claim, ApplyTag: apply, Created: s.clock.Now()}
	if err := tx.PutAssociation(row); err != nil {
		return nil, err
	}
	return &api.AssociateResourceResponse{ApplicationArn: new(api.ApplicationArn(a.ARN)), ResourceArn: new(api.Arn(root.ARN)), Options: options(apply)}, nil
}
func (s *Service) authorizeStack(ctx context.Context, arn, action string) error {
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: arn}); denied != nil {
		return denied
	}
	return nil
}
func association(r Reader, a Application, kind, ref string) (Association, error) {
	rows, err := r.Associations(a.ARN)
	if err != nil {
		return Association{}, err
	}
	for _, row := range rows {
		if row.ResourceType == kind && (row.ResourceARN == ref || row.ResourceName == ref) {
			return row, nil
		}
	}
	return Association{}, failure("ResourceNotFoundException", "Associated resource not found.")
}
func (s *Service) associatedMembers(ctx context.Context, row Association) ([]resourcegroups.ApplicationResource, error) {
	if row.ResourceType == "RESOURCE_TAG_VALUE" {
		return s.groups.ApplicationTagValueResources(ctx, row.ResourceARN)
	}
	root, found, err := s.resources.Resolve(ctx, row.ResourceARN)
	if err != nil {
		return nil, err
	}
	if !found || root.Incarnation != row.Incarnation {
		return nil, nil
	}
	_, members, err := s.resources.StackResources(ctx, row.ResourceARN)
	if err != nil {
		return nil, err
	}
	return append([]resourcegroups.ApplicationResource{root}, members...), nil
}
func (s *Service) disassociateResource(tx Transaction, in *api.DisassociateResourceRequest) (*api.DisassociateResourceResponse, error) {
	a, err := s.associationApplication(tx, value(in.Application), "DisassociateResource", value(in.ResourceType), value(in.Resource))
	if err != nil {
		return nil, err
	}
	row, err := association(tx, a, value(in.ResourceType), value(in.Resource))
	if err != nil {
		return nil, err
	}
	if !edgeOwned(tx.Context(), row.CloudFormationClaim) {
		return nil, failure("ResourceNotFoundException", "Associated resource not found.")
	}
	if s.groups == nil || s.resources == nil || s.roles == nil {
		return nil, failure("NotImplementedException", "Resource disassociation requires its resource and IAM owners.")
	}
	ctx := awsctx.WithViaService(tx.Context(), "servicecatalog-appregistry.amazonaws.com")
	if row.ApplyTag {
		members, err := s.associatedMembers(ctx, row)
		if err != nil {
			return nil, err
		}
		if err := s.groups.ApplyApplicationTags(ctx, a.TagGroupARN, members, true); err != nil {
			return nil, err
		}
	}
	role, err := s.roles.Context(ctx, a.ARN, false)
	if err != nil {
		return nil, err
	}
	if err := s.groups.DisassociateApplicationCollection(role, a.ARN, row.ResourceARN); err != nil {
		return nil, err
	}
	if err := tx.DeleteAssociation(a.ARN, row.ResourceARN); err != nil {
		return nil, err
	}
	return &api.DisassociateResourceResponse{ApplicationArn: new(api.ApplicationArn(a.ARN)), ResourceArn: new(api.Arn(row.ResourceARN))}, nil
}
func (s *Service) getAssociatedResource(tx Transaction, in *api.GetAssociatedResourceRequest) (*api.GetAssociatedResourceResponse, error) {
	a, err := s.loadApplication(tx, value(in.Application), "GetAssociatedResource")
	if err != nil {
		return nil, err
	}
	row, err := association(tx, a, value(in.ResourceType), value(in.Resource))
	if err != nil {
		return nil, err
	}
	groupARN := row.ResourceARN
	if row.ResourceType == "CFN_STACK" {
		scope := scopeFor(tx.Context())
		groupARN = "arn:" + scope.Partition + ":resource-groups:" + scope.Region + ":" + scope.AccountID + ":group/AWS_CloudFormation_Stack-" + row.ResourceName
	}
	out := &api.GetAssociatedResourceResponse{Options: options(row.ApplyTag), Resource: &api.Resource{Arn: new(api.Arn(row.ResourceARN)), Name: new(api.ResourceSpecifier(row.ResourceName)), AssociationTime: new(api.Timestamp(row.Created)), Integrations: &api.ResourceIntegrations{ResourceGroup: groupIntegration(groupARN)}}}
	if !row.ApplyTag {
		return out, nil
	}
	members, err := s.associatedMembers(tx.Context(), row)
	if err != nil {
		return nil, err
	}
	results := api.ResourcesList{}
	state := api.ApplicationTagStatusSUCCESS
	if row.ResourceType == "CFN_STACK" && len(members) == 0 {
		state = api.ApplicationTagStatusFAILURE
	}
	for _, r := range members {
		status := api.ResourceItemStatusSUCCESS
		if r.Tags["awsApplication"] != a.TagGroupARN {
			if r.TaggingPending {
				status = api.ResourceItemStatusIN_PROGRESS
				if state != api.ApplicationTagStatusFAILURE {
					state = api.ApplicationTagStatusIN_PROGRESS
				}
			} else {
				status = api.ResourceItemStatusFAILED
				state = api.ApplicationTagStatusFAILURE
			}
		}
		if len(in.ResourceTagStatus) == 0 || slices.Contains(in.ResourceTagStatus, status) {
			results = append(results, api.ResourcesListItem{ResourceArn: new(api.Arn(r.ARN)), ResourceType: new(api.ResourceItemType(r.Type)), Status: new(api.String(status))})
		}
	}
	page, next, err := paginate(tx.Context(), "GetAssociatedResource", a.ARN+"\x00"+row.ResourceARN+"\x00"+strings.Join(resourceStatuses(in.ResourceTagStatus), ","), in.NextToken, in.MaxResults, results, func(r api.ResourcesListItem) string { return value(r.ResourceArn) })
	if err != nil {
		return nil, err
	}
	out.ApplicationTagResult = &api.ApplicationTagResult{ApplicationTagStatus: new(state), Resources: page, NextToken: next}
	return out, nil
}
func resourceStatuses(rows api.GetAssociatedResourceFilter) []string {
	out := make([]string, len(rows))
	for i, v := range rows {
		out[i] = string(v)
	}
	return out
}
func (s *Service) listAssociatedResources(tx Transaction, in *api.ListAssociatedResourcesRequest) (*api.ListAssociatedResourcesResponse, error) {
	a, err := s.loadApplication(tx, value(in.Application), "ListAssociatedResources")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Associations(a.ARN)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		observeClaim(tx.Context(), row.ResourceARN, row.CloudFormationClaim)
	}
	page, next, err := paginate(tx.Context(), "ListAssociatedResources", a.ARN, in.NextToken, in.MaxResults, rows, func(r Association) string { return r.ResourceARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListAssociatedResourcesResponse{Resources: api.Resources{}, NextToken: next}
	for _, r := range page {
		item := api.ResourceInfo{Arn: new(api.Arn(r.ResourceARN)), Name: new(api.ResourceSpecifier(r.ResourceName)), ResourceType: new(api.ResourceType(r.ResourceType)), Options: options(r.ApplyTag)}
		if r.ResourceType == "RESOURCE_TAG_VALUE" {
			item.ResourceDetails = &api.ResourceDetails{TagValue: new(api.TagValue(r.ResourceName))}
		}
		out.Resources = append(out.Resources, item)
	}
	return out, nil
}
