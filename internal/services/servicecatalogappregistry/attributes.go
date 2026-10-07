package servicecatalogappregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/servicecatalogappregistry"
)

func createFingerprint(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func validateAttributes(attributes string) error {
	// Attributes are customer metadata, not a JSON Schema document. Keep their
	// original representation, including numbers and whitespace, on retrieval.
	trimmed := strings.TrimSpace(attributes)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid([]byte(attributes)) {
		return failure("ValidationException", "Attributes must be a valid JSON object.")
	}
	return nil
}

func attributeGroupOutput(g AttributeGroup) *api.AttributeGroup {
	out := &api.AttributeGroup{
		Id: new(api.AttributeGroupId(g.ID)), Arn: new(api.AttributeGroupArn(g.ARN)),
		Name: new(api.Name(g.Name)), CreationTime: new(api.Timestamp(g.Created)),
		LastUpdateTime: new(api.Timestamp(g.Modified)), Tags: tagsOutput(g.Tags),
	}
	if g.Description != "" {
		out.Description = new(api.Description(g.Description))
	}
	return out
}

func attributeGroupSummary(g AttributeGroup) api.AttributeGroupSummary {
	out := api.AttributeGroupSummary{
		Id: new(api.AttributeGroupId(g.ID)), Arn: new(api.AttributeGroupArn(g.ARN)),
		Name: new(api.Name(g.Name)), CreationTime: new(api.Timestamp(g.Created)),
		LastUpdateTime: new(api.Timestamp(g.Modified)),
	}
	if g.Description != "" {
		out.Description = new(api.Description(g.Description))
	}
	// CreatedBy identifies an AWS service principal, not the customer account.
	// Direct customer-created groups do not have a creating service principal.
	return out
}

func (s *Service) createAttributeGroup(tx Transaction, in *api.CreateAttributeGroupRequest) (*api.CreateAttributeGroupResponse, error) {
	tags, err := tagsInput(in.Tags)
	if err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	rows, err := tx.AttributeGroups(scope)
	if err != nil {
		return nil, err
	}
	var group AttributeGroup
	replay := false
	for _, existing := range rows {
		if existing.ClientToken == value(in.ClientToken) {
			group, replay = existing, true
			break
		}
	}
	if !replay {
		id, err := identifier()
		if err != nil {
			return nil, err
		}
		group = AttributeGroup{Scope: scope, ID: id, ARN: attributeARN(scope, id)}
	}
	keys := slices.Sorted(maps.Keys(tags))
	if err := s.authorize(tx.Context(), "CreateAttributeGroup", group.ARN, group.Tags, tags, keys); err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		if err := s.authorize(tx.Context(), "TagResource", group.ARN, group.Tags, tags, keys); err != nil {
			return nil, err
		}
	}
	if err := validateAttributes(value(in.Attributes)); err != nil {
		return nil, err
	}
	fingerprint, err := createFingerprint(struct {
		Name, Description, Attributes string
		Tags                          map[string]string
	}{value(in.Name), value(in.Description), value(in.Attributes), tags})
	if err != nil {
		return nil, err
	}
	if replay {
		if claim := parentClaim(tx.Context()); claim != "" && group.CloudFormationClaim != claim {
			return nil, failure("ConflictException", "The client token belongs to an independent attribute group.")
		}
		if group.CreateFingerprint != fingerprint {
			return nil, failure("ConflictException", "The client token is already associated with a different request.")
		}
		return &api.CreateAttributeGroupResponse{AttributeGroup: attributeGroupOutput(group)}, nil
	}
	for _, existing := range rows {
		if existing.Name == value(in.Name) {
			return nil, failure("ConflictException", "An attribute group with this name already exists.")
		}
	}
	group.Name, group.Description, group.Attributes = value(in.Name), value(in.Description), value(in.Attributes)
	group.ClientToken, group.CreateFingerprint = value(in.ClientToken), fingerprint
	group.CloudFormationClaim = parentClaim(tx.Context())
	group.Created = s.clock.Now()
	group.Modified, group.Tags = group.Created, tags
	if err := tx.PutAttributeGroup(group); err != nil {
		return nil, err
	}
	return &api.CreateAttributeGroupResponse{AttributeGroup: attributeGroupOutput(group)}, nil
}

func (s *Service) getAttributeGroup(tx Transaction, in *api.GetAttributeGroupRequest) (*api.GetAttributeGroupResponse, error) {
	group, err := s.loadAttributeGroup(tx, value(in.AttributeGroup), "GetAttributeGroup")
	if err != nil {
		return nil, err
	}
	out := attributeGroupOutput(group)
	return &api.GetAttributeGroupResponse{
		Id: out.Id, Arn: out.Arn, Name: out.Name, Description: out.Description,
		CreationTime: out.CreationTime, LastUpdateTime: out.LastUpdateTime,
		Tags: out.Tags, Attributes: new(api.Attributes(group.Attributes)),
	}, nil
}

func (s *Service) updateAttributeGroup(tx Transaction, in *api.UpdateAttributeGroupRequest) (*api.UpdateAttributeGroupResponse, error) {
	group, err := s.loadAttributeGroup(tx, value(in.AttributeGroup), "UpdateAttributeGroup")
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		return nil, failure("ValidationException", "Updating the attribute group name is not supported.")
	}
	if in.Attributes != nil {
		if err := validateAttributes(value(in.Attributes)); err != nil {
			return nil, err
		}
		group.Attributes = value(in.Attributes)
	}
	if in.Description != nil {
		group.Description = value(in.Description)
	}
	group.Modified = s.clock.Now()
	if err := tx.PutAttributeGroup(group); err != nil {
		return nil, err
	}
	return &api.UpdateAttributeGroupResponse{AttributeGroup: attributeGroupOutput(group)}, nil
}

func (s *Service) deleteAttributeGroup(tx Transaction, in *api.DeleteAttributeGroupRequest) (*api.DeleteAttributeGroupResponse, error) {
	group, err := s.loadAttributeGroup(tx, value(in.AttributeGroup), "DeleteAttributeGroup")
	if err != nil {
		return nil, err
	}
	// The repository removes the normalized association links with the group.
	if err := tx.DeleteAttributeGroup(group.Scope, group.ARN); err != nil {
		return nil, err
	}
	out := attributeGroupSummary(group)
	return &api.DeleteAttributeGroupResponse{AttributeGroup: &out}, nil
}

func (s *Service) listAttributeGroups(tx Transaction, in *api.ListAttributeGroupsRequest) (*api.ListAttributeGroupsResponse, error) {
	if err := s.authorize(tx.Context(), "ListAttributeGroups", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	rows, err := tx.AttributeGroups(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	for _, g := range rows {
		observeClaim(tx.Context(), g.ID, g.CloudFormationClaim)
	}
	page, next, err := paginate(tx.Context(), "ListAttributeGroups", "", in.NextToken, in.MaxResults, rows, func(g AttributeGroup) string { return g.ARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListAttributeGroupsResponse{AttributeGroups: make(api.AttributeGroupSummaries, 0, len(page)), NextToken: next}
	for _, group := range page {
		out.AttributeGroups = append(out.AttributeGroups, attributeGroupSummary(group))
	}
	return out, nil
}

func (s *Service) associateAttributeGroup(tx Transaction, in *api.AssociateAttributeGroupRequest) (*api.AssociateAttributeGroupResponse, error) {
	application, err := s.loadApplication(tx, value(in.Application), "AssociateAttributeGroup")
	if err != nil {
		return nil, err
	}
	group, err := s.loadAttributeGroup(tx, value(in.AttributeGroup), "AssociateAttributeGroup")
	if err != nil {
		return nil, err
	}
	links, err := tx.AttributeGroupAssociations(application.ARN)
	if err != nil {
		return nil, err
	}
	out := &api.AssociateAttributeGroupResponse{ApplicationArn: new(api.ApplicationArn(application.ARN)), AttributeGroupArn: new(api.AttributeGroupArn(group.ARN))}
	claim := edgeClaim(tx.Context())
	for _, link := range links {
		if link.AttributeGroupARN != group.ARN {
			continue
		}
		// Only the exact creating incarnation replays; any other edge is independent.
		if claim != "" && link.CloudFormationClaim == claim {
			return out, nil
		}
		return nil, failure("ConflictException", "The attribute group is already associated with this application.")
	}
	if err := tx.AssociateAttributeGroup(AttributeGroupAssociation{ApplicationARN: application.ARN, AttributeGroupARN: group.ARN, CloudFormationClaim: claim}); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) disassociateAttributeGroup(tx Transaction, in *api.DisassociateAttributeGroupRequest) (*api.DisassociateAttributeGroupResponse, error) {
	application, err := s.loadApplication(tx, value(in.Application), "DisassociateAttributeGroup")
	if err != nil {
		return nil, err
	}
	group, err := s.loadAttributeGroup(tx, value(in.AttributeGroup), "DisassociateAttributeGroup")
	if err != nil {
		return nil, err
	}
	links, err := tx.AttributeGroupAssociations(application.ARN)
	if err != nil {
		return nil, err
	}
	found := false
	for _, link := range links {
		found = found || link.AttributeGroupARN == group.ARN && edgeOwned(tx.Context(), link.CloudFormationClaim)
	}
	if !found {
		return nil, failure("ResourceNotFoundException", "The attribute group is not associated with this application.")
	}
	if err := tx.DisassociateAttributeGroup(application.ARN, group.ARN); err != nil {
		return nil, err
	}
	return &api.DisassociateAttributeGroupResponse{ApplicationArn: new(api.ApplicationArn(application.ARN)), AttributeGroupArn: new(api.AttributeGroupArn(group.ARN))}, nil
}

func (s *Service) listAssociatedAttributeGroups(tx Transaction, in *api.ListAssociatedAttributeGroupsRequest) (*api.ListAssociatedAttributeGroupsResponse, error) {
	application, err := s.loadApplication(tx, value(in.Application), "ListAssociatedAttributeGroups")
	if err != nil {
		return nil, err
	}
	links, err := tx.AttributeGroupAssociations(application.ARN)
	if err != nil {
		return nil, err
	}
	observeAttributeLinks(tx, links)
	page, next, err := paginate(tx.Context(), "ListAssociatedAttributeGroups", application.ARN, in.NextToken, in.MaxResults, links, func(link AttributeGroupAssociation) string { return link.AttributeGroupARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListAssociatedAttributeGroupsResponse{AttributeGroups: make(api.AttributeGroupIds, 0, len(page)), NextToken: next}
	for _, link := range page {
		group, ok, err := tx.AttributeGroup(application.Scope, link.AttributeGroupARN)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, failure("InternalServerException", "An associated attribute group is missing.")
		}
		out.AttributeGroups = append(out.AttributeGroups, api.AttributeGroupId(group.ID))
	}
	return out, nil
}

func (s *Service) listAttributeGroupsForApplication(tx Transaction, in *api.ListAttributeGroupsForApplicationRequest) (*api.ListAttributeGroupsForApplicationResponse, error) {
	application, err := s.loadApplication(tx, value(in.Application), "ListAttributeGroupsForApplication")
	if err != nil {
		return nil, err
	}
	links, err := tx.AttributeGroupAssociations(application.ARN)
	if err != nil {
		return nil, err
	}
	observeAttributeLinks(tx, links)
	page, next, err := paginate(tx.Context(), "ListAttributeGroupsForApplication", application.ARN, in.NextToken, in.MaxResults, links, func(link AttributeGroupAssociation) string { return link.AttributeGroupARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListAttributeGroupsForApplicationResponse{AttributeGroupsDetails: make(api.AttributeGroupDetailsList, 0, len(page)), NextToken: next}
	for _, link := range page {
		group, ok, err := tx.AttributeGroup(application.Scope, link.AttributeGroupARN)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, failure("InternalServerException", "An associated attribute group is missing.")
		}
		// AWS no longer supports Name in this operation's details shape.
		out.AttributeGroupsDetails = append(out.AttributeGroupsDetails, api.AttributeGroupDetails{Id: new(api.AttributeGroupId(group.ID)), Arn: new(api.AttributeGroupArn(group.ARN))})
	}
	return out, nil
}

// observeAttributeLinks reports claimed edges only to a trusted controller.
func observeAttributeLinks(tx Transaction, links []AttributeGroupAssociation) {
	for _, link := range links {
		observeClaim(tx.Context(), link.AttributeGroupARN, link.CloudFormationClaim)
	}
}
