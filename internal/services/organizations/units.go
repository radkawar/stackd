package organizations

import (
	"net/http"
	"strings"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) registerUnitOperations() {
	register(s, "CreateOrganizationalUnit", (*operationState).createUnit)
	register(s, "UpdateOrganizationalUnit", (*operationState).updateUnit)
	register(s, "DescribeOrganizationalUnit", func(s *operationState, r *http.Request, in *api.DescribeOrganizationalUnitInput) (*api.DescribeOrganizationalUnitOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		unit, ok := o.units[inputString(in.OrganizationalUnitId)]
		if !ok {
			return nil, failure("OrganizationalUnitNotFoundException", "The organizational unit does not exist.")
		}
		return &api.DescribeOrganizationalUnitOutput{OrganizationalUnit: new(o.unitAPI(unit))}, nil
	})
	register(s, "DeleteOrganizationalUnit", func(s *operationState, r *http.Request, in *api.DeleteOrganizationalUnitInput) (*api.DeleteOrganizationalUnitOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		if _, ok := o.units[inputString(in.OrganizationalUnitId)]; !ok {
			return nil, failure("OrganizationalUnitNotFoundException", "The organizational unit does not exist.")
		}
		for _, parent := range o.parents {
			if parent == inputString(in.OrganizationalUnitId) {
				return nil, failure("OrganizationalUnitNotEmptyException", "Move or remove children before deleting the organizational unit.")
			}
		}
		delete(o.units, inputString(in.OrganizationalUnitId))
		delete(o.parents, inputString(in.OrganizationalUnitId))
		delete(o.attachments, inputString(in.OrganizationalUnitId))
		delete(o.tags, inputString(in.OrganizationalUnitId))
		return &api.DeleteOrganizationalUnitOutput{}, nil
	})
	register(s, "ListOrganizationalUnitsForParent", (*operationState).listUnits)
	register(s, "ListParents", (*operationState).listParents)
	register(s, "ListChildren", (*operationState).listChildren)
}

func (s *operationState) createUnit(r *http.Request, in *api.CreateOrganizationalUnitInput) (*api.CreateOrganizationalUnitOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if !o.parentExists(inputString(in.ParentId)) {
		return nil, failure("ParentNotFoundException", "The parent does not exist.")
	}
	for id, unit := range o.units {
		if o.parents[id] == inputString(in.ParentId) && unit.Name == inputString(in.Name) {
			return nil, failure("DuplicateOrganizationalUnitException", "A sibling organizational unit has this name.")
		}
	}
	depth := 1
	for parent := inputString(in.ParentId); parent != o.root.ID; parent = o.parents[parent] {
		depth++
	}
	if depth > 5 {
		return nil, failure("ConstraintViolationException", "OU_DEPTH_LIMIT_EXCEEDED: Organizational units can be nested at most five levels.")
	}
	if len(o.units) >= 2000 {
		return nil, failure("ConstraintViolationException", "OU_NUMBER_LIMIT_EXCEEDED")
	}
	tags, err := mergeTags(nil, in.Tags)
	if err != nil {
		return nil, err
	}
	id := s.createdResourceID
	unit := organizationalUnit{ID: id, ARN: o.arn(awsctx.FromContext(r.Context()).Partition, "ou", id), Name: inputString(in.Name)}
	o.units[id] = unit
	o.parents[id] = inputString(in.ParentId)
	o.tags[id] = tags
	o.attachDefaults(id)
	return &api.CreateOrganizationalUnitOutput{OrganizationalUnit: new(o.unitAPI(unit))}, nil
}

func (s *operationState) updateUnit(r *http.Request, in *api.UpdateOrganizationalUnitInput) (*api.UpdateOrganizationalUnitOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	unit, ok := o.units[inputString(in.OrganizationalUnitId)]
	if !ok {
		return nil, failure("OrganizationalUnitNotFoundException", "The organizational unit does not exist.")
	}
	if in.Name != nil && strings.TrimSpace(string(*in.Name)) != "" {
		for id, sibling := range o.units {
			if id != unit.ID && o.parents[id] == o.parents[unit.ID] && sibling.Name == string(*in.Name) {
				return nil, failure("DuplicateOrganizationalUnitException", "A sibling organizational unit has this name.")
			}
		}
		unit.Name = string(*in.Name)
	}
	o.units[unit.ID] = unit
	return &api.UpdateOrganizationalUnitOutput{OrganizationalUnit: new(o.unitAPI(unit))}, nil
}

func (s *operationState) listUnits(r *http.Request, in *api.ListOrganizationalUnitsForParentInput) (*api.ListOrganizationalUnitsForParentOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if !o.parentExists(inputString(in.ParentId)) {
		return nil, failure("ParentNotFoundException", "The parent does not exist.")
	}
	items := make([]api.OrganizationalUnit, 0)
	for id, unit := range o.units {
		if o.parents[id] == inputString(in.ParentId) {
			items = append(items, o.unitAPI(unit))
		}
	}
	items, next, err := paginate(s, items, in, o.organization.ID+"/units/"+inputString(in.ParentId), func(v api.OrganizationalUnit) string { return inputString(v.Id) })
	return &api.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: items, NextToken: nextToken(next)}, err
}

func (s *operationState) listParents(r *http.Request, in *api.ListParentsInput) (*api.ListParentsOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	parent, ok := o.parents[inputString(in.ChildId)]
	if !ok {
		return nil, failure("ChildNotFoundException", "The child account or organizational unit does not exist.")
	}
	kind := "ORGANIZATIONAL_UNIT"
	if parent == o.root.ID {
		kind = "ROOT"
	}
	items, next, err := paginate(s, []api.Parent{{Id: new(api.ParentId(parent)), Type: new(api.ParentType(kind))}}, in, o.organization.ID+"/parents/"+inputString(in.ChildId), func(v api.Parent) string { return inputString(v.Id) })
	return &api.ListParentsOutput{Parents: items, NextToken: nextToken(next)}, err
}

func (s *operationState) listChildren(r *http.Request, in *api.ListChildrenInput) (*api.ListChildrenOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if !o.parentExists(inputString(in.ParentId)) {
		return nil, failure("ParentNotFoundException", "The parent does not exist.")
	}
	items := make(api.Children, 0)
	for id, parent := range o.parents {
		_, isAccount := o.accounts[id]
		if parent == inputString(in.ParentId) && (isAccount == (inputString(in.ChildType) == "ACCOUNT")) {
			items = append(items, api.Child{Id: new(api.ChildId(id)), Type: in.ChildType})
		}
	}
	items, next, err := paginate(s, items, in, o.organization.ID+"/children/"+inputString(in.ParentId)+"/"+inputString(in.ChildType), func(v api.Child) string { return inputString(v.Id) })
	return &api.ListChildrenOutput{Children: items, NextToken: nextToken(next)}, err
}
