package ram

import (
	"slices"
	api "stackd/internal/awsapi/ram"
	"strings"
)

func apiTags(tags map[string]string) api.TagList {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make(api.TagList, 0, len(keys))
	for _, k := range keys {
		out = append(out, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(tags[k]))})
	}
	return out
}
func readTags(tags api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range tags {
		k := value(t.Key)
		v := value(t.Value)
		if len(k) == 0 || len(k) > 128 || len(v) > 256 {
			return nil, failure("InvalidParameterException", "Invalid tag key or value.")
		}
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, failure("TagPolicyViolationException", "Tag keys beginning aws: are reserved.")
		}
		if _, ok := out[k]; ok {
			return nil, failure("InvalidParameterException", "Duplicate tag key.")
		}
		out[k] = v
	}
	if len(out) > 50 {
		return nil, failure("TagLimitExceededException", "A resource can have at most 50 tags.")
	}
	return out, nil
}
func tagsMatch(tags map[string]string, filters api.TagFilters) bool {
	for _, f := range filters {
		v, ok := tags[value(f.TagKey)]
		if !ok || len(f.TagValues) > 0 && !slices.Contains(f.TagValues, api.TagValue(v)) {
			return false
		}
	}
	return true
}
func (s *Service) getResourceShares(tx Transaction, in *api.GetResourceSharesRequest) (*api.GetResourceSharesResponse, error) {
	if e := s.authorize(tx, "GetResourceShares", "", nil); e != nil {
		return nil, e
	}
	shares, e := tx.Shares()
	if e != nil {
		return nil, e
	}
	out := api.ResourceShareList{}
	for _, sh := range shares {
		ok, e := s.visibleShare(tx, sh, value(in.ResourceOwner))
		if e != nil {
			return nil, e
		}
		if !ok || in.Name != nil && value(in.Name) != sh.Name || in.ResourceShareStatus != nil && value(in.ResourceShareStatus) != sh.Status || len(in.ResourceShareArns) > 0 && !slices.Contains(in.ResourceShareArns, api.String(sh.ARN)) || !tagsMatch(sh.Tags, in.TagFilters) {
			continue
		}
		if in.PermissionArn != nil {
			match := false
			for _, p := range sh.Permissions {
				if p.ARN == value(in.PermissionArn) && (in.PermissionVersion == nil || int32(*in.PermissionVersion) == p.Version) {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		v := apiShare(sh)
		if value(in.ResourceOwner) != "SELF" {
			v.Tags = nil
		}
		out = append(out, *v)
	}
	out, next, e := page(s, tx, "GetResourceShares", in, out, in.MaxResults, in.NextToken)
	return &api.GetResourceSharesResponse{ResourceShares: out, NextToken: next}, e
}
func (s *Service) getResourceShareAssociations(tx Transaction, in *api.GetResourceShareAssociationsRequest) (*api.GetResourceShareAssociationsResponse, error) {
	if e := s.authorize(tx, "GetResourceShareAssociations", "", nil); e != nil {
		return nil, e
	}
	kind := value(in.AssociationType)
	if kind != "RESOURCE" && kind != "PRINCIPAL" && kind != "SOURCE" {
		return nil, failure("InvalidParameterException", "Invalid association type.")
	}
	shares, e := tx.Shares()
	if e != nil {
		return nil, e
	}
	out := api.ResourceShareAssociationList{}
	sc := scopeFor(tx.Context())
	for _, sh := range shares {
		if sh.Scope != sc || len(in.ResourceShareArns) > 0 && !slices.Contains(in.ResourceShareArns, api.String(sh.ARN)) {
			continue
		}
		if kind == "RESOURCE" {
			for _, a := range sh.Resources {
				status := a.Status
				if status == "ASSOCIATED" {
					_, ok, e := s.currentResource(tx, a)
					if e != nil {
						return nil, e
					}
					if !ok {
						status = "DISASSOCIATED"
					}
				}
				if in.ResourceArn != nil && value(in.ResourceArn) != a.ARN || in.AssociationStatus != nil && value(in.AssociationStatus) != status {
					continue
				}
				out = append(out, resourceAssociation(sh, a, status))
			}
		}
		if kind == "PRINCIPAL" {
			for _, a := range sh.Principals {
				status, e := s.principalAssociationStatus(tx, a)
				if e != nil {
					return nil, e
				}
				if in.Principal != nil && value(in.Principal) != a.Principal || in.AssociationStatus != nil && value(in.AssociationStatus) != status {
					continue
				}
				out = append(out, apiAssociation(sh, a.Principal, kind, status, !a.Organization, a.Created, a.Updated))
			}
		}
	}
	out, next, e := page(s, tx, "GetResourceShareAssociations", in, out, in.MaxResults, in.NextToken)
	return &api.GetResourceShareAssociationsResponse{ResourceShareAssociations: out, NextToken: next}, e
}
func apiResource(sh Share, a ResourceAssociation) api.Resource {
	return api.Resource{Arn: new(api.String(a.ARN)), Type: new(api.String(a.ResourceType)), ResourceShareArn: new(api.String(sh.ARN)), Status: new(api.ResourceStatusAVAILABLE), ResourceRegionScope: new(api.ResourceRegionScopeREGIONAL), CreationTime: &a.Created, LastUpdatedTime: &a.Updated}
}
func (s *Service) listResources(tx Transaction, in *api.ListResourcesRequest) (*api.ListResourcesResponse, error) {
	if e := s.authorize(tx, "ListResources", "", nil); e != nil {
		return nil, e
	}
	shares, e := tx.Shares()
	if e != nil {
		return nil, e
	}
	out := api.ResourceList{}
	for _, sh := range shares {
		ok, e := s.visibleShare(tx, sh, value(in.ResourceOwner))
		if e != nil {
			return nil, e
		}
		if !ok || sh.Status != "ACTIVE" || len(in.ResourceShareArns) > 0 && !slices.Contains(in.ResourceShareArns, api.String(sh.ARN)) || value(in.ResourceRegionScope) == "GLOBAL" {
			continue
		}
		if in.Principal != nil {
			match := false
			for _, p := range sh.Principals {
				if p.Principal == value(in.Principal) && p.Status == "ASSOCIATED" {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		for _, a := range sh.Resources {
			if in.ResourceType != nil && value(in.ResourceType) != a.ResourceType || len(in.ResourceArns) > 0 && !slices.Contains(in.ResourceArns, api.String(a.ARN)) {
				continue
			}
			_, ok, e := s.currentResource(tx, a)
			if e != nil {
				return nil, e
			}
			if ok {
				out = append(out, apiResource(sh, a))
			}
		}
	}
	out, next, e := page(s, tx, "ListResources", in, out, in.MaxResults, in.NextToken)
	return &api.ListResourcesResponse{Resources: out, NextToken: next}, e
}
func (s *Service) listPrincipals(tx Transaction, in *api.ListPrincipalsRequest) (*api.ListPrincipalsResponse, error) {
	if e := s.authorize(tx, "ListPrincipals", "", nil); e != nil {
		return nil, e
	}
	shares, e := tx.Shares()
	if e != nil {
		return nil, e
	}
	out := api.PrincipalList{}
	for _, sh := range shares {
		ok, e := s.visibleShare(tx, sh, value(in.ResourceOwner))
		if e != nil {
			return nil, e
		}
		if !ok || sh.Status != "ACTIVE" || len(in.ResourceShareArns) > 0 && !slices.Contains(in.ResourceShareArns, api.String(sh.ARN)) {
			continue
		}
		if in.ResourceArn != nil || in.ResourceType != nil {
			match := false
			for _, a := range sh.Resources {
				if a.Status == "ASSOCIATED" && (in.ResourceArn == nil || value(in.ResourceArn) == a.ARN) && (in.ResourceType == nil || value(in.ResourceType) == a.ResourceType) {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		for _, p := range sh.Principals {
			if p.Status != "ASSOCIATED" || len(in.Principals) > 0 && !slices.Contains(in.Principals, api.String(p.Principal)) {
				continue
			}
			if value(in.ResourceOwner) == "OTHER-ACCOUNTS" {
				ok, e := s.principalActive(tx, sh, p, scopeFor(tx.Context()).AccountID)
				if e != nil {
					return nil, e
				}
				if !ok {
					continue
				}
			}
			out = append(out, api.Principal{Id: new(api.String(p.Principal)), ResourceShareArn: new(api.String(sh.ARN)), External: new(api.Boolean(!p.Organization)), CreationTime: &p.Created, LastUpdatedTime: &p.Updated})
		}
	}
	out, next, e := page(s, tx, "ListPrincipals", in, out, in.MaxResults, in.NextToken)
	return &api.ListPrincipalsResponse{Principals: out, NextToken: next}, e
}
func (s *Service) listResourceTypes(tx Transaction, in *api.ListResourceTypesRequest) (*api.ListResourceTypesResponse, error) {
	if e := s.authorize(tx, "ListResourceTypes", "", nil); e != nil {
		return nil, e
	}
	out := api.ServiceNameAndResourceTypeList{}
	if value(in.ResourceRegionScope) != "GLOBAL" {
		for _, kind := range s.resourceTypes {
			service, _, _ := strings.Cut(kind, ":")
			out = append(out, api.ServiceNameAndResourceType{ServiceName: new(api.String(service)), ResourceType: new(api.String(kind)), ResourceRegionScope: new(api.ResourceRegionScopeREGIONAL)})
		}
	}
	out, next, e := page(s, tx, "ListResourceTypes", in, out, in.MaxResults, in.NextToken)
	return &api.ListResourceTypesResponse{ResourceTypes: out, NextToken: next}, e
}
func (s *Service) getResourcePolicies(tx Transaction, in *api.GetResourcePoliciesRequest) (*api.GetResourcePoliciesResponse, error) {
	if e := s.authorize(tx, "GetResourcePolicies", "", nil); e != nil {
		return nil, e
	}
	out := api.PolicyList{}
	for _, arn := range in.ResourceArns {
		r, e := s.resolve(tx, string(arn))
		if e != nil {
			return nil, e
		}
		if r.AccountID != scopeFor(tx.Context()).AccountID {
			return nil, failure("OperationNotPermittedException", "Only the resource owner can inspect its policies.")
		}
		rows, e := s.resourcePolicies(tx, r.ARN, "", true)
		if e != nil {
			return nil, e
		}
		for _, p := range rows {
			document := p.Policy.Document
			if s.binder != nil {
				document, e = s.binder.RenderResourcePolicy(tx.Context(), p.Policy)
				if e != nil {
					return nil, e
				}
			}
			if in.Principal != nil && !strings.Contains(document, value(in.Principal)) {
				continue
			}
			out = append(out, api.Policy(document))
		}
	}
	out, next, e := page(s, tx, "GetResourcePolicies", in, out, in.MaxResults, in.NextToken)
	return &api.GetResourcePoliciesResponse{Policies: out, NextToken: next}, e
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceRequest) (*api.TagResourceResponse, error) {
	arn := value(in.ResourceArn)
	if arn == "" {
		arn = value(in.ResourceShareArn)
	} else if in.ResourceShareArn != nil {
		return nil, failure("InvalidParameterException", "Specify only one resource ARN.")
	}
	tags, e := readTags(in.Tags)
	if e != nil {
		return nil, e
	}
	if strings.Contains(arn, ":resource-share/") {
		sh, e := s.ownedShare(tx, arn, "TagResource", true)
		if e != nil {
			return nil, e
		}
		for k, v := range tags {
			sh.Tags[k] = v
		}
		if len(sh.Tags) > 50 {
			return nil, failure("TagLimitExceededException", "A resource can have at most 50 tags.")
		}
		if e = tx.PutShare(sh); e != nil {
			return nil, e
		}
	} else {
		p, e := s.mutablePermission(tx, arn, "TagResource")
		if e != nil {
			return nil, e
		}
		if p.Tags == nil {
			p.Tags = map[string]string{}
		}
		for k, v := range tags {
			p.Tags[k] = v
		}
		if len(p.Tags) > 50 {
			return nil, failure("TagLimitExceededException", "A resource can have at most 50 tags.")
		}
		if e = tx.PutPermission(p); e != nil {
			return nil, e
		}
	}
	return &api.TagResourceResponse{}, nil
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceRequest) (*api.UntagResourceResponse, error) {
	arn := value(in.ResourceArn)
	if arn == "" {
		arn = value(in.ResourceShareArn)
	} else if in.ResourceShareArn != nil {
		return nil, failure("InvalidParameterException", "Specify only one resource ARN.")
	}
	if strings.Contains(arn, ":resource-share/") {
		sh, e := s.ownedShare(tx, arn, "UntagResource", true)
		if e != nil {
			return nil, e
		}
		for _, k := range in.TagKeys {
			delete(sh.Tags, string(k))
		}
		if e = tx.PutShare(sh); e != nil {
			return nil, e
		}
	} else {
		p, e := s.mutablePermission(tx, arn, "UntagResource")
		if e != nil {
			return nil, e
		}
		for _, k := range in.TagKeys {
			delete(p.Tags, string(k))
		}
		if e = tx.PutPermission(p); e != nil {
			return nil, e
		}
	}
	return &api.UntagResourceResponse{}, nil
}
func (s *Service) listSourceAssociations(tx Transaction, in *api.ListSourceAssociationsRequest) (*api.ListSourceAssociationsResponse, error) {
	if e := s.authorize(tx, "ListSourceAssociations", "", nil); e != nil {
		return nil, e
	}
	for _, arn := range in.ResourceShareArns {
		if _, e := s.ownedShare(tx, string(arn), "ListSourceAssociations", false); e != nil {
			return nil, e
		}
	}
	rows, next, e := page(s, tx, "ListSourceAssociations", in, api.AssociatedSourceList{}, in.MaxResults, in.NextToken)
	return &api.ListSourceAssociationsResponse{SourceAssociations: rows, NextToken: next}, e
}
