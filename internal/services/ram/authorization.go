package ram

import (
	"errors"
	"maps"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ram"
)

// authorize follows the current RAM SAR: each requested principal/resource is a
// separate authorization context, not a multivalued scalar condition that could
// let one allowed association conceal another denied association.
func (s *Service) authorize(r Reader, op, arn string, tags map[string]string) error {
	if arn == "" {
		arn = "*"
	}
	base := map[string][]string{}
	accountGrant := false
	if strings.Contains(arn, ":resource-share/") {
		sh, e := r.Share(arn)
		if e == nil {
			tags = sh.Tags
			base["ram:ResourceShareName"] = []string{sh.Name}
			base["ram:AllowsExternalPrincipals"] = []string{strconv.FormatBool(sh.AllowExternal)}
			base["ram:RetainSharingOnAccountLeaveOrganization"] = []string{strconv.FormatBool(sh.RetainOnLeave)}
			if op == "ListResourceSharePermissions" && sh.AccountID != scopeFor(r.Context()).AccountID {
				accountGrant, e = s.visibleShare(r, sh, "OTHER-ACCOUNTS")
				if e != nil {
					return e
				}
				if !accountGrant {
					return ErrNotFound
				}
			}
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
	}
	if strings.Contains(arn, ":resource-share-invitation/") {
		i, e := r.Invitation(arn)
		if e != nil {
			return e
		}
		base["ram:ResourceShareName"] = []string{i.ShareName}
		base["ram:ShareOwnerAccountId"] = []string{i.Sender}
	}
	if strings.Contains(arn, ":permission/") {
		p, e := s.permission(r, arn)
		if e != nil {
			return e
		}
		tags = p.Tags
		base["ram:PermissionArn"] = []string{p.ARN}
		base["ram:PermissionResourceType"] = []string{p.ResourceType}
		accountGrant = p.Type == "AWS_MANAGED"
	}
	for k, v := range tags {
		base["aws:ResourceTag/"+k] = []string{v}
		base["ram:ResourceTag/"+k] = []string{v}
	}
	var resources api.ResourceArnList
	var principals api.PrincipalArnOrIdList
	var requestedTags api.TagList
	var tagKeys api.TagKeyList
	var extraPermission string
	request, _ := awsapi.FromContext(r.Context())
	switch in := request.Input.(type) {
	case *api.CreateResourceShareRequest:
		resources, principals, requestedTags = in.ResourceArns, in.Principals, in.Tags
		external := true
		if in.AllowExternalPrincipals != nil {
			external = bool(*in.AllowExternalPrincipals)
		}
		base["ram:RequestedAllowsExternalPrincipals"] = []string{strconv.FormatBool(external)}
		base["ram:AllowsExternalPrincipals"] = []string{strconv.FormatBool(external)}
		retain := false
		if in.ResourceShareConfiguration != nil && in.ResourceShareConfiguration.RetainSharingOnAccountLeaveOrganization != nil {
			retain = bool(*in.ResourceShareConfiguration.RetainSharingOnAccountLeaveOrganization)
		}
		base["ram:RetainSharingOnAccountLeaveOrganization"] = []string{strconv.FormatBool(retain)}
	case *api.AssociateResourceShareRequest:
		resources, principals = in.ResourceArns, in.Principals
	case *api.DisassociateResourceShareRequest:
		resources, principals = in.ResourceArns, in.Principals
	case *api.UpdateResourceShareRequest:
		if in.AllowExternalPrincipals != nil {
			base["ram:RequestedAllowsExternalPrincipals"] = []string{strconv.FormatBool(bool(*in.AllowExternalPrincipals))}
		}
	case *api.TagResourceRequest:
		requestedTags = in.Tags
	case *api.UntagResourceRequest:
		tagKeys = in.TagKeys
	case *api.CreatePermissionRequest:
		requestedTags = in.Tags
		base["ram:PermissionResourceType"] = []string{value(in.ResourceType)}
		base["ram:PermissionArn"] = []string{arnFor(scopeFor(r.Context()), "permission", value(in.Name))}
	case *api.AssociateResourceSharePermissionRequest:
		extraPermission = value(in.PermissionArn)
	case *api.DisassociateResourceSharePermissionRequest:
		extraPermission = value(in.PermissionArn)
	}
	for _, t := range requestedTags {
		key := value(t.Key)
		base["aws:RequestTag/"+key] = []string{value(t.Value)}
		base["aws:TagKeys"] = append(base["aws:TagKeys"], key)
	}
	for _, key := range tagKeys {
		base["aws:TagKeys"] = append(base["aws:TagKeys"], string(key))
	}
	now := s.clock.Now()
	check := func(resource string, conditions map[string][]string, accountGrant bool) error {
		if e := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "ram:" + op, ResourceARN: resource, ResourceAccountGrant: accountGrant, Context: conditions, EvaluationTime: &now}); e != nil {
			return wireError(e)
		}
		return nil
	}
	if len(resources) == 0 && len(principals) == 0 {
		if e := check(arn, base, accountGrant); e != nil {
			return e
		}
	}
	for _, resource := range resources {
		conditions := maps.Clone(base)
		conditions["ram:ResourceArn"] = []string{string(resource)}
		current, e := s.resolve(r, string(resource))
		if e != nil {
			return e
		}
		conditions["ram:RequestedResourceType"] = []string{current.ResourceType}
		if e = check(arn, conditions, accountGrant); e != nil {
			return e
		}
	}
	for _, principal := range principals {
		conditions := maps.Clone(base)
		conditions["ram:Principal"] = []string{string(principal)}
		if e := check(arn, conditions, accountGrant); e != nil {
			return e
		}
	}
	if extraPermission != "" && extraPermission != arn {
		p, e := s.permission(r, extraPermission)
		if e != nil {
			return e
		}
		conditions := map[string][]string{"ram:PermissionArn": {p.ARN}, "ram:PermissionResourceType": {p.ResourceType}}
		for k, v := range p.Tags {
			conditions["aws:ResourceTag/"+k] = []string{v}
		}
		// RAM owns these public permission definitions; the account-side grant
		// does not bypass identity, boundary, session, SCP or explicit denials.
		if e = check(extraPermission, conditions, p.Type == "AWS_MANAGED"); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) authorizeCreationTags(r Reader, in, out any) error {
	switch input := in.(type) {
	case *api.CreateResourceShareRequest:
		if len(input.Tags) > 0 {
			response, ok := out.(*api.CreateResourceShareResponse)
			if ok {
				return s.authorize(r, "TagResource", value(response.ResourceShare.ResourceShareArn), nil)
			}
		}
	case *api.CreatePermissionRequest:
		if len(input.Tags) > 0 {
			response, ok := out.(*api.CreatePermissionResponse)
			if ok {
				return s.authorize(r, "TagResource", value(response.Permission.Arn), nil)
			}
		}
	}
	return nil
}
