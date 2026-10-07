package wafv2

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/wafv2"
)

func registerWebACLs(s *Service) {
	register(s, "CreateWebACL", s.createWebACL)
	register(s, "GetWebACL", s.getWebACL)
	register(s, "ListWebACLs", s.listWebACLs)
	register(s, "UpdateWebACL", s.updateWebACL)
	register(s, "DeleteWebACL", s.deleteWebACL)
	register(s, "CheckCapacity", s.checkCapacity)
}

func webACLARN(sc Scope, name, id string) string {
	return "arn:" + sc.Partition + ":wafv2:" + sc.Region + ":" + sc.AccountID + ":regional/webacl/" + name + "/" + id
}

// LabelNamespace is the prefix AWS WAF adds to labels from this web ACL's rules.
func (v WebACL) LabelNamespace() string { return "awswaf:" + v.AccountID + ":webacl:" + v.Name + ":" }

func (v WebACL) model() *api.WebACL {
	d := v.Definition
	out := &api.WebACL{
		ARN: new(api.ResourceArn(v.ARN)), Name: new(api.EntityName(v.Name)), Id: new(api.EntityId(v.ID)),
		DefaultAction: &d.DefaultAction, Rules: d.Rules, VisibilityConfig: &d.VisibilityConfig,
		CustomResponseBodies: d.CustomResponseBodies, AssociationConfig: d.AssociationConfig,
		Capacity: new(api.ConsumedCapacity(v.Capacity)), LabelNamespace: new(api.LabelName(v.LabelNamespace())),
		ManagedByFirewallManager: new(api.Boolean(false)), RetrofittedByFirewallManager: new(api.Boolean(false)),
	}
	if out.Rules == nil {
		out.Rules = api.Rules{}
	}
	if v.Description != "" {
		out.Description = new(api.EntityDescription(v.Description))
	}
	return out
}

func (v WebACL) summary() api.WebACLSummary {
	out := api.WebACLSummary{ARN: new(api.ResourceArn(v.ARN)), Name: new(api.EntityName(v.Name)), Id: new(api.EntityId(v.ID)), LockToken: new(api.LockToken(v.LockToken))}
	if v.Description != "" {
		out.Description = new(api.EntityDescription(v.Description))
	}
	return out
}

func validDescription(v *api.EntityDescription) error {
	if v != nil && (len(*v) == 0 || len(*v) > 256) {
		return invalidParameter("DESCRIPTION", "Description", "Description must contain 1-256 characters")
	}
	return nil
}

// requestTags validates TagList input and returns tag conditions.
func requestTags(list api.TagList) (map[string]string, map[string][]string, error) {
	tags := map[string]string{}
	conditions := map[string][]string{}
	for _, tag := range list {
		key, val := value(tag.Key), value(tag.Value)
		if key == "" || len(key) > 128 || len(val) > 256 || tag.Value == nil {
			return nil, nil, invalidParameter("TAGS", key, "Tag keys must contain 1-128 characters and values 0-256 characters")
		}
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, nil, failure("WAFTagOperationException", "Tag keys can't start with aws:", 400)
		}
		if _, dup := tags[key]; dup {
			return nil, nil, invalidParameter("TAGS", key, "Tag keys must be unique")
		}
		tags[key] = val
		conditions["aws:RequestTag/"+key] = []string{val}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	if len(tags) > 50 {
		return nil, nil, failure("WAFLimitsExceededException", "A resource can have at most 50 tags", 400)
	}
	return tags, conditions, nil
}

// loadWebACL resolves a web ACL by name and ID within the regional scope.
func (s *Service) loadWebACL(ctx context.Context, r Reader, name, id string, action string) (WebACL, error) {
	sc := scopeFor(ctx)
	v, err := r.WebACL(sc, webACLARN(sc, name, id))
	if errors.Is(err, ErrNotFound) {
		return v, nonexistent("AWS WAF couldn’t find the web ACL " + name + " with ID " + id)
	}
	if err != nil {
		return v, err
	}
	if err := s.authorize(ctx, "wafv2:"+action, v.ARN, v.Tags, nil); err != nil {
		return v, err
	}
	return v, checkResourceOwner(ctx, v.Owner)
}

// webACLByARN resolves a regional web ACL ARN in the caller's scope.
func (s *Service) webACLByARN(ctx context.Context, r Reader, arn, action string) (WebACL, error) {
	sc := scopeFor(ctx)
	name, id, ok := parseEntityARN(sc, arn, "webacl")
	if !ok {
		return WebACL{}, invalidParameter("RESOURCE_ARN", arn, "The ARN must identify a REGIONAL web ACL in this account and Region")
	}
	return s.loadWebACL(ctx, r, name, id, action)
}

// parseEntityARN splits arn:partition:wafv2:region:account:regional/kind/name/id.
func parseEntityARN(sc Scope, arn, kind string) (string, string, bool) {
	prefix := "arn:" + sc.Partition + ":wafv2:" + sc.Region + ":" + sc.AccountID + ":regional/" + kind + "/"
	rest, ok := strings.CutPrefix(arn, prefix)
	if !ok {
		return "", "", false
	}
	name, id, ok := strings.Cut(rest, "/")
	return name, id, ok && entityName.MatchString(name) && id != "" && !strings.Contains(id, "/")
}

func (s *Service) authorizeReferences(ctx context.Context, action string, refs []string) error {
	for _, arn := range refs {
		if err := s.authorize(ctx, "wafv2:"+action, arn, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) createWebACL(ctx context.Context, t Transaction, in *api.CreateWebACLInput) (*api.CreateWebACLOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	name := value(in.Name)
	if !entityName.MatchString(name) {
		return nil, invalidParameter("NAME", name, "Name must match ^[\\w\\-]+$ and contain 1-128 characters")
	}
	if err := validDescription(in.Description); err != nil {
		return nil, err
	}
	tags, conditions, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	sc := scopeFor(ctx)
	definition, capacity, refs, err := admitDefinition(t, sc, definitionInput{
		DefaultAction: in.DefaultAction, Rules: in.Rules, VisibilityConfig: in.VisibilityConfig, CustomResponseBodies: in.CustomResponseBodies,
		AssociationConfig: in.AssociationConfig, ApplicationConfig: in.ApplicationConfig, CaptchaConfig: in.CaptchaConfig, ChallengeConfig: in.ChallengeConfig,
		DataProtectionConfig: in.DataProtectionConfig, MonetizationConfig: in.MonetizationConfig, OnSourceDDoSProtectionConfig: in.OnSourceDDoSProtectionConfig, TokenDomains: in.TokenDomains,
	})
	if err != nil {
		return nil, err
	}
	owner, err := resourceOwnerFor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeReferences(ctx, "CreateWebACL", refs); err != nil {
		return nil, err
	}
	existing, err := t.WebACLs(sc)
	if err != nil {
		return nil, err
	}
	for _, other := range existing {
		if other.Name == name {
			if err := s.authorize(ctx, "wafv2:CreateWebACL", other.ARN, other.Tags, conditions); err != nil {
				return nil, err
			}
			if owner != (ResourceOwner{}) && other.Owner == owner {
				summary := other.summary()
				return &api.CreateWebACLOutput{Summary: &summary}, nil
			}
			return nil, failure("WAFDuplicateItemException", "AWS WAF couldn’t perform the operation because some resource in your request is a duplicate of an existing one.", 400)
		}
	}
	id := uuid.NewString()
	v := WebACL{Scope: sc, Name: name, ID: id, ARN: webACLARN(sc, name, id), Description: value(in.Description), LockToken: uuid.NewString(), Definition: definition, Capacity: capacity, Tags: tags, Owner: owner}
	if err := s.authorize(ctx, "wafv2:CreateWebACL", v.ARN, nil, conditions); err != nil {
		return nil, err
	}
	if len(existing) >= 100 {
		return nil, failure("WAFLimitsExceededException", "The account already has the maximum of 100 regional web ACLs", 400)
	}
	v.Created = s.clock.Now().UTC()
	v.Updated = v.Created
	if err := t.PutWebACL(v); err != nil {
		return nil, err
	}
	summary := v.summary()
	return &api.CreateWebACLOutput{Summary: &summary}, nil
}

func (s *Service) getWebACL(ctx context.Context, t Transaction, in *api.GetWebACLInput) (*api.GetWebACLOutput, error) {
	var v WebACL
	var err error
	if arn := value(in.ARN); arn != "" {
		if in.Name != nil || in.Id != nil || in.Scope != nil {
			return nil, invalidParameter("RESOURCE_ARN", arn, "Specify either ARN or Name, Id and Scope")
		}
		v, err = s.webACLByARN(ctx, t, arn, "GetWebACL")
	} else {
		if err := requireRegional(in.Scope); err != nil {
			return nil, err
		}
		v, err = s.loadWebACL(ctx, t, value(in.Name), value(in.Id), "GetWebACL")
	}
	if err != nil {
		return nil, err
	}
	return &api.GetWebACLOutput{WebACL: v.model(), LockToken: new(api.LockToken(v.LockToken))}, nil
}

// page returns the window selected by an opaque offset marker.
func page(limit *api.PaginationLimit, marker *api.NextMarker, total int) (int, int, *api.NextMarker, error) {
	size := 100
	if limit != nil {
		if *limit < 1 || *limit > 100 {
			return 0, 0, nil, invalidParameter("LIMIT", "Limit", "Limit must be between 1 and 100")
		}
		size = int(*limit)
	}
	start := 0
	if m := value(marker); m != "" {
		n, err := strconv.Atoi(m)
		if err != nil || n < 0 || n > total {
			return 0, 0, nil, invalidParameter("NEXT_MARKER", m, "NextMarker is not valid")
		}
		start = n
	}
	end := min(start+size, total)
	var next *api.NextMarker
	if end < total {
		next = new(api.NextMarker(strconv.Itoa(end)))
	}
	return start, end, next, nil
}

func (s *Service) listWebACLs(ctx context.Context, t Transaction, in *api.ListWebACLsInput) (*api.ListWebACLsOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "wafv2:ListWebACLs", "", nil, nil); err != nil {
		return nil, err
	}
	rows, err := t.WebACLs(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	owner, err := resourceOwnerFor(ctx)
	if err != nil {
		return nil, err
	}
	if owner != (ResourceOwner{}) {
		owned := rows[:0]
		for _, v := range rows {
			if v.Owner == owner {
				if err := s.authorize(ctx, "wafv2:GetWebACL", v.ARN, v.Tags, nil); err != nil {
					return nil, err
				}
				owned = append(owned, v)
			}
		}
		rows = owned
	}
	start, end, next, err := page(in.Limit, in.NextMarker, len(rows))
	if err != nil {
		return nil, err
	}
	out := &api.ListWebACLsOutput{WebACLs: api.WebACLSummaries{}, NextMarker: next}
	for _, v := range rows[start:end] {
		out.WebACLs = append(out.WebACLs, v.summary())
	}
	return out, nil
}

func checkLock(current string, supplied *api.LockToken) error {
	if value(supplied) == "" {
		return invalidParameter("LOCK_TOKEN", "LockToken", "LockToken is required")
	}
	if value(supplied) != current {
		return failure("WAFOptimisticLockException", "AWS WAF couldn’t save your changes because you tried to update or delete a resource that has changed since you last retrieved it. Get the resource again, make any changes you need to make to the new copy, and retry your operation.", 400)
	}
	return nil
}

func (s *Service) updateWebACL(ctx context.Context, t Transaction, in *api.UpdateWebACLInput) (*api.UpdateWebACLOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	v, err := s.loadWebACL(ctx, t, value(in.Name), value(in.Id), "UpdateWebACL")
	if err != nil {
		return nil, err
	}
	if err := validDescription(in.Description); err != nil {
		return nil, err
	}
	definition, capacity, refs, err := admitDefinition(t, v.Scope, definitionInput{
		DefaultAction: in.DefaultAction, Rules: in.Rules, VisibilityConfig: in.VisibilityConfig, CustomResponseBodies: in.CustomResponseBodies,
		AssociationConfig: in.AssociationConfig, ApplicationConfig: in.ApplicationConfig, CaptchaConfig: in.CaptchaConfig, ChallengeConfig: in.ChallengeConfig,
		DataProtectionConfig: in.DataProtectionConfig, MonetizationConfig: in.MonetizationConfig, OnSourceDDoSProtectionConfig: in.OnSourceDDoSProtectionConfig, TokenDomains: in.TokenDomains,
	})
	if err != nil {
		return nil, err
	}
	if err := s.authorizeReferences(ctx, "UpdateWebACL", refs); err != nil {
		return nil, err
	}
	if err := checkLock(v.LockToken, in.LockToken); err != nil {
		return nil, err
	}
	v.Definition, v.Capacity, v.Description = definition, capacity, value(in.Description)
	v.LockToken, v.Updated = uuid.NewString(), s.clock.Now().UTC()
	if err := t.PutWebACL(v); err != nil {
		return nil, err
	}
	return &api.UpdateWebACLOutput{NextLockToken: new(api.LockToken(v.LockToken))}, nil
}

func (s *Service) deleteWebACL(ctx context.Context, t Transaction, in *api.DeleteWebACLInput) (*api.DeleteWebACLOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	v, err := s.loadWebACL(ctx, t, value(in.Name), value(in.Id), "DeleteWebACL")
	if err != nil {
		return nil, err
	}
	if err := checkLock(v.LockToken, in.LockToken); err != nil {
		return nil, err
	}
	live, err := s.liveAssociations(ctx, t, v.ARN)
	if err != nil {
		return nil, err
	}
	if len(live) > 0 {
		return nil, failure("WAFAssociatedItemException", "AWS WAF couldn’t perform the operation because your resource is being used by another resource or it’s associated with another resource.", 400)
	}
	// Remaining rows protect deleted or recreated resource incarnations only.
	stale, err := t.Associations(v.Scope, v.ARN)
	if err != nil {
		return nil, err
	}
	for _, a := range stale {
		if err := t.DeleteAssociation(a.Scope, a.ResourceARN); err != nil {
			return nil, err
		}
	}
	if err := t.DeleteWebACL(v.Scope, v.ARN); err != nil {
		return nil, err
	}
	return &api.DeleteWebACLOutput{}, nil
}

func (s *Service) checkCapacity(ctx context.Context, t Transaction, in *api.CheckCapacityInput) (*api.CheckCapacityOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "wafv2:CheckCapacity", "", nil, nil); err != nil {
		return nil, err
	}
	a := &admission{r: t, scope: scopeFor(ctx), ipSets: map[string]bool{}}
	capacity, err := a.rules(in.Rules, nil)
	if err != nil {
		return nil, err
	}
	return &api.CheckCapacityOutput{Capacity: new(api.ConsumedCapacity(capacity))}, nil
}
