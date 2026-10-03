package elbv2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/elbv2"
	"strings"
)

var resourceName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?$`)

func validateName(name string, lb bool) error {
	if !resourceName.MatchString(name) || (lb && strings.HasPrefix(name, "internal-")) {
		return invalid("Name must contain 1-32 alphanumeric or hyphen characters and cannot begin or end with a hyphen")
	}
	return nil
}
func arn(sc Scope, resource string) string {
	return fmt.Sprintf("arn:%s:elasticloadbalancing:%s:%s:%s", sc.Partition, sc.Region, sc.AccountID, resource)
}
func scopedARN(sc Scope, v, kind string) error {
	if !strings.HasPrefix(v, arn(sc, kind+"/")) {
		return failure(kindError(kind), "The specified resource does not exist")
	}
	return nil
}
func kindError(kind string) string {
	switch kind {
	case "loadbalancer":
		return "LoadBalancerNotFound"
	case "targetgroup":
		return "TargetGroupNotFound"
	case "listener":
		return "ListenerNotFound"
	default:
		return "RuleNotFound"
	}
}
func resourceError(e error, kind string) error {
	if errors.Is(e, ErrNotFound) {
		return failure(kindError(kind), "The specified resource does not exist")
	}
	return e
}
func (s *Service) authorize(ctx context.Context, action, resource string, tags api.TagList, extra map[string][]string) error {
	if strings.HasPrefix(action, "Describe") {
		resource = "*"
		tags = nil
		extra = nil
	}
	if extra == nil {
		extra = map[string][]string{}
	}
	for _, t := range tags {
		extra["aws:ResourceTag/"+value(t.Key)] = []string{value(t.Value)}
		extra["elasticloadbalancing:ResourceTag/"+value(t.Key)] = []string{value(t.Value)}
	}
	now := s.clock.Now()
	if e := s.authorizer.Authorize(ctx, authorization.Request{Action: "elasticloadbalancing:" + action, ResourceARN: resource, ResourceAccountID: scopeFor(ctx).AccountID, Context: extra, EvaluationTime: &now}); e != nil {
		return e
	}
	return nil
}
func requestTags(tags api.TagList) map[string][]string {
	out := map[string][]string{}
	keys := make([]string, 0, len(tags))
	for _, t := range tags {
		out["aws:RequestTag/"+value(t.Key)] = []string{value(t.Value)}
		keys = append(keys, value(t.Key))
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		out["aws:TagKeys"] = keys
	}
	return out
}
func (s *Service) authorizeCreate(ctx context.Context, action, resource string, tags api.TagList, conditions map[string][]string) error {
	if e := validateTags(tags); e != nil {
		return e
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range requestTags(tags) {
		conditions[k] = v
	}
	if e := s.authorize(ctx, action, resource, nil, conditions); e != nil {
		return e
	}
	if len(tags) > 0 {
		conditions["elasticloadbalancing:CreateAction"] = []string{action}
		return s.authorize(ctx, "AddTags", resource, nil, conditions)
	}
	return nil
}
func loadBalancer(tx Reader, sc Scope, a string) (LoadBalancerRecord, error) {
	if e := scopedARN(sc, a, "loadbalancer"); e != nil {
		return LoadBalancerRecord{}, e
	}
	v, e := tx.LoadBalancer(sc, a)
	if e == nil && v.Deleting {
		e = ErrNotFound
	}
	return v, resourceError(e, "loadbalancer")
}
func targetGroup(tx Reader, sc Scope, a string) (TargetGroupRecord, error) {
	if e := scopedARN(sc, a, "targetgroup"); e != nil {
		return TargetGroupRecord{}, e
	}
	v, e := tx.TargetGroup(sc, a)
	return v, resourceError(e, "targetgroup")
}
func listener(tx Reader, sc Scope, a string) (ListenerRecord, error) {
	if e := scopedARN(sc, a, "listener"); e != nil {
		return ListenerRecord{}, e
	}
	v, e := tx.Listener(sc, a)
	return v, resourceError(e, "listener")
}
func rule(tx Reader, sc Scope, a string) (RuleRecord, error) {
	if e := scopedARN(sc, a, "listener-rule"); e != nil {
		return RuleRecord{}, e
	}
	v, e := tx.Rule(sc, a)
	return v, resourceError(e, "listener-rule")
}

// Markers bind the exact scope/filter and ordered last key, not mutable offsets.
func page[T any](items []T, marker *api.Marker, size *api.PageSize, query string, key func(T) string) ([]T, *api.Marker, error) {
	limit := 400
	if size != nil {
		limit = int(*size)
		if limit < 1 || limit > 400 {
			return nil, nil, invalid("PageSize must be between 1 and 400")
		}
	}
	sum := sha256.Sum256([]byte(query))
	prefix := fmt.Sprintf("%x:", sum[:])
	start := 0
	if marker != nil {
		decoded, e := base64.RawURLEncoding.DecodeString(string(*marker))
		if e != nil || !strings.HasPrefix(string(decoded), prefix) {
			return nil, nil, invalid("Invalid pagination marker")
		}
		last := strings.TrimPrefix(string(decoded), prefix)
		start = len(items)
		for i, item := range items {
			if key(item) > last {
				start = i
				break
			}
		}
	}
	end := min(start+limit, len(items))
	var next *api.Marker
	if end < len(items) {
		v := api.Marker(base64.RawURLEncoding.EncodeToString([]byte(prefix + key(items[end-1]))))
		next = &v
	}
	return items[start:end], next, nil
}
func actionTargetARNs(actions api.Actions) []string {
	out := []string{}
	for _, a := range actions {
		if v := value(a.TargetGroupArn); v != "" {
			out = append(out, v)
		}
		if a.ForwardConfig != nil {
			for _, t := range a.ForwardConfig.TargetGroups {
				if v := value(t.TargetGroupArn); v != "" {
					out = append(out, v)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Rebuild the single association projection after listener/rule mutation.
func refreshAssociations(tx Transaction, sc Scope) error {
	groups, e := tx.TargetGroups(sc)
	if e != nil {
		return e
	}
	ls, e := tx.Listeners(sc)
	if e != nil {
		return e
	}
	rs, e := tx.Rules(sc)
	if e != nil {
		return e
	}
	links := map[string]map[string]bool{}
	for _, l := range ls {
		for _, tg := range actionTargetARNs(l.Data.DefaultActions) {
			if links[tg] == nil {
				links[tg] = map[string]bool{}
			}
			links[tg][value(l.Data.LoadBalancerArn)] = true
		}
		for _, r := range rs {
			if r.ListenerARN != value(l.Data.ListenerArn) {
				continue
			}
			for _, tg := range actionTargetARNs(r.Data.Actions) {
				if links[tg] == nil {
					links[tg] = map[string]bool{}
				}
				links[tg][value(l.Data.LoadBalancerArn)] = true
			}
		}
	}
	for _, tg := range groups {
		tg.Data.LoadBalancerArns = api.LoadBalancerArns{}
		for lb := range links[value(tg.Data.TargetGroupArn)] {
			tg.Data.LoadBalancerArns = append(tg.Data.LoadBalancerArns, api.LoadBalancerArn(lb))
		}
		slices.Sort(tg.Data.LoadBalancerArns)
		if e = tx.PutTargetGroup(tg); e != nil {
			return e
		}
	}
	return nil
}
func validateActionNetwork(tx Reader, lb LoadBalancerRecord, actions api.Actions) error {
	for _, a := range actionTargetARNs(actions) {
		tg, e := targetGroup(tx, lb.Scope, a)
		if e != nil {
			return e
		}
		if value(tg.Data.VpcId) != value(lb.Data.VpcId) {
			return failure("InvalidConfigurationRequest", "Target group and load balancer must belong to the same VPC")
		}
		for _, bound := range tg.Data.LoadBalancerArns {
			if string(bound) != value(lb.Data.LoadBalancerArn) {
				return failure("TargetGroupAssociationLimit", "Target group is already associated with another load balancer")
			}
		}
	}
	return nil
}
func validateRedirectProtocol(protocol string, actions api.Actions) error {
	if protocol == "HTTPS" {
		for _, a := range actions {
			if a.RedirectConfig != nil && value(a.RedirectConfig.Protocol) == "HTTP" {
				return failure("InvalidLoadBalancerAction", "HTTPS listeners cannot redirect to HTTP")
			}
		}
	}
	return nil
}
func (s *Service) authorizeChildCreate(ctx context.Context, action, parent string, current api.TagList, child string, tags api.TagList, conditions map[string][]string) error {
	if e := validateTags(tags); e != nil {
		return e
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range requestTags(tags) {
		conditions[k] = v
	}
	if e := s.authorize(ctx, action, parent, current, conditions); e != nil {
		return e
	}
	if len(tags) == 0 {
		return nil
	}
	tagConditions := requestTags(tags)
	tagConditions["elasticloadbalancing:CreateAction"] = []string{action}
	return s.authorize(ctx, "AddTags", child, nil, tagConditions)
}
