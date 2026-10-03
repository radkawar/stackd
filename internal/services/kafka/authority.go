package kafka

import (
	"context"
	"errors"
	"stackd/internal/authorization"
	"stackd/internal/awswire"
	"strings"
)

func arnScope(arn string) (Scope, error) {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[2] != "kafka" || p[1] == "" || p[3] == "" || p[4] == "" || p[5] == "" {
		return Scope{}, invalid("Invalid MSK ARN")
	}
	return Scope{p[1], p[4], p[3]}, nil
}
func (s *Service) authorize(ctx context.Context, v ClusterRecord, action string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, x := range v.Tags {
		conditions["aws:ResourceTag/"+k] = []string{x}
	}
	now := s.clock.Now()
	req := authorization.Request{Action: "kafka:" + action, ResourceARN: v.ARN, EvaluationTime: &now, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}
	if req.ResourceARN == "" {
		req.ResourceARN = "*"
	}
	if v.Policy.Document != "" {
		req.ResourcePolicies = []authorization.BoundPolicy{v.Policy}
	}
	if e := s.authorizer.Authorize(ctx, req); e != nil {
		return e
	}
	return nil
}

func (s *Service) authorizeClusterDescribe(ctx context.Context, v ClusterRecord, permission ClusterDescribePermission) error {
	err := s.authorize(ctx, v, "DescribeClusterV2", nil)
	if err == nil || permission != AllowEitherDescribeCluster {
		return err
	}
	var denied *awswire.Error
	if !errors.As(err, &denied) || denied.StatusCode != 403 {
		return err
	}
	// These are alternative API permissions, not IAM aliases: each decision
	// independently enforces its identity, resource, boundary and SCP policies.
	return s.authorize(ctx, v, "DescribeCluster", nil)
}
func (s *Service) load(ctx context.Context, r Reader, arn, action string) (ClusterRecord, error) {
	sc, e := arnScope(arn)
	if e != nil {
		return ClusterRecord{}, e
	}
	caller := scopeFor(ctx)
	if sc.Partition != caller.Partition || sc.Region != caller.Region {
		return ClusterRecord{}, ErrNotFound
	}
	v, e := r.Cluster(arn)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return v, e
	}
	if e != nil {
		v = ClusterRecord{Scope: sc, ARN: arn}
	}
	if a := s.authorize(ctx, v, action, nil); a != nil {
		return v, a
	}
	return v, e
}
func (s *Service) configuration(ctx context.Context, r Reader, arn, action string) (ConfigurationRecord, error) {
	sc, e := arnScope(arn)
	if e != nil {
		return ConfigurationRecord{}, e
	}
	if sc != scopeFor(ctx) {
		return ConfigurationRecord{}, invalid("Configuration ARN does not exist.")
	}
	if e = s.authorize(ctx, ClusterRecord{Scope: sc, ARN: arn}, action, nil); e != nil {
		return ConfigurationRecord{}, e
	}
	v, e := r.Configuration(arn)
	if errors.Is(e, ErrNotFound) {
		return v, invalid("Configuration ARN does not exist.")
	}
	return v, e
}
func requestTags(tags map[string]string) map[string][]string {
	c := map[string][]string{}
	for k, v := range tags {
		c["aws:RequestTag/"+k] = []string{v}
		c["aws:TagKeys"] = append(c["aws:TagKeys"], k)
	}
	return c
}
func validateTags(tags map[string]string) error {
	if len(tags) > 50 {
		return invalid("A resource may have at most 50 tags")
	}
	for k, v := range tags {
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalid("Invalid resource tag")
		}
	}
	return nil
}
func writable(v ClusterRecord) error {
	if v.State != "ACTIVE" && v.State != "FAILED" {
		return conflict("The cluster is not in a mutable state")
	}
	return nil
}
