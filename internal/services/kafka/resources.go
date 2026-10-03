package kafka

import (
	"context"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/kafka"
	"strconv"
)

func registerResources(s *Service) {
	register(s, "ListTagsForResource", func(ctx context.Context, t Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
		v, e := s.load(ctx, t, value(in.ResourceArn), "ListTagsForResource")
		if e != nil {
			return nil, e
		}
		out := &api.ListTagsForResourceOutput{}
		tagMap(&out.Tags, v.Tags)
		return out, nil
	})
	register(s, "TagResource", func(ctx context.Context, t Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
		v, e := s.load(ctx, t, value(in.ResourceArn), "TagResource")
		if e != nil {
			return nil, e
		}
		tags := plainTags(in.Tags)
		if e = s.authorize(ctx, v, "TagResource", requestTags(tags)); e != nil {
			return nil, e
		}
		if v.Tags == nil {
			v.Tags = map[string]string{}
		}
		for k, x := range tags {
			v.Tags[k] = x
		}
		if e = validateTags(v.Tags); e != nil {
			return nil, e
		}
		return &api.TagResourceOutput{}, t.PutCluster(v)
	})
	register(s, "UntagResource", func(ctx context.Context, t Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
		v, e := s.load(ctx, t, value(in.ResourceArn), "UntagResource")
		if e != nil {
			return nil, e
		}
		if e = s.authorize(ctx, v, "UntagResource", map[string][]string{"aws:TagKeys": plainList(in.TagKeys)}); e != nil {
			return nil, e
		}
		for _, k := range in.TagKeys {
			delete(v.Tags, string(k))
		}
		return &api.UntagResourceOutput{}, t.PutCluster(v)
	})
	register(s, "PutClusterPolicy", s.putPolicy)
	register(s, "GetClusterPolicy", s.getPolicy)
	register(s, "DeleteClusterPolicy", func(ctx context.Context, t Transaction, in *api.DeleteClusterPolicyInput) (*api.DeleteClusterPolicyOutput, error) {
		v, e := s.load(ctx, t, value(in.ClusterArn), "DeleteClusterPolicy")
		if e != nil {
			return nil, e
		}
		v.Policy = authorization.BoundPolicy{}
		v.PolicyVersion = 0
		return &api.DeleteClusterPolicyOutput{}, t.PutCluster(v)
	})
	register(s, "BatchAssociateScramSecret", s.associateSecrets)
	register(s, "BatchDisassociateScramSecret", s.disassociateSecrets)
	register(s, "ListScramSecrets", func(ctx context.Context, t Transaction, in *api.ListScramSecretsInput) (*api.ListScramSecretsOutput, error) {
		v, e := s.load(ctx, t, value(in.ClusterArn), "ListScramSecrets")
		if e != nil {
			return nil, e
		}
		rows := slices.Clone(v.Secrets)
		slices.Sort(rows)
		rows, next, e := page(rows, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListScramSecrets", v.ARN), func(x string) string { return x })
		if e != nil {
			return nil, e
		}
		out := &api.ListScramSecretsOutput{}
		stringList(&out.SecretArnList, rows)
		if next != "" {
			text(&out.NextToken, next)
		}
		return out, nil
	})
}
func (s *Service) putPolicy(ctx context.Context, t Transaction, in *api.PutClusterPolicyInput) (*api.PutClusterPolicyOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "PutClusterPolicy")
	if e != nil {
		return nil, e
	}
	if v.PolicyVersion > 0 && value(in.CurrentVersion) != strconv.FormatInt(v.PolicyVersion, 10) {
		return nil, invalid("The current policy version does not match")
	}
	if v.PolicyVersion == 0 && value(in.CurrentVersion) != "" {
		return nil, invalid("The policy does not exist")
	}
	binder, ok := s.authorizer.(authorization.PolicyBinder)
	if !ok {
		return nil, unsupported("Resource policy principal binding is unavailable")
	}
	bound, e := binder.BindResourcePolicy(ctx, value(in.Policy), authorization.ResourcePolicyOptions{})
	if e != nil {
		return nil, invalid(e.Error())
	}
	v.Policy = bound
	v.PolicyVersion++
	if e = t.PutCluster(v); e != nil {
		return nil, e
	}
	out := &api.PutClusterPolicyOutput{}
	text(&out.CurrentVersion, strconv.FormatInt(v.PolicyVersion, 10))
	return out, nil
}
func (s *Service) getPolicy(ctx context.Context, t Transaction, in *api.GetClusterPolicyInput) (*api.GetClusterPolicyOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "GetClusterPolicy")
	if e != nil {
		return nil, e
	}
	if v.Policy.Document == "" {
		return nil, ErrNotFound
	}
	binder, ok := s.authorizer.(authorization.PolicyBinder)
	if !ok {
		return nil, unsupported("Resource policy principal binding is unavailable")
	}
	document, e := binder.RenderResourcePolicy(ctx, v.Policy)
	if e != nil {
		return nil, e
	}
	out := &api.GetClusterPolicyOutput{}
	text(&out.CurrentVersion, strconv.FormatInt(v.PolicyVersion, 10))
	text(&out.Policy, document)
	return out, nil
}

type preparedKey struct{}
type preparedMutation struct {
	ARN, Incarnation string
	Version          int64
	Accepted         []string
	Rejected         []api.UnprocessedScramSecret
}

func checkPrepared(ctx context.Context, v ClusterRecord) error {
	p, ok := ctx.Value(preparedKey{}).(preparedMutation)
	if !ok {
		if len(v.Secrets) == 0 {
			return nil
		}
		return conflict("Secret authority was not prepared")
	}
	if p.ARN != v.ARN || p.Incarnation != v.Incarnation || p.Version != v.Version {
		return conflict("The cluster changed while secret authority was being checked")
	}
	return nil
}
func (s *Service) prepare(ctx context.Context, action string, in any) (context.Context, error) {
	arn := ""
	var refs []string
	mutation := false
	associate := false
	switch v := in.(type) {
	case *api.DescribeClusterInput:
		arn = value(v.ClusterArn)
	case *api.DescribeClusterV2Input:
		arn = value(v.ClusterArn)
	case *api.GetBootstrapBrokersInput:
		arn = value(v.ClusterArn)
	case *api.ListNodesInput:
		arn = value(v.ClusterArn)
	case *api.DeleteClusterInput:
		arn = value(v.ClusterArn)
		mutation = true
	case *api.BatchAssociateScramSecretInput:
		arn = value(v.ClusterArn)
		refs = plainList(v.SecretArnList)
		mutation = true
		associate = true
	case *api.BatchDisassociateScramSecretInput:
		arn = value(v.ClusterArn)
		refs = plainList(v.SecretArnList)
		mutation = true
	default:
		return ctx, nil
	}
	if !mutation {
		return ctx, s.observe(ctx, arn, action)
	}
	var v ClusterRecord
	e := s.repository.View(ctx, func(r Reader) error { var e error; v, e = s.load(r.Context(), r, arn, action); return e })
	if e != nil {
		return ctx, e
	}
	if action == "DeleteCluster" {
		refs = slices.Clone(v.Secrets)
		if x := value(in.(*api.DeleteClusterInput).CurrentVersion); x != "" && x != strconv.FormatInt(v.Version, 10) {
			return ctx, invalid("The current cluster version does not match")
		}
	} else {
		if e = writable(v); e != nil {
			return ctx, e
		}
		if v.SecurityMode != "SASL_SCRAM" {
			return ctx, invalid("The cluster does not use SCRAM authentication")
		}
		if len(refs) < 1 || len(refs) > 10 {
			return ctx, invalid("Provide between one and ten secret ARNs")
		}
	}
	if len(refs) > 0 && s.secrets == nil {
		return ctx, unsupported("No Secrets Manager owner is configured")
	}
	p := preparedMutation{ARN: v.ARN, Incarnation: v.Incarnation, Version: v.Version}
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if associate {
			var u SCRAMUser
			u, e = s.secrets.ResolveSCRAM(ctx, v.ARN, ref)
			if e == nil {
				spec := baseSpecification(v)
				spec.Users = []SCRAMUser{u}
				e = ValidateSpecification(spec)
			}
		} else {
			e = nil
		}
		if e != nil {
			if action == "DeleteCluster" {
				return ctx, e
			}
			r := api.UnprocessedScramSecret{}
			w := wireError(e)
			text(&r.SecretArn, ref)
			text(&r.ErrorCode, w.Code)
			text(&r.ErrorMessage, w.Message)
			p.Rejected = append(p.Rejected, r)
			continue
		}
		p.Accepted = append(p.Accepted, ref)
	}
	return context.WithValue(ctx, preparedKey{}, p), nil
}
func (s *Service) associateSecrets(ctx context.Context, t Transaction, in *api.BatchAssociateScramSecretInput) (*api.BatchAssociateScramSecretOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "BatchAssociateScramSecret")
	if e != nil {
		return nil, e
	}
	if e = checkPrepared(ctx, v); e != nil {
		return nil, e
	}
	p := ctx.Value(preparedKey{}).(preparedMutation)
	for _, ref := range p.Accepted {
		if e = s.secrets.AssociateSCRAM(ctx, v.ARN, ref); e != nil {
			return nil, e
		}
		if !slices.Contains(v.Secrets, ref) {
			v.Secrets = append(v.Secrets, ref)
		}
	}
	if len(v.Secrets) > 100 {
		return nil, invalid("A cluster supports at most 100 SCRAM secrets")
	}
	if len(p.Accepted) > 0 {
		if e = s.beginOperation(t, &v, "UPDATE_SCRAM_SECRETS"); e != nil {
			return nil, e
		}
	}
	out := &api.BatchAssociateScramSecretOutput{UnprocessedScramSecrets: p.Rejected}
	text(&out.ClusterArn, v.ARN)
	return out, nil
}
func (s *Service) disassociateSecrets(ctx context.Context, t Transaction, in *api.BatchDisassociateScramSecretInput) (*api.BatchDisassociateScramSecretOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "BatchDisassociateScramSecret")
	if e != nil {
		return nil, e
	}
	if e = checkPrepared(ctx, v); e != nil {
		return nil, e
	}
	p := ctx.Value(preparedKey{}).(preparedMutation)
	for _, ref := range p.Accepted {
		if slices.Contains(v.Secrets, ref) {
			if e = s.secrets.ReleaseSCRAM(ctx, v.ARN, ref); e != nil {
				return nil, e
			}
		}
	}
	v.Secrets = slices.DeleteFunc(v.Secrets, func(ref string) bool { return slices.Contains(p.Accepted, ref) })
	if len(p.Accepted) > 0 {
		if e = s.beginOperation(t, &v, "UPDATE_SCRAM_SECRETS"); e != nil {
			return nil, e
		}
	}
	out := &api.BatchDisassociateScramSecretOutput{UnprocessedScramSecrets: p.Rejected}
	text(&out.ClusterArn, v.ARN)
	return out, nil
}
