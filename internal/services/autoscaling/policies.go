package autoscaling

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	api "stackd/internal/awsapi/autoscaling"
)

func registerPolicies(s *Service) {
	register(s, "PutScalingPolicy", s.putScalingPolicy)
	register(s, "DescribePolicies", s.describePolicies)
	register(s, "DeletePolicy", s.deletePolicy)
	register(s, "ExecutePolicy", s.executePolicy)
}

func (s *Service) putScalingPolicy(ctx context.Context, tx Transaction, in *api.PutScalingPolicyInput) (*api.PutScalingPolicyOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "PutScalingPolicy")
	if err != nil {
		return nil, err
	}
	name := value(in.PolicyName)
	if name == "" || len(name) > 255 {
		return nil, invalid("PolicyName is required and must not exceed 255 characters")
	}
	key := PolicyKey{GroupKey: g.Key, Name: name}
	record, err := tx.Policy(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	existing := err == nil
	if errors.Is(err, ErrNotFound) {
		rows, err := tx.Policies(g.Key)
		if err != nil {
			return nil, err
		}
		if len(rows) >= 50 {
			return nil, failure("LimitExceeded", "You may not create more than 50 scaling policies for an Auto Scaling group")
		}
		resource := "arn:" + g.Key.Partition + ":autoscaling:" + g.Key.Region + ":" + g.Key.AccountID + ":scalingPolicy:" + uuid.NewString() + ":autoScalingGroupName/" + g.Key.Name + ":policyName/" + name
		record = PolicyRecord{Key: key, GroupID: g.ID, Data: api.ScalingPolicy{AutoScalingGroupName: new(api.XmlStringMaxLen255(g.Key.Name)), PolicyName: in.PolicyName, PolicyARN: new(api.ResourceName(resource)), PolicyType: new(api.XmlStringMaxLen64("SimpleScaling")), Enabled: new(api.ScalingPolicyEnabled(true)), Alarms: api.Alarms{}, StepAdjustments: api.StepAdjustments{}}}
	}
	oldType := value(record.Data.PolicyType)
	data := api.CloneScalingPolicy(record.Data)
	if in.PolicyType != nil {
		data.PolicyType = in.PolicyType
	}
	if in.PredictiveScalingConfiguration != nil || value(data.PolicyType) == "PredictiveScaling" {
		return nil, unsupported("Predictive scaling policies are not implemented")
	}
	if existing && oldType != value(data.PolicyType) {
		return nil, invalid("The policy type cannot be changed for an existing policy")
	}
	if in.AdjustmentType != nil {
		data.AdjustmentType = in.AdjustmentType
	}
	if in.Cooldown != nil {
		data.Cooldown = in.Cooldown
	}
	if in.Enabled != nil {
		data.Enabled = in.Enabled
	}
	if in.EstimatedInstanceWarmup != nil {
		data.EstimatedInstanceWarmup = in.EstimatedInstanceWarmup
	}
	if in.MetricAggregationType != nil {
		data.MetricAggregationType = in.MetricAggregationType
	}
	if in.MinAdjustmentMagnitude != nil {
		data.MinAdjustmentMagnitude = in.MinAdjustmentMagnitude
	}
	if in.MinAdjustmentStep != nil {
		data.MinAdjustmentStep = in.MinAdjustmentStep
	}
	if in.ScalingAdjustment != nil {
		data.ScalingAdjustment = in.ScalingAdjustment
	}
	if in.StepAdjustments != nil {
		data.StepAdjustments = in.StepAdjustments
	}
	if in.TargetTrackingConfiguration != nil {
		data.TargetTrackingConfiguration = in.TargetTrackingConfiguration
	}
	if value(data.PolicyType) == "SimpleScaling" && data.Cooldown == nil {
		data.Cooldown = new(api.Cooldown(*g.Data.DefaultCooldown))
	}
	if value(data.PolicyType) == "StepScaling" && data.MetricAggregationType == nil {
		data.MetricAggregationType = new(api.XmlStringMaxLen32("Average"))
	}
	if err = validatePolicy(data); err != nil {
		return nil, err
	}
	record.Data = data
	if value(data.PolicyType) == "TargetTrackingScaling" {
		policies, err := tx.Policies(g.Key)
		if err != nil {
			return nil, err
		}
		for _, other := range policies {
			if other.Key != key && other.GroupID == g.ID && sameTrackingMetric(data.TargetTrackingConfiguration, other.Data.TargetTrackingConfiguration) {
				return nil, invalid("Only one TargetTrackingScaling policy for a given metric specification is allowed")
			}
		}
		if err = s.replaceTrackingAlarms(ctx, g, &record); err != nil {
			return nil, err
		}
	}
	record.Data = api.CloneScalingPolicy(record.Data)
	if err = tx.PutPolicy(record); err != nil {
		return nil, err
	}
	return &api.PutScalingPolicyOutput{PolicyARN: record.Data.PolicyARN, Alarms: record.Data.Alarms}, nil
}

func (s *Service) describePolicies(ctx context.Context, tx Transaction, in *api.DescribePoliciesInput) (*api.DescribePoliciesOutput, error) {
	if err := s.authorize(ctx, "DescribePolicies", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	names, types := listSelection(in.PolicyNames), listSelection(in.PolicyTypes)
	groups, err := tx.Groups(GroupQuery{Scope: scope})
	if err != nil {
		return nil, err
	}
	rows := []PolicyRecord{}
	for _, g := range groups {
		if value(in.AutoScalingGroupName) != "" && g.Key.Name != value(in.AutoScalingGroupName) {
			continue
		}
		records, err := tx.Policies(g.Key)
		if err != nil {
			return nil, err
		}
		for _, r := range records {
			if r.GroupID == g.ID && (len(names) == 0 || slices.Contains(names, r.Key.Name) || slices.Contains(names, value(r.Data.PolicyARN))) && (len(types) == 0 || slices.Contains(types, value(r.Data.PolicyType))) {
				rows = append(rows, r)
			}
		}
	}
	rows, next, err := pageRows(scope, "DescribePolicies", []any{value(in.AutoScalingGroupName), names, types}, in.MaxRecords, in.NextToken, rows, func(r PolicyRecord) string { return r.Key.GroupKey.Name + "\x00" + r.Key.Name })
	if err != nil {
		return nil, err
	}
	out := &api.DescribePoliciesOutput{ScalingPolicies: api.ScalingPolicies{}, NextToken: next}
	for _, r := range rows {
		out.ScalingPolicies = append(out.ScalingPolicies, r.Data)
	}
	return out, nil
}

func (s *Service) resolvePolicy(ctx context.Context, tx Transaction, group, name, action string) (GroupRecord, PolicyRecord, error) {
	suppliedARN := ""
	if strings.HasPrefix(name, "arn:") {
		parsed, err := arn.Parse(name)
		scope := scopeFor(ctx)
		if err != nil || parsed.Service != "autoscaling" || parsed.Partition != scope.Partition || parsed.AccountID != scope.AccountID || parsed.Region != scope.Region || !strings.HasPrefix(parsed.Resource, "scalingPolicy:") {
			return GroupRecord{}, PolicyRecord{}, invalid("Policy not found")
		}
		_, suffix, ok := strings.Cut(parsed.Resource, ":autoScalingGroupName/")
		if !ok {
			return GroupRecord{}, PolicyRecord{}, invalid("Policy not found")
		}
		namedGroup, namedPolicy, ok := strings.Cut(suffix, ":policyName/")
		if !ok || group != "" && group != namedGroup {
			return GroupRecord{}, PolicyRecord{}, invalid("Policy not found")
		}
		suppliedARN = name
		group, name = namedGroup, namedPolicy
	}
	if group == "" {
		return GroupRecord{}, PolicyRecord{}, invalid("AutoScalingGroupName is required when PolicyName is not an ARN")
	}
	g, err := s.loadGroup(ctx, tx, group, action)
	if err != nil {
		return g, PolicyRecord{}, err
	}
	p, err := tx.Policy(PolicyKey{GroupKey: g.Key, Name: name})
	if errors.Is(err, ErrNotFound) || err == nil && (p.GroupID != g.ID || suppliedARN != "" && value(p.Data.PolicyARN) != suppliedARN) {
		return g, p, invalid("Policy not found")
	}
	return g, p, err
}

func (s *Service) deletePolicy(ctx context.Context, tx Transaction, in *api.DeletePolicyInput) (*api.DeletePolicyOutput, error) {
	g, p, err := s.resolvePolicy(ctx, tx, value(in.AutoScalingGroupName), value(in.PolicyName), "DeletePolicy")
	if err != nil {
		return nil, err
	}
	if err = s.deletePolicyAlarms(ctx, g, p); err != nil {
		return nil, err
	}
	if err = tx.DeletePolicy(p.Key); err != nil {
		return nil, err
	}
	return &api.DeletePolicyOutput{}, nil
}

func (s *Service) executePolicy(ctx context.Context, tx Transaction, in *api.ExecutePolicyInput) (*api.ExecutePolicyOutput, error) {
	g, p, err := s.resolvePolicy(ctx, tx, value(in.AutoScalingGroupName), value(in.PolicyName), "ExecutePolicy")
	if err != nil {
		return nil, err
	}
	if value(p.Data.PolicyType) == "TargetTrackingScaling" {
		return nil, invalid("ExecutePolicy cannot be used with a target tracking scaling policy")
	}
	if value(p.Data.PolicyType) == "SimpleScaling" && (in.MetricValue != nil || in.BreachThreshold != nil) {
		return nil, invalid("MetricValue and BreachThreshold apply only to StepScaling")
	}
	if value(p.Data.PolicyType) == "StepScaling" && in.HonorCooldown != nil {
		return nil, invalid("HonorCooldown applies only to SimpleScaling")
	}
	honor := in.HonorCooldown != nil && bool(*in.HonorCooldown)
	if err = s.applyScalingPolicy(ctx, tx, g, p, in.MetricValue, in.BreachThreshold, honor, false); err != nil {
		return nil, err
	}
	return &api.ExecutePolicyOutput{}, nil
}
