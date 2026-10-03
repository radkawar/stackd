package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

var capacityName = regexp.MustCompile(`^[a-zA-Z0-9-_]{1,140}$`)

func capacityKey(ctx context.Context, name string) (CapacityProviderKey, error) {
	scope := scopeFor(ctx)
	if strings.HasPrefix(name, "arn:") {
		parts := strings.SplitN(name, ":", 7)
		if len(parts) != 7 || parts[0] != "arn" || parts[2] != "lambda" || parts[5] != "capacity-provider" || parts[1] != scope.Partition || parts[3] != scope.Region {
			return CapacityProviderKey{}, capacityParameter("Invalid capacity provider ARN.")
		}
		scope.Account = parts[4]
		name = parts[6]
	}
	if !capacityName.MatchString(name) {
		return CapacityProviderKey{}, capacityParameter("Invalid capacity provider name.")
	}
	return CapacityProviderKey{Scope: scope, Name: name}, nil
}
func capacityParameter(message string) *awswire.Error {
	return failure("InvalidParameterValueException", message, 400)
}
func (s *Service) registerCapacity() {
	register(s, "CreateCapacityProvider", s.createCapacityProvider)
	register(s, "GetCapacityProvider", s.getCapacityProvider)
	register(s, "UpdateCapacityProvider", s.updateCapacityProvider)
	register(s, "DeleteCapacityProvider", s.deleteCapacityProvider)
	register(s, "ListCapacityProviders", s.listCapacityProviders)
	register(s, "ListFunctionVersionsByCapacityProvider", s.listFunctionVersionsByCapacityProvider)
	register(s, "GetResourcePolicy", s.getCapacityPolicy)
	register(s, "PutResourcePolicy", s.putCapacityPolicy)
	register(s, "DeleteResourcePolicy", s.deleteCapacityPolicy)
	register(s, "GetFunctionScalingConfig", s.getCapacityScaling)
	register(s, "PutFunctionScalingConfig", s.putCapacityScaling)
}
func (s *Service) authorizeCapacity(ctx context.Context, action string, v CapacityProviderRecord) *awswire.Error {
	return s.authorizer.Authorize(ctx, authorization.Request{Action: "lambda:" + action, ResourceARN: v.Key.ARN(), ResourceAccountID: v.Key.Account, Context: tagConditions(v.Tags, nil)})
}
func capacityScaling(v *CapacityProviderRecord, in *api.CapacityProviderScalingConfig) error {
	if in == nil {
		return nil
	}
	if in.ScalingMode != nil {
		v.ScalingMode = value(in.ScalingMode)
	}
	if v.ScalingMode != "Auto" && v.ScalingMode != "Manual" {
		return capacityParameter("ScalingMode must be Auto or Manual.")
	}
	if in.MaxVCpuCount != nil {
		v.MaxVCPUs = int32(*in.MaxVCpuCount)
	}
	if v.MaxVCPUs < 2 || v.MaxVCPUs > 15000 {
		return capacityParameter("MaxVCpuCount must be between 2 and 15000.")
	}
	if in.ScalingPolicies != nil {
		if len(in.ScalingPolicies) > 1 {
			return capacityParameter("Only one CPU target tracking policy is supported.")
		}
		v.TargetCPU = 50
		for _, policy := range in.ScalingPolicies {
			if value(policy.PredefinedMetricType) != "LambdaCapacityProviderAverageCPUUtilization" || policy.TargetValue == nil || math.IsNaN(float64(*policy.TargetValue)) || float64(*policy.TargetValue) <= 0 || float64(*policy.TargetValue) > 100 {
				return capacityParameter("Invalid CPU target tracking policy.")
			}
			v.TargetCPU = float64(*policy.TargetValue)
		}
	}
	return nil
}
func capacityPropagation(v *CapacityProviderRecord, in *api.PropagateTags) error {
	if in == nil {
		return nil
	}
	switch value(in.Mode) {
	case "None":
		if len(in.ExplicitTags) != 0 {
			return capacityParameter("None propagation cannot include explicit tags.")
		}
		v.PropagateTags = nil
	case "Explicit":
		v.PropagateTags = map[string]string{}
		for key, value := range in.ExplicitTags {
			v.PropagateTags[string(key)] = string(value)
		}
	default:
		return capacityParameter("PropagateTags.Mode must be None or Explicit.")
	}
	return nil
}
func capacityOutput(v CapacityProviderRecord) *api.CapacityProvider {
	out := &api.CapacityProvider{CapacityProviderArn: new(api.CapacityProviderArn(v.Key.ARN())), State: new(api.CapacityProviderState(v.State)), LastModified: new(api.Timestamp(v.Modified.UTC().Format("2006-01-02T15:04:05.000Z"))), PermissionsConfig: &api.CapacityProviderPermissionsConfig{CapacityProviderOperatorRoleArn: new(api.RoleArn(v.OperatorRoleARN))}, VpcConfig: &api.CapacityProviderVpcConfig{}, InstanceRequirements: &api.InstanceRequirements{Architectures: api.ArchitecturesList{api.Architecture(v.Architecture)}}, CapacityProviderScalingConfig: &api.CapacityProviderScalingConfig{ScalingMode: new(api.CapacityProviderScalingMode(v.ScalingMode)), MaxVCpuCount: new(api.CapacityProviderMaxVCpuCount(v.MaxVCPUs)), ScalingPolicies: api.CapacityProviderScalingPoliciesList{{PredefinedMetricType: new(api.CapacityProviderPredefinedMetricType("LambdaCapacityProviderAverageCPUUtilization")), TargetValue: new(api.MetricTargetValue(v.TargetCPU))}}}, PropagateTags: &api.PropagateTags{Mode: new(api.PropagateTagsMode("None"))}}
	for _, id := range v.SubnetIDs {
		out.VpcConfig.SubnetIds = append(out.VpcConfig.SubnetIds, api.SubnetId(id))
	}
	for _, id := range v.SecurityGroupIDs {
		out.VpcConfig.SecurityGroupIds = append(out.VpcConfig.SecurityGroupIds, api.SecurityGroupId(id))
	}
	for _, name := range v.AllowedInstanceTypes {
		out.InstanceRequirements.AllowedInstanceTypes = append(out.InstanceRequirements.AllowedInstanceTypes, api.InstanceType(name))
	}
	for _, name := range v.ExcludedInstanceTypes {
		out.InstanceRequirements.ExcludedInstanceTypes = append(out.InstanceRequirements.ExcludedInstanceTypes, api.InstanceType(name))
	}
	if v.KMSKeyARN != "" {
		out.KmsKeyArn = new(api.KMSKeyArn(v.KMSKeyARN))
	}
	if v.PropagateTags != nil {
		out.PropagateTags.Mode = new(api.PropagateTagsMode("Explicit"))
		out.PropagateTags.ExplicitTags = api.Tags{}
		for k, val := range v.PropagateTags {
			out.PropagateTags.ExplicitTags[api.TagKey(k)] = api.TagValue(val)
		}
	}
	return out
}
func (s *Service) createCapacityProvider(ctx context.Context, in *api.CreateCapacityProviderRequest) (*api.CreateCapacityProviderResponse, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.CapacityProviderName))
	if err != nil {
		return nil, wireError(err)
	}
	if key.Scope != scopeFor(ctx) {
		return nil, capacityParameter("Capacity providers must be created in the current account.")
	}
	v := CapacityProviderRecord{Key: key, Generation: uuid.NewString(), State: "Pending", Architecture: "x86_64", ScalingMode: "Auto", MaxVCPUs: 400, TargetCPU: 50, Modified: s.clock.Now().UTC(), Tags: map[string]string{}}
	if in.PermissionsConfig == nil || value(in.PermissionsConfig.CapacityProviderOperatorRoleArn) == "" || in.VpcConfig == nil || len(in.VpcConfig.SubnetIds) == 0 {
		return nil, capacityParameter("PermissionsConfig and VpcConfig subnets are required.")
	}
	v.OperatorRoleARN = value(in.PermissionsConfig.CapacityProviderOperatorRoleArn)
	v.KMSKeyARN = value(in.KmsKeyArn)
	for _, id := range in.VpcConfig.SubnetIds {
		v.SubnetIDs = append(v.SubnetIDs, string(id))
	}
	for _, id := range in.VpcConfig.SecurityGroupIds {
		v.SecurityGroupIDs = append(v.SecurityGroupIDs, string(id))
	}
	for k, val := range in.Tags {
		v.Tags[string(k)] = string(val)
	}
	if in.InstanceRequirements != nil {
		req := in.InstanceRequirements
		if len(req.Architectures) > 1 {
			return nil, capacityParameter("A capacity provider must select one architecture.")
		}
		if len(req.Architectures) == 1 {
			v.Architecture = string(req.Architectures[0])
		}
		if v.Architecture != "x86_64" && v.Architecture != "arm64" {
			return nil, capacityParameter("Invalid capacity provider architecture.")
		}
		for _, name := range req.AllowedInstanceTypes {
			v.AllowedInstanceTypes = append(v.AllowedInstanceTypes, string(name))
		}
		for _, name := range req.ExcludedInstanceTypes {
			v.ExcludedInstanceTypes = append(v.ExcludedInstanceTypes, string(name))
		}
		if len(v.AllowedInstanceTypes) != 0 && len(v.ExcludedInstanceTypes) != 0 {
			return nil, capacityParameter("AllowedInstanceTypes and ExcludedInstanceTypes are mutually exclusive.")
		}
	}
	if err = capacityScaling(&v, in.CapacityProviderScalingConfig); err != nil {
		return nil, wireError(err)
	}
	if err = capacityPropagation(&v, in.PropagateTags); err != nil {
		return nil, wireError(err)
	}
	if in.TelemetryConfig != nil {
		return nil, unsupported("Capacity provider agent log delivery is not implemented.")
	}
	if rejected := s.authorize(ctx, "CreateCapacityProvider", key.ARN(), nil, v.Tags, nil); rejected != nil {
		return nil, rejected
	}
	if s.capacityBackend == nil {
		return nil, unsupported("A real managed EC2 guest backend is required.")
	}
	v.State = "Active"
	out := &api.CreateCapacityProviderResponse{CapacityProvider: capacityOutput(v)}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := tx.CapacityProvider(key); err == nil {
			return failure("ResourceConflictException", "Capacity provider already exists.", 409)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		all, err := tx.CapacityProviders(key.Scope)
		if err != nil {
			return err
		}
		if len(all) >= 1000 {
			return failure("CapacityProviderLimitExceededException", "Capacity provider quota exceeded.", 400)
		}
		if rejected := s.authorize(tx.Context(), "CreateCapacityProvider", key.ARN(), nil, v.Tags, nil); rejected != nil {
			return rejected
		}
		if err := s.capacityBackend.Validate(tx.Context(), v); err != nil {
			return err
		}
		if err = tx.PutCapacityProvider(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "CreateCapacityProvider", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) getCapacityProvider(ctx context.Context, in *api.GetCapacityProviderRequest) (*api.GetCapacityProviderResponse, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.CapacityProviderName))
	if err != nil {
		return nil, wireError(err)
	}
	var v CapacityProviderRecord
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = r.CapacityProvider(key)
		if err != nil {
			return err
		}
		if rejected := s.authorizeCapacity(r.Context(), "GetCapacityProvider", v); rejected != nil {
			return rejected
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.GetCapacityProviderResponse{CapacityProvider: capacityOutput(v)}, nil
}
func (s *Service) updateCapacityProvider(ctx context.Context, in *api.UpdateCapacityProviderRequest) (*api.UpdateCapacityProviderResponse, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.CapacityProviderName))
	if err != nil {
		return nil, wireError(err)
	}
	var out *api.UpdateCapacityProviderResponse
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.CapacityProvider(key)
		if err != nil {
			return err
		}
		if rejected := s.authorizeCapacity(tx.Context(), "UpdateCapacityProvider", v); rejected != nil {
			return rejected
		}
		if v.State != "Active" {
			return failure("ResourceConflictException", "Capacity provider is not active.", 409)
		}
		if err = capacityScaling(&v, in.CapacityProviderScalingConfig); err != nil {
			return err
		}
		if err = capacityPropagation(&v, in.PropagateTags); err != nil {
			return err
		}
		if in.TelemetryConfig != nil {
			return unsupported("Capacity provider agent log delivery is not implemented.")
		}
		v.Modified = s.clock.Now().UTC()
		if err = tx.PutCapacityProvider(v); err != nil {
			return err
		}
		out = &api.UpdateCapacityProviderResponse{CapacityProvider: capacityOutput(v)}
		return s.recordCall(tx.Context(), "UpdateCapacityProvider", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
func capacityVersions(r Reader, provider CapacityProviderKey) ([]FunctionRecord, error) {
	functions, err := r.AllFunctions()
	if err != nil {
		return nil, err
	}
	out := []FunctionRecord{}
	for _, f := range functions {
		versions, err := r.FunctionVersions(f.Key)
		if err != nil {
			return nil, err
		}
		for _, v := range versions {
			if v.Capacity != nil && v.Capacity.ProviderARN == provider.ARN() {
				out = append(out, v)
			}
		}
	}
	slices.SortFunc(out, func(a, b FunctionRecord) int {
		return strings.Compare((FunctionVersionKey{FunctionKey: a.Key, Version: a.Version}).ARN(), (FunctionVersionKey{FunctionKey: b.Key, Version: b.Version}).ARN())
	})
	return out, nil
}
func (s *Service) deleteCapacityProvider(ctx context.Context, in *api.DeleteCapacityProviderRequest) (*api.DeleteCapacityProviderResponse, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.CapacityProviderName))
	if err != nil {
		return nil, wireError(err)
	}
	var out *api.DeleteCapacityProviderResponse
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.CapacityProvider(key)
		if err != nil {
			return err
		}
		if rejected := s.authorizeCapacity(tx.Context(), "DeleteCapacityProvider", v); rejected != nil {
			return rejected
		}
		versions, err := capacityVersions(tx, key)
		if err != nil {
			return err
		}
		if len(versions) != 0 {
			return failure("ResourceConflictException", "Capacity provider has attached function versions.", 409)
		}
		v.State = "Deleting"
		v.Modified = s.clock.Now().UTC()
		if err = tx.PutCapacityProvider(v); err != nil {
			return err
		}
		out = &api.DeleteCapacityProviderResponse{CapacityProvider: capacityOutput(v)}
		return s.recordCall(tx.Context(), "DeleteCapacityProvider", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
func capacityPage(marker, prefix string, maxItems *api.MaxFiftyListItems) (string, int, error) {
	after := ""
	limit := 50
	if marker != "" {
		raw, err := base64.RawURLEncoding.DecodeString(marker)
		if err != nil || !strings.HasPrefix(string(raw), prefix) {
			return "", 0, capacityParameter("Invalid pagination marker.")
		}
		after = strings.TrimPrefix(string(raw), prefix)
	}
	if maxItems != nil {
		limit = int(*maxItems)
		if limit < 1 || limit > 50 {
			return "", 0, capacityParameter("MaxItems must be between 1 and 50.")
		}
	}
	return after, limit, nil
}
func (s *Service) listCapacityProviders(ctx context.Context, in *api.ListCapacityProvidersRequest) (*api.ListCapacityProvidersResponse, *awswire.Error) {
	if rejected := s.authorize(ctx, "ListCapacityProviders", "*", nil, nil, nil); rejected != nil {
		return nil, rejected
	}
	scope := scopeFor(ctx)
	prefix := "capacity:" + scope.Partition + ":" + scope.Account + ":" + scope.Region + ":" + value(in.State) + ":"
	after, limit, err := capacityPage(value(in.Marker), prefix, in.MaxItems)
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.ListCapacityProvidersResponse{CapacityProviders: api.CapacityProvidersList{}}
	err = s.repository.View(ctx, func(r Reader) error {
		rows, err := r.CapacityProviders(scope)
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.Key.Name <= after || (in.State != nil && v.State != value(in.State)) {
				continue
			}
			if len(out.CapacityProviders) == limit {
				last := out.CapacityProviders[len(out.CapacityProviders)-1]
				name := strings.TrimPrefix(value(last.CapacityProviderArn), "arn:"+scope.Partition+":lambda:"+scope.Region+":"+scope.Account+":capacity-provider:")
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + name))))
				break
			}
			out.CapacityProviders = append(out.CapacityProviders, *capacityOutput(v))
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) listFunctionVersionsByCapacityProvider(ctx context.Context, in *api.ListFunctionVersionsByCapacityProviderRequest) (*api.ListFunctionVersionsByCapacityProviderResponse, *awswire.Error) {
	key, err := capacityKey(ctx, value(in.CapacityProviderName))
	if err != nil {
		return nil, wireError(err)
	}
	prefix := "capacity-versions:" + key.ARN() + ":"
	after, limit, err := capacityPage(value(in.Marker), prefix, in.MaxItems)
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.ListFunctionVersionsByCapacityProviderResponse{CapacityProviderArn: new(api.CapacityProviderArn(key.ARN())), FunctionVersions: api.FunctionVersionsByCapacityProviderList{}}
	err = s.repository.View(ctx, func(r Reader) error {
		v, err := r.CapacityProvider(key)
		if err != nil {
			return err
		}
		if rejected := s.authorizeCapacity(r.Context(), "ListFunctionVersionsByCapacityProvider", v); rejected != nil {
			return rejected
		}
		rows, err := capacityVersions(r, key)
		if err != nil {
			return err
		}
		for _, f := range rows {
			arn := (FunctionVersionKey{FunctionKey: f.Key, Version: f.Version}).ARN()
			if arn <= after {
				continue
			}
			if len(out.FunctionVersions) == limit {
				last := value(out.FunctionVersions[len(out.FunctionVersions)-1].FunctionArn)
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + last))))
				break
			}
			out.FunctionVersions = append(out.FunctionVersions, api.FunctionVersionsByCapacityProviderListItem{FunctionArn: new(api.NameSpacedFunctionArn(arn)), State: new(api.State(f.State))})
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

// WithCapacityRoleUsage holds authoritative provider references while IAM checks
// whether its Lambda service-linked role can be deleted.
func (s *Service) WithCapacityRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.AllCapacityProviders()
		if err != nil {
			return err
		}
		var arns []string
		for _, v := range rows {
			if v.Key.Partition == partition && v.Key.Account == account {
				arns = append(arns, v.Key.ARN())
			}
		}
		return fn(tx.Context(), arns)
	})
}
