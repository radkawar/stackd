package lambda

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	native "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// FunctionNetworkConfiguration is customer runtime placement, independent of
// event-source poller placement. An empty pair detaches the function from VPC.
type FunctionNetworkConfiguration struct {
	SubnetIDs, SecurityGroupIDs []string
	VPCID                       string
}

// FunctionNetworks allocates an EC2-authoritative ENI for one execution
// incarnation. The returned lease owns native policy and ENI cleanup, including
// deployment failure. It never shares an ENI across execution environments.
type FunctionNetworks interface {
	Open(context.Context, FunctionKey, string, string, FunctionNetworkConfiguration) (native.FunctionNetworkLease, error)
	Validate(context.Context, FunctionKey, string, string, FunctionNetworkConfiguration) (string, error)
	Recover(context.Context, FunctionKey, string, string) error
}

func (s *Service) openFunctionNetwork(ctx context.Context, function FunctionRecord) (native.FunctionNetworkLease, error) {
	configuration := function.VpcConfig
	if len(configuration.SubnetIDs) == 0 && len(configuration.SecurityGroupIDs) == 0 {
		return nil, nil
	}
	if len(configuration.SubnetIDs) == 0 || len(configuration.SecurityGroupIDs) == 0 {
		return nil, failure("InvalidParameterValueException", "VpcConfig requires both SubnetIds and SecurityGroupIds.", 400)
	}
	if function.NetworkIncarnation == "" {
		return nil, failure("InvalidParameterValueException", "The function lacks its immutable network incarnation.", 400)
	}
	if s.functionNetworks == nil {
		return nil, unsupported("Lambda VpcConfig requires an EC2-owned native function network runtime.")
	}
	if err := s.recoverFunctionNetwork(ctx, function); err != nil {
		return nil, err
	}
	return s.functionNetworks.Open(ownerContext(ctx, function.Key), function.Key, function.Role, function.NetworkIncarnation+"/"+uuid.NewString(), configuration)
}

func cloneFunctionNetwork(configuration FunctionNetworkConfiguration) FunctionNetworkConfiguration {
	configuration.SubnetIDs = slices.Clone(configuration.SubnetIDs)
	configuration.SecurityGroupIDs = slices.Clone(configuration.SecurityGroupIDs)
	return configuration
}

// configureFunctionNetwork runs inside command admission, under the proposed
// execution role. An update with no VpcConfig still revalidates placement when
// changing that role; published versions retain their independent snapshot.
func (s *Service) configureFunctionNetwork(ctx context.Context, function *FunctionRecord, input *api.VpcConfig) *awswire.Error {
	if function.NetworkIncarnation == "" {
		function.NetworkIncarnation = uuid.NewString()
	}
	configuration := cloneFunctionNetwork(function.VpcConfig)
	if input != nil {
		if input.Ipv6AllowedForDualStack != nil && bool(*input.Ipv6AllowedForDualStack) {
			return unsupported("Lambda function dual-stack VPC networking is not supported by the IPv4 native attachment runtime.")
		}
		configuration = FunctionNetworkConfiguration{}
		for _, id := range input.SubnetIds {
			configuration.SubnetIDs = append(configuration.SubnetIDs, string(id))
		}
		for _, id := range input.SecurityGroupIds {
			configuration.SecurityGroupIDs = append(configuration.SecurityGroupIDs, string(id))
		}
	}
	if len(configuration.SubnetIDs) == 0 && len(configuration.SecurityGroupIDs) == 0 {
		function.VpcConfig = FunctionNetworkConfiguration{}
		return nil
	}
	if len(configuration.SubnetIDs) == 0 || len(configuration.SubnetIDs) > 16 || len(configuration.SecurityGroupIDs) == 0 || len(configuration.SecurityGroupIDs) > 5 {
		return failure("InvalidParameterValueException", "VpcConfig requires 1–16 subnets and 1–5 security groups.", 400)
	}
	for _, ids := range [][]string{configuration.SubnetIDs, configuration.SecurityGroupIDs} {
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return failure("InvalidParameterValueException", "VpcConfig resource IDs must not be empty.", 400)
			}
		}
	}
	slices.Sort(configuration.SubnetIDs)
	configuration.SubnetIDs = slices.Compact(configuration.SubnetIDs)
	slices.Sort(configuration.SecurityGroupIDs)
	configuration.SecurityGroupIDs = slices.Compact(configuration.SecurityGroupIDs)
	if s.functionNetworks == nil {
		return unsupported("Lambda VpcConfig requires an EC2-owned native function network runtime.")
	}
	vpcID, err := s.functionNetworks.Validate(ownerContext(ctx, function.Key), function.Key, function.Role, function.NetworkIncarnation, configuration)
	if err != nil {
		var wire *awswire.Error
		if errors.As(err, &wire) {
			return wire
		}
		return failure("InvalidParameterValueException", err.Error(), 400)
	}
	configuration.VPCID = vpcID
	function.VpcConfig = configuration
	return nil
}

func functionVpcConfig(function FunctionRecord) *api.VpcConfigResponse {
	configuration := function.VpcConfig
	out := &api.VpcConfigResponse{Ipv6AllowedForDualStack: new(api.NullableBoolean(false)), VpcId: new(api.VpcId(configuration.VPCID))}
	for _, id := range configuration.SubnetIDs {
		out.SubnetIds = append(out.SubnetIds, api.SubnetId(id))
	}
	for _, id := range configuration.SecurityGroupIDs {
		out.SecurityGroupIds = append(out.SecurityGroupIds, api.SecurityGroupId(id))
	}
	return out
}

// wrapFunctionNetworkFailure retains failed cleanup as an execution owner so the
// existing retirement/shutdown paths retry it; it cannot execute customer code.
func wrapFunctionNetworkFailure(network native.FunctionNetworkLease, cause error) native.Environment {
	return &functionNetworkFailure{network: network, cause: cause}
}

type functionNetworkFailure struct {
	network native.FunctionNetworkLease
	cause   error
}

func (f *functionNetworkFailure) Invoke(context.Context, native.Invocation, func(native.Result)) (native.Report, error) {
	return native.Report{}, f.cause
}

func (f *functionNetworkFailure) Close(ctx context.Context) error {
	return f.network.Close(ctx)
}

func (s *Service) recoverFunctionNetwork(ctx context.Context, function FunctionRecord) error {
	if len(function.VpcConfig.SubnetIDs) == 0 && len(function.VpcConfig.SecurityGroupIDs) == 0 {
		return nil
	}
	if s.functionNetworks == nil {
		return unsupported("Lambda VpcConfig recovery requires its EC2-owned native function network runtime.")
	}
	if function.NetworkIncarnation == "" {
		return failure("InvalidParameterValueException", "The function lacks its immutable network incarnation.", 400)
	}
	return s.functionNetworks.Recover(ownerContext(ctx, function.Key), function.Key, function.Role, function.NetworkIncarnation)
}
