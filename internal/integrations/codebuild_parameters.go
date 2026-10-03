package integrations

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// ParameterStoreAPI retains SSM's live IAM, KMS and audit command boundaries.
type ParameterStoreAPI interface {
	GetParameters(context.Context, *api.GetParametersRequest) (*api.GetParametersResult, *awswire.Error)
}

// CodeBuildParameters uses the build's regional SSM endpoint and service role.
type CodeBuildParameters struct{ Parameters ParameterStoreAPI }

func (a CodeBuildParameters) Read(ctx context.Context, references []string) (map[string]string, error) {
	return readParameterValues(codeBuildCommandContext(ctx), a.Parameters, references, false)
}

// ECS routes full ARNs to their region; CodeBuild uses its build-region endpoint.
// Only temporary native environment preparation receives these values.
func readParameterValues(ctx context.Context, service ParameterStoreAPI, references []string, crossRegion bool) (map[string]string, error) {
	if service == nil {
		return nil, fmt.Errorf("parameter store is unavailable")
	}
	metadata := awsctx.FromContext(ctx)
	groups := make(map[string][]string)
	for _, reference := range references {
		region := metadata.Region
		if strings.HasPrefix(reference, "arn:") {
			resource, err := arn.Parse(reference)
			if err != nil || resource.Service != "ssm" || resource.Partition != metadata.Partition || resource.Region == "" || resource.AccountID == "" || !strings.HasPrefix(resource.Resource, "parameter/") {
				return nil, fmt.Errorf("invalid SSM parameter ARN %q", reference)
			}
			if crossRegion {
				region = resource.Region
			}
		}
		groups[region] = append(groups[region], reference)
	}
	regions := make([]string, 0, len(groups))
	for region := range groups {
		regions = append(regions, region)
	}
	slices.Sort(regions)
	values := make(map[string]string, len(references))
	for _, region := range regions {
		names := groups[region]
		slices.Sort(names)
		names = slices.Compact(names)
		for start := 0; start < len(names); start += 10 {
			batch := names[start:min(start+10, len(names))]
			input := &api.GetParametersRequest{Names: make(api.ParameterNameList, len(batch)), WithDecryption: new(api.Boolean(true))}
			for i, reference := range batch {
				input.Names[i] = api.PSParameterName(reference)
			}
			m := metadata
			m.Region, m.RequestID = region, uuid.NewString()
			result, rejected := service.GetParameters(awsctx.WithMetadata(ctx, m), input)
			if rejected != nil {
				return nil, rejected
			}
			if result == nil {
				return nil, fmt.Errorf("parameter store returned no result")
			}
			if len(result.InvalidParameters) != 0 {
				return nil, fmt.Errorf("SSM parameter %q was not found", result.InvalidParameters[0])
			}
			for _, reference := range batch {
				found := false
				for _, parameter := range result.Parameters {
					name := ""
					if strings.HasPrefix(reference, "arn:") {
						if parameter.ARN != nil {
							name = string(*parameter.ARN)
						}
					} else if parameter.Name != nil {
						name = string(*parameter.Name)
					}
					if parameter.Selector != nil {
						name += string(*parameter.Selector)
					}
					if name == reference && parameter.Value != nil {
						values[reference] = string(*parameter.Value)
						found = true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("SSM parameter %q was not returned", reference)
				}
			}
		}
	}
	return values, nil
}
