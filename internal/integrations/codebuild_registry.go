package integrations

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	runtime "stackd/compute/codebuild"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// CodeBuildRegistryCommands issues only ordinary ECR tokens; all registry bytes
// still pass current repository authorization when the Docker daemon pulls them.
type CodeBuildRegistryCommands interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	ServiceAuthorization(context.Context) (*api.GetAuthorizationTokenOutput, *awswire.Error)
}
type CodeBuildRegistry struct {
	ECR      CodeBuildRegistryCommands
	Endpoint string
}

func (a CodeBuildRegistry) Authorization(ctx context.Context, image string) (*runtime.RegistryAuth, error) {
	if a.Endpoint == "" {
		return nil, nil
	}
	origin, err := url.Parse(a.Endpoint)
	if err != nil || origin.Host == "" {
		return nil, fmt.Errorf("CodeBuild ECR endpoint is not configured")
	}
	host, path, hasPath := strings.Cut(image, "/")
	if !hasPath || host != origin.Host {
		return nil, nil
	}
	parts := strings.SplitN(path, "/", 4)
	if len(parts) != 4 || parts[3] == "" || len(parts[1]) != 12 || strings.Trim(parts[1], "0123456789") != "" || awscatalog.RegionPartition(parts[2]) != parts[0] {
		return nil, fmt.Errorf("invalid scoped CodeBuild ECR image URI")
	}
	m := awsctx.FromContext(ctx)
	if m.Partition != parts[0] {
		return nil, fmt.Errorf("CodeBuild image registry partition differs from the build")
	}
	m.Region = parts[2]
	ctx = codeBuildCommandContext(awsctx.WithMetadata(ctx, m))
	var output *api.GetAuthorizationTokenOutput
	if m.ServicePrincipal.Name != "" {
		var rejected *awswire.Error
		output, rejected = a.ECR.ServiceAuthorization(ctx)
		if rejected != nil {
			return nil, rejected
		}
	} else {
		model, ok := awscatalog.LookupService("ecr")
		if !ok {
			return nil, fmt.Errorf("ECR generated service is unavailable")
		}
		operation, ok := model.Operation("GetAuthorizationToken")
		if !ok {
			return nil, fmt.Errorf("ECR authorization operation is unavailable")
		}
		value, rejected := a.ECR.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: &api.GetAuthorizationTokenInput{}})
		if rejected != nil {
			return nil, rejected
		}
		output, ok = value.(*api.GetAuthorizationTokenOutput)
		if !ok {
			return nil, fmt.Errorf("ECR returned an invalid authorization response")
		}
	}
	if output == nil || len(output.AuthorizationData) != 1 || output.AuthorizationData[0].AuthorizationToken == nil {
		return nil, fmt.Errorf("ECR did not return registry authorization")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(*output.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return nil, fmt.Errorf("ECR returned invalid registry authorization")
	}
	user, password, ok := strings.Cut(string(decoded), ":")
	if !ok || user != "AWS" || password == "" {
		return nil, fmt.Errorf("ECR returned invalid registry credentials")
	}
	return &runtime.RegistryAuth{Username: user, Password: password, ServerAddress: origin.Host}, nil
}
