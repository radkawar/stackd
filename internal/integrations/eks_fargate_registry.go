package integrations

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	native "stackd/compute/eks"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

func (a EKSWorkloadRoles) FargateImageAuthorization(ctx context.Context, roleARN, roleID, profileARN string, images []string) ([]native.RegistryAuthorization, error) {
	if a.RegistryEndpoint == "" {
		return nil, nil
	}
	origin, err := url.Parse(a.RegistryEndpoint)
	if err != nil || origin.Host == "" {
		return nil, errors.New("fargate ECR registry endpoint is invalid")
	}
	needed := false
	for _, image := range images {
		host, _, ok := strings.Cut(image, "/")
		if ok && host == origin.Host {
			needed = true
			break
		}
	}
	if !needed {
		return nil, nil
	}
	if a.ECR == nil {
		return nil, errors.New("fargate ECR owner is unavailable")
	}
	source := awsctx.ServicePrincipal{Name: "eks-fargate-pods.amazonaws.com", SourceARN: profileARN, Type: "AWSService"}
	credential, rejected := a.Roles.assumeResolved(ctx, source, identity.RoleSessionSpec{SessionName: "EKSFargatePull", Duration: time.Hour}, "", func(ctx context.Context) (string, error) {
		role, err := a.Roles.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			return "", err
		}
		if role.ID != roleID {
			return "", errors.New("fargate execution-role identity changed")
		}
		return roleARN, nil
	})
	if rejected != nil {
		return nil, rejected
	}
	requestCtx, rejected := serviceRoleRequestContext(ctx, credential, awsctx.FromContext(ctx).Region, source.Name)
	if rejected != nil {
		return nil, rejected
	}
	model, _ := awscatalog.LookupService("ecr")
	operation, _ := model.Operation("GetAuthorizationToken")
	value, rejected := a.ECR.ExecuteCommand(requestCtx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &api.GetAuthorizationTokenInput{}})
	if rejected != nil {
		return nil, rejected
	}
	output, ok := value.(*api.GetAuthorizationTokenOutput)
	if !ok || len(output.AuthorizationData) != 1 || output.AuthorizationData[0].AuthorizationToken == nil {
		return nil, errors.New("ECR returned invalid Fargate authorization")
	}
	raw, err := base64.StdEncoding.DecodeString(string(*output.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return nil, err
	}
	username, password, ok := strings.Cut(string(raw), ":")
	if !ok || username != "AWS" || password == "" {
		return nil, errors.New("ECR returned invalid Fargate credentials")
	}
	return []native.RegistryAuthorization{{ServerAddress: origin.Host, Endpoint: a.RegistryEndpoint, Username: username, Password: password}}, nil
}
