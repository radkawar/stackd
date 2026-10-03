package integrations

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
)

const eventConnectionPrincipal = "apidestinations.events.amazonaws.com"
const eventConnectionRole = "AWSServiceRoleForAmazonEventBridgeApiDestinations"

type EventBridgeManagedSecrets interface {
	CreateManaged(context.Context, string, *api.CreateSecretInput) (*api.CreateSecretOutput, *awswire.Error)
	UpdateManaged(context.Context, string, *api.UpdateSecretInput) (*api.UpdateSecretOutput, *awswire.Error)
	DeleteManaged(context.Context, string, *api.DeleteSecretInput) (*api.DeleteSecretOutput, *awswire.Error)
	DescribeSecret(context.Context, *api.DescribeSecretInput) (*api.DescribeSecretOutput, *awswire.Error)
	GetSecretValue(context.Context, *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error)
}

type EventBridgeSecretRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

type EventBridgeSecrets struct {
	Secrets     EventBridgeManagedSecrets
	Roles       ServiceRoles
	Provisioner EventBridgeSecretRoles
	sessions    serviceRoleSessions
}

func (a *EventBridgeSecrets) owner(ctx context.Context, connectionARN string) (context.Context, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/" + eventConnectionPrincipal + "/" + eventConnectionRole
	ctx, err := a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: eventConnectionPrincipal, SourceARN: connectionARN, Type: "AWSService"}, role, "AmazonEventBridgeApiDestinations", "")
	if err != nil {
		return nil, serviceRoleFailure(err)
	}
	return ctx, nil
}
func (a *EventBridgeSecrets) Create(ctx context.Context, connectionARN, name, keyID, value string) (string, *awswire.Error) {
	if err := a.Provisioner.EnsureServiceLinkedRole(ctx, eventConnectionPrincipal); err != nil {
		rejected := *serviceRoleFailure(err)
		rejected.Cause = err
		return "", &rejected
	}
	ctx, rejected := a.owner(ctx, connectionARN)
	if rejected != nil {
		return "", rejected
	}
	input := &api.CreateSecretInput{Name: new(api.NameType(name)), SecretString: new(api.SecretStringType(value))}
	if keyID != "" {
		input.KmsKeyId = new(api.KmsKeyIdType(keyID))
	}
	out, rejected := a.Secrets.CreateManaged(ctx, "events", input)
	if rejected != nil {
		return "", rejected
	}
	return string(*out.ARN), nil
}
func (a *EventBridgeSecrets) Update(ctx context.Context, connectionARN, id string, keyID *string, value string) *awswire.Error {
	ctx, rejected := a.owner(ctx, connectionARN)
	if rejected != nil {
		return rejected
	}
	input := &api.UpdateSecretInput{SecretId: new(api.SecretIdType(id)), SecretString: new(api.SecretStringType(value))}
	if keyID != nil {
		input.KmsKeyId = new(api.KmsKeyIdType(*keyID))
	}
	_, rejected = a.Secrets.UpdateManaged(ctx, "events", input)
	return rejected
}
func (a *EventBridgeSecrets) Delete(ctx context.Context, connectionARN, id string) *awswire.Error {
	ctx, rejected := a.owner(ctx, connectionARN)
	if rejected != nil {
		return rejected
	}
	_, rejected = a.Secrets.DeleteManaged(ctx, "events", &api.DeleteSecretInput{SecretId: new(api.SecretIdType(id)), ForceDeleteWithoutRecovery: new(api.BooleanType(true))})
	return rejected
}
func (a *EventBridgeSecrets) ReadOwned(ctx context.Context, connectionARN, id string) (string, *awswire.Error) {
	ctx, rejected := a.owner(ctx, connectionARN)
	if rejected != nil {
		return "", rejected
	}
	return a.read(ctx, id)
}
func (a *EventBridgeSecrets) ReadForInvocation(ctx context.Context, id string) (string, *awswire.Error) {
	if _, rejected := a.Secrets.DescribeSecret(ctx, &api.DescribeSecretInput{SecretId: new(api.SecretIdType(id))}); rejected != nil {
		return "", rejected
	}
	return a.read(ctx, id)
}
func (a *EventBridgeSecrets) read(ctx context.Context, id string) (string, *awswire.Error) {
	out, rejected := a.Secrets.GetSecretValue(ctx, &api.GetSecretValueInput{SecretId: new(api.SecretIdType(id))})
	if rejected != nil {
		return "", rejected
	}
	if out.SecretString == nil {
		return "", &awswire.Error{Code: "InvalidRequestException", Message: "The connection secret does not contain string credentials.", StatusCode: 400}
	}
	return string(*out.SecretString), nil
}

func EventBridgeConnectionRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: eventConnectionPrincipal, RoleName: eventConnectionRole,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"apidestinations.events.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		DefaultDescription: "Enables access to the Secrets Manager Secrets created by AWS EventBridge",
		UsageFailureReason: "The role is in use by EventBridge connections.",
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonEventBridgeApiDestinationsServiceRolePolicy"},
		Sources:            []string{"testdata/aws/eventbridge/connections.json", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEventBridgeApiDestinationsServiceRolePolicy.html"},
	}
}

type EventBridgeConnectionRoleResources interface {
	WithConnectionRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
}
type EventBridgeConnectionRoleUsage struct {
	Connections EventBridgeConnectionRoleResources
}

func (a EventBridgeConnectionRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Connections.WithConnectionRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, connections []string) error {
		regions := map[string][]string{}
		for _, connection := range connections {
			resource, err := arn.Parse(connection)
			if err != nil {
				return errors.New("invalid retained connection ARN")
			}
			regions[resource.Region] = append(regions[resource.Region], connection)
		}
		usage := make([]iam.ServiceLinkedRoleUsage, 0, len(regions))
		for region, resources := range regions {
			slices.Sort(resources)
			usage = append(usage, iam.ServiceLinkedRoleUsage{Region: region, ResourceARNs: resources})
		}
		slices.SortFunc(usage, func(a, b iam.ServiceLinkedRoleUsage) int { return strings.Compare(a.Region, b.Region) })
		return fn(ctx, usage)
	})
}
