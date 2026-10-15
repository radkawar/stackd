package cloudformation

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudformation"
)

// resourceRegistryContract retains the same captured schema used to generate
// admission contracts. It describes AWS registry types, not local owner effects.
// Native optional metadata remains absent when the capture did not contain it.
type resourceRegistryContract struct {
	Schema, Description, SourceURL, DocumentationURL        string
	Version, ProvisioningType, DeprecatedStatus, Visibility string
	IsDefaultVersion                                        bool
	TimeCreated                                             time.Time
}

var registryTypeNamePattern = regexp.MustCompile(`^[A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64}(::MODULE)?$`)

func registryTypeARN(scope Scope, typeName string) string {
	return fmt.Sprintf("arn:%s:cloudformation:%s::type/resource/%s", scope.Partition, scope.Region, strings.ReplaceAll(typeName, "::", "-"))
}

func (s *Service) describeType(tx Transaction, in *api.DescribeTypeInput) (*api.DescribeTypeOutput, error) {
	scope := scopeFor(tx.Context())
	typeName, kind, selectedARN, version := text(in.TypeName), text(in.Type), text(in.Arn), text(in.VersionId)
	if selectedARN != "" && (typeName != "" || kind != "") {
		return nil, invalid("Specify either Arn or Type and TypeName, not both")
	}
	if selectedARN == "" {
		if typeName == "" || kind == "" {
			return nil, invalid("Specify Arn or both Type and TypeName")
		}
		if !registryTypeNamePattern.MatchString(typeName) {
			return nil, invalid("TypeName is not a valid registry extension name")
		}
		if kind != "RESOURCE" && kind != "MODULE" && kind != "HOOK" {
			return nil, invalid("Type must be RESOURCE, MODULE or HOOK")
		}
		selectedARN = registryTypeARN(scope, typeName)
		if kind != "RESOURCE" {
			selectedARN = strings.Replace(selectedARN, "/resource/", "/"+strings.ToLower(kind)+"/", 1)
		}
	}
	// Registry reads use current caller authority. Public type ARNs omit the
	// account, so the account-scoped read authority comes from the caller.
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(tx.Context(), authorization.Request{
		Action: "cloudformation:DescribeType", ResourceARN: selectedARN,
		ResourceAccountID: scope.Account, EvaluationTime: &now,
	}); denied != nil {
		return nil, denied
	}
	parsed, err := arn.Parse(selectedARN)
	if err != nil || parsed.Service != "cloudformation" || !strings.HasPrefix(parsed.Resource, "type/") {
		return nil, invalid("Arn must identify a CloudFormation registry extension")
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return nil, invalid("Arn must identify a registry type or type version")
	}
	if parsed.Partition != scope.Partition || parsed.Region != scope.Region || parsed.AccountID != "" || parts[1] != "resource" {
		return nil, registryTypeMissing(selectedARN)
	}
	if typeName == "" {
		typeName = strings.ReplaceAll(parts[2], "-", "::")
	}
	if len(parts) == 4 {
		if version != "" && version != parts[3] {
			return nil, invalid("Arn and VersionId refer to different extension versions")
		}
		version = parts[3]
	}
	contract, known := resourceSchemas[typeName]
	if !known || contract.Registry.Schema == "" || !strings.HasPrefix(typeName, "AWS::") {
		return nil, registryTypeMissing(selectedARN)
	}
	registry := contract.Registry
	// The captures contain only the default AWS-owned schema. Public AWS
	// types do not expose a private registration version or publisher ID.
	if in.PublisherId != nil || in.PublicVersionNumber != nil {
		return nil, failure("CFNRegistryException", "AWS resource types do not have a publisher or public version number.")
	}
	if version != "" && (registry.Version == "" || registry.Version != version) {
		return nil, registryTypeMissing(selectedARN)
	}
	out := &api.DescribeTypeOutput{
		Arn:  new(api.TypeArn(registryTypeARN(scope, typeName))),
		Type: new(api.RegistryTypeRESOURCE), TypeName: new(api.TypeName(typeName)),
		Schema:           new(api.TypeSchema(registry.Schema)),
		IsDefaultVersion: new(api.IsDefaultVersion(registry.IsDefaultVersion)),
		Visibility:       new(api.Visibility(registry.Visibility)),
		ProvisioningType: new(api.ProvisioningType(registry.ProvisioningType)),
	}
	if registry.Description != "" {
		out.Description = new(api.Description(registry.Description))
	}
	if registry.Version != "" {
		out.DefaultVersionId = new(api.TypeVersionId(registry.Version))
	}
	if registry.DeprecatedStatus != "" {
		out.DeprecatedStatus = new(api.DeprecatedStatus(registry.DeprecatedStatus))
	}
	if registry.SourceURL != "" {
		out.SourceUrl = new(api.OptionalSecureUrl(registry.SourceURL))
	}
	if registry.DocumentationURL != "" {
		out.DocumentationUrl = new(api.OptionalSecureUrl(registry.DocumentationURL))
	}
	if !registry.TimeCreated.IsZero() {
		out.TimeCreated = new(api.Timestamp(registry.TimeCreated))
	}
	return out, nil
}

func registryTypeMissing(identity string) error {
	return failure("TypeNotFoundException", "The registry extension does not exist: "+identity, 404)
}
