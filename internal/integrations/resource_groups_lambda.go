package integrations

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

type lambdaResourceOwner struct{ stackID, logicalID, token string }

func resourceGroupsLambdaStackOnly(resourceType string) bool {
	switch resourceType {
	case "AWS::Lambda::Alias", "AWS::Lambda::Version", "AWS::Lambda::LayerVersion":
		return true
	default:
		return false
	}
}

// Qualified Lambda resources are stack-only members; function tags do not
// establish ownership of their aliases, immutable versions or layers.
func (r ResourceGroupsResources) lambdaQualifiedOwners(ctx context.Context, scope cloudformation.Scope, candidates []cloudformation.ResourceRecord) (map[string]lambdaResourceOwner, error) {
	needed := false
	for _, candidate := range candidates {
		if candidate.Current && resourceGroupsLambdaStackOnly(candidate.Type) && candidate.PhysicalID != "" && candidate.Status != "DELETE_COMPLETE" {
			needed = true
			break
		}
	}
	if !needed {
		return nil, nil
	}
	if r.Tagging.Backends.Lambda == nil {
		return nil, fmt.Errorf("resource groups requires qualified Lambda storage")
	}
	var owners map[string]lambdaResourceOwner
	err := r.Tagging.Backends.Lambda.View(ctx, func(tx lambda.Reader) error {
		for _, candidate := range candidates {
			if !candidate.Current || !resourceGroupsLambdaStackOnly(candidate.Type) || candidate.PhysicalID == "" || candidate.Status == "DELETE_COMPLETE" {
				continue
			}
			resourceARN := resourceGroupsStackARN(scope, candidate)
			parsed, err := arn.Parse(resourceARN)
			if err != nil || parsed.Partition != scope.Partition || parsed.AccountID != scope.Account || parsed.Region != scope.Region || parsed.Service != "lambda" {
				continue
			}
			kind, resource, valid := strings.Cut(parsed.Resource, ":")
			expectedKind := "function"
			if candidate.Type == "AWS::Lambda::LayerVersion" {
				expectedKind = "layer"
			}
			if kind != expectedKind {
				continue
			}
			name, qualifier, qualified := strings.Cut(resource, ":")
			if !valid || !qualified || name == "" || qualifier == "" || strings.Contains(qualifier, ":") {
				continue
			}
			key := lambda.FunctionReference{FunctionKey: lambda.FunctionKey{
				Scope: lambda.Scope{Partition: scope.Partition, Account: scope.Account, Region: scope.Region}, Name: name,
			}, Qualifier: qualifier}
			var owner lambdaResourceOwner
			switch candidate.Type {
			case "AWS::Lambda::Alias":
				alias, e := tx.Alias(key)
				err = e
				owner = lambdaResourceOwner{alias.Owner.StackID, alias.Owner.LogicalID, alias.Owner.Token}
			case "AWS::Lambda::Version":
				version, e := strconv.ParseUint(qualifier, 10, 64)
				if e != nil || version == 0 || strconv.FormatUint(version, 10) != qualifier {
					continue
				}
				publication, e := tx.FunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: key.FunctionKey, Version: version})
				err = e
				owner = lambdaResourceOwner{publication.StackID, publication.LogicalID, publication.Token}
			case "AWS::Lambda::LayerVersion":
				version, e := strconv.ParseUint(qualifier, 10, 64)
				if e != nil || version == 0 || strconv.FormatUint(version, 10) != qualifier {
					continue
				}
				layer, e := tx.LayerVersion(lambda.LayerVersionKey{LayerKey: lambda.LayerKey{Scope: key.Scope, Name: name}, Version: version})
				err = e
				owner = lambdaResourceOwner{layer.Owner.StackID, layer.Owner.LogicalID, layer.Owner.Token}
			}
			if errors.Is(err, lambda.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if owner.stackID != "" && owner.logicalID != "" && owner.token != "" {
				if owners == nil {
					owners = make(map[string]lambdaResourceOwner)
				}
				owners[resourceARN] = owner
			}
		}
		return nil
	})
	return owners, err
}
