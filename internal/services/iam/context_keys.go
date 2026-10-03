package iam

import (
	"context"
	"fmt"
	"slices"
	"strings"

	policyeval "stackd/iam/policy"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func getContextKeysForCustomPolicy(ctx context.Context, _ *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.GetContextKeysForCustomPolicyInput](ctx)
	if err != nil {
		return nil, err
	}
	if len(input.PolicyInputList) == 0 {
		return nil, invalidInput("PolicyInputList is required.")
	}
	return contextKeysOutput(input.PolicyInputList)
}

func getContextKeysForPrincipalPolicy(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.GetContextKeysForPrincipalPolicyInput](ctx)
	if err != nil {
		return nil, err
	}
	identity, sourceErr := resolvePermissionPolicyIdentity(a, m, inputString(input.PolicySourceArn))
	if sourceErr != nil {
		return nil, sourceErr
	}
	documents := slices.Clone(input.PolicyInputList)
	attached := make(map[string]struct{})
	for _, owner := range identity.owners {
		for _, name := range sortedMapKeys(owner.policies.Inline) {
			documents = append(documents, iamapi.PolicyDocumentType(owner.policies.Inline[name]))
		}
		for arn := range owner.policies.Attached {
			attached[arn] = struct{}{}
		}
	}
	if identity.boundary != nil {
		attached[identity.boundary.PermissionsBoundaryArn] = struct{}{}
	}
	for _, arn := range sortedMapKeys(attached) {
		document, err := currentPolicySnapshot(a, arn)
		if err != nil {
			return nil, &awswire.Error{Code: "ServiceFailure", StatusCode: 500, Message: "Unable to load a principal policy."}
		}
		documents = append(documents, iamapi.PolicyDocumentType(document.Document))
	}
	return contextKeysOutput(documents)
}

func contextKeySourceARN(arn string) (string, string, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(arn) < 20 || len(arn) > 2048 || len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "iam" || parts[3] != "" || len(parts[4]) != 12 || strings.Trim(parts[4], "0123456789") != "" {
		return "", "", invalidInput("Invalid ARN provided in the request: PolicySourceArn must identify an IAM user, group, or role.")
	}
	kind, _, ok := strings.Cut(parts[5], "/")
	name := parts[5][strings.LastIndexByte(parts[5], '/')+1:]
	if !ok || name == "" || (kind != "user" && kind != "group" && kind != "role") {
		return "", "", invalidInput("PolicySourceArn must identify an IAM user, group, or role.")
	}
	return kind, name, nil
}

func contextKeysOutput(documents iamapi.SimulationPolicyListType) (*iamapi.GetContextKeysForPolicyResponse, *awswire.Error) {
	keys := make(iamapi.ContextKeyNamesResultListType, 0)
	for i, document := range documents {
		text := string(document)
		if len(text) == 0 || len(text) > 131072 {
			return nil, invalidInput("Policy input length must be between 1 and 131072.")
		}
		for _, ch := range text {
			if (ch < 32 && ch != '\t' && ch != '\n' && ch != '\r') || ch > 255 {
				return nil, invalidInput("Policy input contains an invalid character.")
			}
		}
		names, err := policyeval.ContextKeys([]byte(text))
		if err != nil {
			return nil, invalidInput(fmt.Sprintf("Policy input list item %d has invalid content", i+1))
		}
		for _, name := range names {
			keys = append(keys, iamapi.ContextKeyNameType(name))
		}
	}
	return &iamapi.GetContextKeysForPolicyResponse{ContextKeyNames: keys}, nil
}

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
