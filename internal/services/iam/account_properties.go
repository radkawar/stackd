package iam

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const roleManagerServicePrincipal = "role-manager.iam.amazonaws.com"

func accountPropertyConditions(ctx context.Context, action string) (map[string][]string, *awswire.Error) {
	switch action {
	case "GetAccountProperties":
		return map[string][]string{"iam:AccountPropertyNamespaces": {"RoleManager"}}, nil
	case "PutAccountProperties":
		input, err := generatedIAMInput[iamapi.PutAccountPropertiesInput](ctx)
		if err != nil {
			return nil, err
		}
		namespaces := make(map[string]struct{})
		for key := range input.Properties {
			namespace, _, _ := strings.Cut(string(key), "/")
			namespaces[namespace] = struct{}{}
		}
		return map[string][]string{"iam:AccountPropertyNamespaces": slices.Sorted(maps.Keys(namespaces))}, nil
	default:
		return nil, nil
	}
}

func getAccountProperties(_ context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	return &iamapi.GetAccountPropertiesOutput{Properties: iamapi.AccountPropertiesMapType{"RoleManager/Enabled": iamapi.AccountPropertyValueType(strconv.FormatBool(a.settings.RoleManagerEnabled))}}, nil
}

func roleManagerProperty(properties iamapi.AccountPropertiesMapType) (bool, *awswire.Error) {
	namespace := ""
	for i, key := range slices.Sorted(maps.Keys(properties)) {
		current, _, separated := strings.Cut(string(key), "/")
		if !separated {
			return false, invalidInput("Property key must be in format Namespace/PropertyName: " + string(key))
		}
		if i > 0 && namespace != current {
			return false, invalidInput("All properties must belong to the same namespace")
		}
		namespace = current
	}
	if namespace != "RoleManager" {
		return false, invalidInput("Unsupported namespace: " + namespace)
	}
	value, present := properties["RoleManager/Enabled"]
	if !present {
		return false, invalidInput("RoleManager namespace requires Enabled property")
	}
	if value != "true" && value != "false" {
		return false, invalidInput("Enabled must be 'true' or 'false'")
	}
	// AWS ignores other properties in the recognized namespace when Enabled
	// is present. It does not persist an arbitrary account-property map.
	return value == "true", nil
}

func (s *Service) putAccountProperties(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	// TODO: Comeback implement new-experience account defaults, advanced-feature eligibility and the first-disable Access Analyzer transition with the account-onboarding authority.
	input, err := generatedIAMInput[iamapi.PutAccountPropertiesInput](ctx)
	if err != nil {
		return nil, err
	}
	enabled, err := roleManagerProperty(input.Properties)
	if err != nil {
		return nil, err
	}
	if enabled {
		template, err := s.serviceLinkedTemplate(m.Partition, roleManagerServicePrincipal)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		authorizer := s.authorizer
		s.mu.Unlock()
		permission := authorization.Request{Action: "iam:CreateServiceLinkedRole", ResourceARN: resourceARN(m, "role", "/aws-service-role/"+template.ServiceName+"/", template.RoleName),
			Context: map[string][]string{"iam:AWSServiceName": {template.ServiceName}}, EvaluationTime: &a.currentTime}
		if err := authorizer.Authorize(ctx, permission); err != nil {
			return nil, err
		}
		key := strings.ToLower(template.RoleName)
		if existing := a.roles[key]; existing != nil {
			if existing.ServiceLinkedService != template.ServiceName {
				return nil, invalidInput("Service role name " + template.RoleName + " has been taken in this account, please try a different suffix.")
			}
		} else {
			a.roles[key] = newServiceLinkedRole(template, m, template.RoleName, template.DefaultDescription, a.currentTime)
		}
	}
	a.settings.RoleManagerEnabled = enabled
	return &iamapi.PutAccountPropertiesOutput{}, nil
}
