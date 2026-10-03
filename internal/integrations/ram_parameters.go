package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/services/ram"
	"stackd/internal/services/ssm"
)

// RAMParameters exposes active share policies without duplicating parameter data.
type RAMParameters struct{ RAM *ram.Service }

func (a RAMParameters) Policies(ctx context.Context, resource ssm.SharedParameter) ([]authorization.BoundPolicy, error) {
	return a.RAM.ResourcePolicies(ctx, resource.ARN)
}

func (a RAMParameters) ResourceDeleted(ctx context.Context, arn string) error {
	return a.RAM.ResourceDeleted(ctx, arn)
}

func (a RAMParameters) ManagedPolicies(ctx context.Context, resource ssm.SharedParameter) ([]ssm.ResourcePolicy, error) {
	policies, err := a.RAM.ManagedResourcePolicies(ctx, resource.ARN)
	if err != nil {
		return nil, err
	}
	out := make([]ssm.ResourcePolicy, 0, len(policies))
	for _, bound := range policies {
		hash := sha256.Sum256([]byte(bound.Policy.Document))
		out = append(out, ssm.ResourcePolicy{ID: bound.ID, Hash: hex.EncodeToString(hash[:]), Policy: bound.Policy})
	}
	return out, nil
}

func (a RAMParameters) Resources(ctx context.Context) ([]ssm.SharedParameter, error) {
	m := awsctx.FromContext(ctx)
	resources, err := a.RAM.SharedResources(ctx, ram.SharedResourcesQuery{Partition: m.Partition, Region: m.Region, AccountID: m.AccountID, ResourceType: "ssm:Parameter", Action: "ssm:DescribeParameters"})
	if err != nil {
		return nil, err
	}
	out := make([]ssm.SharedParameter, 0, len(resources))
	for _, resource := range resources {
		out = append(out, ssm.SharedParameter{ARN: resource.ARN})
	}
	return out, nil
}

// SyncPolicy mirrors only RAM's share identity. SSM retains the original policy
// and its immutable bindings as the sole authority until safe RAM promotion.
func (a RAMParameters) SyncPolicy(ctx context.Context, resource ssm.SharedParameter, id string, bound authorization.BoundPolicy) error {
	parts := strings.SplitN(resource.ARN, ":", 6)
	identity := ram.ResourceIdentity{ARN: resource.ARN, ResourceType: "ssm:Parameter", Partition: parts[1], Region: parts[3], AccountID: parts[4], SupportsIAMPrincipals: true}
	if bound.Document == "" {
		return a.RAM.SyncResourcePolicy(ctx, identity, id, nil, "")
	}
	document, err := policy.ParseResource([]byte(bound.Document))
	if err != nil {
		return err
	}
	principals := document.AWSPrincipals()
	template, err := ramParameterPermissionTemplate(bound.Document, resource.ARN)
	if err != nil {
		return err
	}
	return a.RAM.SyncResourcePolicy(ctx, identity, id, principals, template)
}

// Native permission promotion cannot merge distinct principal/action pairs into
// an all-principals grant. An empty template keeps that valid SSM policy readable
// and discoverable as policy-created, but not convertible into a RAM permission.
func ramParameterPermissionTemplate(document, arn string) (string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &object); err != nil {
		return "", err
	}
	var statements []map[string]json.RawMessage
	if err := json.Unmarshal(object["Statement"], &statements); err != nil {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(object["Statement"], &statement); err != nil {
			return "", err
		}
		statements = []map[string]json.RawMessage{statement}
	}
	var commonPrincipals []string
	for i, statement := range statements {
		var effect string
		if err := json.Unmarshal(statement["Effect"], &effect); err != nil {
			return "", err
		}
		if effect != "Allow" || statement["NotAction"] != nil || statement["NotPrincipal"] != nil || statement["NotResource"] != nil {
			return "", nil
		}
		var principal map[string]json.RawMessage
		if err := json.Unmarshal(statement["Principal"], &principal); err != nil || len(principal) != 1 || principal["AWS"] == nil {
			return "", nil
		}
		principals, err := ramPolicyStrings(principal["AWS"])
		if err != nil {
			return "", err
		}
		slices.Sort(principals)
		principals = slices.Compact(principals)
		if i == 0 {
			commonPrincipals = principals
		} else if !slices.Equal(commonPrincipals, principals) {
			return "", nil
		}
		resources, err := ramPolicyStrings(statement["Resource"])
		if err != nil {
			return "", err
		}
		if len(resources) != 1 || resources[0] != arn {
			return "", nil
		}
		delete(statement, "Principal")
		delete(statement, "Resource")
	}
	object["Statement"], _ = json.Marshal(statements)
	encoded, err := json.Marshal(object)
	return string(encoded), err
}

func ramPolicyStrings(raw json.RawMessage) ([]string, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		return values, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return []string{value}, nil
}
