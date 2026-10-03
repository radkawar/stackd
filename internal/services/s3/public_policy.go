package s3

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"stackd/iam/policy"
	"stackd/internal/iam/catalog"
)

// Public classification is a trust analysis, not request authorization. The IAM
// parser owns policy syntax and the IAM permission summary owns action/resource
// set algebra, including NotAction, NotResource and overlapping explicit denies.
// S3 contributes only its resource admission and public trust-anchor rules.
type publicPolicyStatement struct {
	Effect       string
	Principal    json.RawMessage                       `json:",omitempty"`
	NotPrincipal json.RawMessage                       `json:",omitempty"`
	Action       json.RawMessage                       `json:",omitempty"`
	NotAction    json.RawMessage                       `json:",omitempty"`
	Resource     json.RawMessage                       `json:",omitempty"`
	NotResource  json.RawMessage                       `json:",omitempty"`
	Condition    map[string]map[string]json.RawMessage `json:",omitempty"`
}

type publicPolicyMetadata struct {
	catalog.Service
	conditionActions map[string]map[string]struct{}
}

var publicPolicyCatalog = sync.OnceValues(func() (publicPolicyMetadata, error) {
	c, err := catalog.Load()
	if err != nil {
		return publicPolicyMetadata{}, err
	}
	s, ok := c.LookupService("s3")
	if !ok {
		return publicPolicyMetadata{}, fmt.Errorf("S3 IAM action catalog is missing")
	}
	metadata := publicPolicyMetadata{Service: s, conditionActions: make(map[string]map[string]struct{})}
	for _, action := range s.Actions {
		for _, key := range action.ConditionKeys {
			key = strings.ToLower(key)
			if variable := strings.IndexAny(key, "$<"); variable >= 0 {
				key = key[:variable]
			}
			if metadata.conditionActions[key] == nil {
				metadata.conditionActions[key] = make(map[string]struct{})
			}
			metadata.conditionActions[key][action.Name] = struct{}{}
		}
	}
	return metadata, nil
})

func bucketPolicyPublic(document, bucketARN string) (bool, error) {
	return s3PolicyPublic(document, bucketARN, false)
}

func accessPointPolicyPublic(document string, point AccessPointRecord) (bool, error) {
	public, err := s3PolicyPublic(document, point.Key.ARN(), true)
	return public && point.VPCID == "", err
}

func s3PolicyPublic(document, resourceARN string, accessPoint bool) (bool, error) {
	statements, resources, err := parseS3Policy(document, resourceARN, accessPoint)
	if err != nil {
		return false, err
	}
	for _, allow := range statements {
		if allow.Effect != "Allow" || fixedPrincipal(allow.Principal) || publicPolicyTrustedCondition(allow.Condition, accessPoint) {
			continue
		}
		projection := []publicPolicyStatement{publicPolicySelectors(allow)}
		for _, deny := range statements {
			// Native public classification does not infer a trusted remainder
			// from NotPrincipal. Only a universal principal can cancel a grant.
			if deny.Effect != "Deny" || len(deny.NotPrincipal) != 0 || !publicPolicyUniversalPrincipal(deny.Principal) {
				continue
			}
			if publicPolicyDenyRestricts(deny.Condition, allow.Condition, accessPoint) {
				projection = append(projection, publicPolicySelectors(deny))
			}
		}
		actions, err := publicPolicyPotential(context.Background(), projection, resources)
		if err != nil {
			return false, err
		}
		if len(actions) != 0 {
			return true, nil
		}
	}
	return false, nil
}

// parseS3PolicyStatements shares the resource-policy parser with public
// classification. Evidence queries consume already admitted source state and
// need not rerun the catalog's action/resource admission checks.
func parseS3PolicyStatements(document string) ([]publicPolicyStatement, *policy.Document, error) {
	compiled, err := policy.ParseResource([]byte(document))
	if err != nil {
		return nil, nil, err
	}
	var raw struct{ Statement json.RawMessage }
	if err := json.Unmarshal([]byte(document), &raw); err != nil {
		return nil, nil, err
	}
	var statements []publicPolicyStatement
	if len(raw.Statement) > 0 && raw.Statement[0] == '[' {
		if err := json.Unmarshal(raw.Statement, &statements); err != nil {
			return nil, nil, err
		}
	} else {
		var st publicPolicyStatement
		if err := json.Unmarshal(raw.Statement, &st); err != nil {
			return nil, nil, err
		}
		statements = []publicPolicyStatement{st}
	}
	return statements, compiled, nil
}

func parseS3Policy(document, resourceARN string, accessPoint bool) ([]publicPolicyStatement, map[string][]string, error) {
	statements, _, err := parseS3PolicyStatements(document)
	if err != nil {
		return nil, nil, failure("MalformedPolicy", err.Error(), 400)
	}
	service, err := publicPolicyCatalog()
	if err != nil {
		return nil, nil, err
	}
	resources := make(map[string][]string, len(service.Actions))
	allActions := make(map[string][]string, len(service.Actions))
	for _, action := range service.Actions {
		allActions[action.Name] = nil
		for _, kind := range action.Resources {
			switch kind {
			case "bucket", "accesspoint":
				if accessPoint == (kind == "accesspoint") {
					resources[action.Name] = append(resources[action.Name], resourceARN)
				}
			case "object":
				if !accessPoint {
					resources[action.Name] = append(resources[action.Name], resourceARN+"/*")
				}
			case "accesspointobject":
				if accessPoint {
					resources[action.Name] = append(resources[action.Name], resourceARN+"/object/*")
				}
			}
		}
	}
	for _, st := range statements {
		var conditionActions []map[string]struct{}
		for _, keys := range st.Condition {
			for key := range keys {
				key = strings.ToLower(key)
				if !strings.HasPrefix(key, "s3:") {
					continue
				}
				actions := service.conditionActions[key]
				if actions == nil {
					prefix, suffix, tagged := strings.Cut(key, "/")
					if tagged && suffix != "" {
						actions = service.conditionActions[prefix+"/"]
					}
				}
				if actions == nil {
					return nil, nil, failure("MalformedPolicy", "Policy has an invalid condition key.", 400)
				}
				conditionActions = append(conditionActions, actions)
			}
		}
		if err := admitPublicPolicyStatement(st, resourceARN, accessPoint, allActions, resources, conditionActions); err != nil {
			return nil, nil, err
		}
	}
	return statements, resources, nil
}

func publicPolicySelectors(st publicPolicyStatement) publicPolicyStatement {
	st.Principal, st.NotPrincipal, st.Condition = nil, nil, nil
	return st
}

func publicPolicyPotential(ctx context.Context, statements []publicPolicyStatement, resources map[string][]string) ([]string, error) {
	summary, err := publicPolicySummary(statements)
	if err != nil {
		return nil, err
	}
	return policy.PotentialActions(ctx, [][]*policy.PermissionSummary{{summary}}, resources)
}

func publicPolicySummary(statements []publicPolicyStatement) (*policy.PermissionSummary, error) {
	data, err := json.Marshal(struct{ Statement []publicPolicyStatement }{statements})
	if err != nil {
		return nil, err
	}
	return policy.ParsePermissionSummary(data)
}

func admitPublicPolicyStatement(st publicPolicyStatement, resourceARN string, accessPoint bool, allActions, resources map[string][]string, conditionActions []map[string]struct{}) error {
	selectedResources := st.Resource
	if len(st.NotResource) != 0 {
		selectedResources = st.NotResource
	}
	objectPrefix := resourceARN + "/"
	if accessPoint {
		objectPrefix += "object/"
	}
	for _, resource := range policyStrings(selectedResources) {
		if resource != resourceARN && !strings.HasPrefix(resource, objectPrefix) {
			return failure("MalformedPolicy", "Policy has invalid resource.", 400)
		}
	}
	selector := publicPolicySelectors(st)
	selector.Effect = "Allow"
	if len(st.NotAction) != 0 {
		// NotAction's excluded actions need not apply to the remaining resources.
		return nil
	}
	for _, action := range policyStrings(st.Action) {
		encoded, err := json.Marshal(action)
		if err != nil {
			return err
		}
		selector.Action = encoded
		actionOnly := selector
		actionOnly.Resource, actionOnly.NotResource = json.RawMessage(`"*"`), nil
		matching, err := publicPolicyPotential(context.Background(), []publicPolicyStatement{actionOnly}, allActions)
		if err != nil {
			return err
		}
		if len(matching) == 0 {
			return failure("MalformedPolicy", "Policy has invalid action.", 400)
		}
		applicable := make(map[string][]string, len(matching))
		for _, name := range matching {
			if r, ok := resources[name]; ok {
				applicable[name] = r
			}
		}
		matching, err = publicPolicyPotential(context.Background(), []publicPolicyStatement{selector}, applicable)
		if err != nil {
			return err
		}
		if len(matching) == 0 {
			return failure("MalformedPolicy", "Action does not apply to any resource(s) in statement", 400)
		}
		for _, supported := range conditionActions {
			applies := false
			for _, name := range matching {
				if _, applies = supported[name]; applies {
					break
				}
			}
			if !applies {
				return failure("MalformedPolicy", "Conditions do not apply to combination of actions and resources in statement", 400)
			}
		}
	}
	return nil
}

func policyStrings(raw json.RawMessage) []string {
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		return values
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return []string{value}
	}
	return nil
}

func fixedPrincipal(raw json.RawMessage) bool {
	// ParseResource has already validated principal kinds and fixed values.
	return !publicPolicyUniversalPrincipal(raw)
}

func publicPolicyUniversalPrincipal(raw json.RawMessage) bool {
	if values := policyStrings(raw); len(values) != 0 {
		for _, value := range values {
			if value == "*" {
				return true
			}
		}
	}
	var principals map[string]json.RawMessage
	if json.Unmarshal(raw, &principals) == nil {
		for _, value := range policyStrings(principals["AWS"]) {
			if value == "*" {
				return true
			}
		}
	}
	return false
}
