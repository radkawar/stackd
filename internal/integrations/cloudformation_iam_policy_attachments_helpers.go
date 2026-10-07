package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/iam"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
)

func CloudFormationIAMAdditionalHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::IAM::InstanceProfile": cfnIAMInstanceProfile{commands}, "AWS::IAM::User": cfnIAMUser{commands}, "AWS::IAM::Group": cfnIAMGroup{commands}, "AWS::IAM::UserToGroupAddition": cfnIAMUserToGroupAddition{commands}, "AWS::IAM::AccessKey": cfnIAMAccessKey{commands}, "AWS::IAM::OIDCProvider": cfnIAMOIDC{commands}, "AWS::IAM::SAMLProvider": cfnIAMSAML{commands}, "AWS::IAM::VirtualMFADevice": cfnIAMMFA{commands}, "AWS::IAM::ServiceLinkedRole": cfnIAMServiceLinked{commands}, "AWS::IAM::UserPolicy": cfnIAMUserPolicy{cfnIAMInlineAttachment{commands, "User"}}, "AWS::IAM::GroupPolicy": cfnIAMGroupPolicy{cfnIAMInlineAttachment{commands, "Group"}}, "AWS::IAM::RolePolicy": cfnIAMRolePolicy{cfnIAMInlineAttachment{commands, "Role"}},
		"AWS::IAM::ServerCertificate": cfnIAMServerCertificate{commands},
	}
}
func cfnIAMContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return iamowner.WithCloudFormationContext(ctx, iamowner.CloudFormationContext{Owner: cfnIAMPolicyOwner(r), Direct: r.CloudControl})
}
func cfnIAMTags(tags api.TagListType) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		out[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return out
}
func cfnIAMCustomerTags(r cloudformation.ResourceRequest) map[string]string {
	tags, _ := cfnComputeTags(r.Properties)
	return tags
}
func cfnIAMUserTags(tags api.TagListType) []map[string]string {
	out := []map[string]string{}
	for _, t := range tags {
		k := cfnComputeValue(t.Key)
		out = append(out, map[string]string{"Key": k, "Value": cfnComputeValue(t.Value)})
	}
	return out
}
func cfnIAMUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, kind, key, id string, current map[string]string) error {
	desired := cfnIAMCustomerTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "iam", "Untag"+kind, map[string]any{key: id, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "iam", "Tag"+kind, map[string]any{key: id, "Tags": cfnComputeTagList(desired)})
}
func cfnIAMNamedResult(name, arn string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": arn}}
}
func cfnIAMNotFound() error {
	return &awswire.Error{Code: "NoSuchEntity", Message: "IAM resource does not exist.", StatusCode: 404}
}
func cfnIAMDocument(raw string) any {
	decoded, err := url.QueryUnescape(raw)
	if err == nil {
		raw = decoded
	}
	var document any
	if json.Unmarshal([]byte(raw), &document) == nil {
		return document
	}
	return raw
}
func cfnIAMPolicyInputs(kind, name, policy, document string) map[string]any {
	in := map[string]any{kind + "Name": name, "PolicyName": policy}
	if document != "" {
		in["PolicyDocument"] = document
	}
	return in
}
func cfnIAMIdentityPolicies(ctx context.Context, c StepFunctionsCommands, kind, name string) (cloudformation.Properties, error) {
	p := cloudformation.Properties{}
	policies := []any{}
	input := map[string]any{kind + "Name": name}
	for {
		listed, marker, err := cfnIAMListInline(ctx, c, kind, input)
		if err != nil {
			return nil, err
		}
		for _, policy := range listed {
			policyName := string(policy)
			doc, err := cfnIAMGetInline(ctx, c, kind, cfnIAMPolicyInputs(kind, name, policyName, ""))
			if err != nil {
				return nil, err
			}
			policies = append(policies, map[string]any{"PolicyName": policyName, "PolicyDocument": cfnIAMDocument(doc)})
		}
		if marker == "" {
			break
		}
		input["Marker"] = marker
	}
	p["Policies"] = policies
	managed := []string{}
	delete(input, "Marker")
	for {
		listed, marker, err := cfnIAMListAttached(ctx, c, kind, input)
		if err != nil {
			return nil, err
		}
		for _, policy := range listed {
			managed = append(managed, cfnComputeValue(policy.PolicyArn))
		}
		if marker == "" {
			break
		}
		input["Marker"] = marker
	}
	p["ManagedPolicyArns"] = managed
	return p, nil
}
func cfnIAMReconcilePolicies(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, kind, name string) error {
	desired, err := cfnIAMInlinePolicies(r.Properties)
	if err != nil {
		return err
	}
	old, _ := cfnIAMInlinePolicies(r.Previous)
	for policy, doc := range desired {
		if err := cfnComputeRun(cfnIAMContext(ctx, r), c, "iam", "Put"+kind+"Policy", cfnIAMPolicyInputs(kind, name, policy, doc)); err != nil {
			return err
		}
	}
	for policy := range old {
		if _, ok := desired[policy]; !ok {
			if err := cfnComputeAbsent(cfnComputeRun(cfnIAMContext(ctx, r), c, "iam", "Delete"+kind+"Policy", cfnIAMPolicyInputs(kind, name, policy, ""))); err != nil {
				return err
			}
		}
	}
	managed, _ := cfnComputeStringList(r.Properties, "ManagedPolicyArns")
	previous, _ := cfnComputeStringList(r.Previous, "ManagedPolicyArns")
	for _, policy := range managed {
		if err := cfnComputeRun(cfnIAMContext(ctx, r), c, "iam", "Attach"+kind+"Policy", map[string]any{kind + "Name": name, "PolicyArn": policy}); err != nil {
			return err
		}
	}
	for _, policy := range previous {
		found := false
		for _, v := range managed {
			if v == policy {
				found = true
			}
		}
		if !found {
			if err := cfnComputeAbsent(cfnComputeRun(cfnIAMContext(ctx, r), c, "iam", "Detach"+kind+"Policy", map[string]any{kind + "Name": name, "PolicyArn": policy})); err != nil {
				return err
			}
		}
	}
	return nil
}
func cfnIAMValidateIdentity(p cloudformation.Properties, keys ...string) error {
	if err := cfnComputeProperties(p, keys...); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Path"); err != nil {
		return err
	}
	if _, err := cfnIAMInlinePolicies(p); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "ManagedPolicyArns"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func cfnIAMARN(r cloudformation.ResourceRequest, kind, path, name string) string {
	return "arn:" + r.Scope.Partition + ":iam::" + r.Scope.Account + ":" + kind + strings.TrimSuffix(path, "/") + "/" + name
}
func cfnIAMRequireList(p cloudformation.Properties, key string, max int) error {
	if err := cfnComputeRequired(p, key); err != nil {
		return err
	}
	list, err := cfnComputeStringList(p, key)
	if err != nil {
		return err
	}
	if max >= 0 && len(list) > max {
		return fmt.Errorf("%s supports at most %d entries", key, max)
	}
	return nil
}
func cfnIAMInteger(p map[string]any, key string, min, max int64) (int64, error) {
	raw, err := json.Marshal(p[key])
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < float64(min) || n > float64(max) {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	return int64(n), nil
}
