package main

import (
	"bytes"
	"fmt"
	"go/format"

	"stackd/internal/awsschema"
)

// These accessors serve the shared service authorization evaluators. Field presence
// and types come from each operation's input, not a second operation allowlist.
func renderAuthorization(c contract) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(generatedHeader)
	fmt.Fprintf(&out, "package %s\n", c.Info.Name)
	methods := map[string]string{
		"Tags":                  "RequestTags",
		"TagKeys":               "RequestTagKeys",
		"PolicyArn":             "PolicyARN",
		"PermissionsBoundary":   "PermissionsBoundaryARN",
		"OrganizationsPolicyId": "OrganizationsPolicyID",
		"Arn":                   "InputARN",
		"PolicySourceArn":       "PolicySourceARN",
		"TemplateArn":           "TemplateARN",
	}
	// Name shapes differ between creation and lookup (for example UserNameType
	// and ExistingUserNameType). The resource selector needs their string value
	// and presence; generated decoding retains each shape's own constraints.
	nameMethods := map[string]string{
		"UserName": "ResourceUserName", "GroupName": "ResourceGroupName",
		"RoleName": "ResourceRoleName", "ServerCertificateName": "ResourceServerCertificateName",
		"InstanceProfileName": "ResourceInstanceProfileName", "SerialNumber": "ResourceSerialNumber",
	}
	if c.Info.Name == "organizations" {
		methods = map[string]string{"Tags": "RequestTags", "TagKeys": "RequestTagKeys"}
		nameMethods = map[string]string{
			"AccountId": "ResourceAccountID", "ParentId": "ResourceParentID",
			"SourceParentId": "ResourceSourceParentID", "DestinationParentId": "ResourceDestinationParentID",
			"ChildId": "ResourceChildID", "OrganizationalUnitId": "ResourceUnitID",
			"RootId": "ResourceRootID", "PolicyId": "ResourcePolicyID",
			"TargetId": "ResourceTargetID", "ResourceId": "ResourceID",
			"HandshakeId": "ResourceHandshakeID",
			"Type":        "RequestPolicyType", "PolicyType": "RequestPolicyType", "Filter": "RequestPolicyType",
			"ServicePrincipal": "RequestServicePrincipal",
		}
	}
	if c.Info.Name == "sns" {
		methods = nil
		nameMethods = map[string]string{
			"TopicArn": "ResourceTopicARN", "ResourceArn": "ResourceARN",
			"SubscriptionArn": "ResourceSubscriptionARN",
		}
	}
	shapes := make(map[awsschema.ShapeID]awsschema.Shape, len(c.Shapes))
	for _, shape := range c.Shapes {
		shapes[shape.ID] = shape
	}
	label := c.Info.Name
	if label == "iam" {
		label = "IAM"
	}
	seen := make(map[awsschema.ShapeID]bool)
	for _, op := range c.Operations {
		if seen[op.Input] {
			continue
		}
		seen[op.Input] = true
		for _, member := range shapes[op.Input].Members {
			if method, ok := nameMethods[member.Name]; ok {
				if c.Info.Name == "organizations" && member.Name == "Filter" && shapeName(member.Target) != "PolicyType" {
					continue
				}
				if shapes[member.Target].Kind != "string" && shapes[member.Target].Kind != "enum" {
					return nil, fmt.Errorf("%s resource name %s must be a string", op.Name, member.Name)
				}
				fmt.Fprintf(&out, "// %s exposes the modeled %s member to %s resource selection.\n", method, member.Name, label)
				fmt.Fprintf(&out, "func (in *%s) %s() *string { return (*string)(in.%s) }\n", exportedName(shapeName(op.Input)), method, exportedName(member.Name))
				continue
			}
			method, ok := methods[member.Name]
			if !ok {
				continue
			}
			fmt.Fprintf(&out, "// %s exposes the modeled %s member to %s authorization.\n", method, member.Name, label)
			fmt.Fprintf(&out, "func (in *%s) %s() %s { return in.%s }\n", exportedName(shapeName(op.Input)), method, memberGoType(member, shapes), exportedName(member.Name))
		}
	}
	return format.Source(out.Bytes())
}
