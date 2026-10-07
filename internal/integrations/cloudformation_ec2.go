package integrations

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationEC2Handlers delegates networking, guest and disk resource
// lifecycles to EC2's ordinary authorized commands. Networking controls do not
// require a guest runtime; instance and disk effects keep their real prerequisites.
func CloudFormationEC2Handlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	handlers := map[string]cloudformation.ResourceHandler{
		"AWS::EC2::VPC":                         cfnEC2VPC{commands},
		"AWS::EC2::Subnet":                      cfnEC2Subnet{commands},
		"AWS::EC2::InternetGateway":             cfnEC2InternetGateway{commands},
		"AWS::EC2::RouteTable":                  cfnEC2RouteTable{commands},
		"AWS::EC2::VPCGatewayAttachment":        cfnEC2GatewayAttachment{commands},
		"AWS::EC2::Route":                       cfnEC2Route{commands},
		"AWS::EC2::SubnetRouteTableAssociation": cfnEC2RouteAssociation{commands},
	}
	for _, family := range []map[string]cloudformation.ResourceHandler{CloudFormationEC2ComputeHandlers(commands), CloudFormationEC2AncillaryHandlers(commands), CloudFormationEC2NetworkExtensionHandlers(commands)} {
		for name, handler := range family {
			handlers[name] = handler
		}
	}
	return handlers
}

func cfnEC2Tags(tags api.TagList) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return out
}
func cfnEC2Missing(err error) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && (strings.HasSuffix(wire.Code, ".NotFound") || wire.Code == "NatGatewayNotFound")
}
func cfnEC2Absent(err error) error {
	if cfnEC2Missing(err) {
		return nil
	}
	return err
}
func cfnEC2Booleans(p cloudformation.Properties, keys ...string) error {
	for _, key := range keys {
		if value, exists := p[key]; exists {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	return nil
}
func cfnEC2IDResult(id string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id}
}

func cfnEC2NotFound(resource string) error {
	return &awswire.Error{Code: "Resource.NotFound", Message: resource + " does not exist", StatusCode: 400}
}
func cfnEC2PairID(r cloudformation.ResourceRequest, a, b, ak, bk string) string {
	if !r.CloudControl {
		return a + "|" + b
	}
	data, _ := json.Marshal(map[string]string{ak: a, bk: b})
	return string(data)
}
func cfnEC2Pair(id, ak, bk string) (string, string, error) {
	if strings.HasPrefix(id, "{") {
		var fields map[string]string
		if err := json.Unmarshal([]byte(id), &fields); err != nil {
			return "", "", err
		}
		if fields[ak] == "" || fields[bk] == "" {
			return "", "", fmt.Errorf("invalid composite EC2 identifier")
		}
		return fields[ak], fields[bk], nil
	}
	a, b, ok := strings.Cut(id, "|")
	if !ok || a == "" || b == "" {
		return "", "", fmt.Errorf("invalid composite EC2 identifier")
	}
	return a, b, nil
}
