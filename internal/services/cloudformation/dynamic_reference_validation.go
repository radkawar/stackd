package cloudformation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DynamicReferencePin is a durable selector, not a cache of decrypted material.
// ParameterVersion belongs to ssm/ssm-secure; SecretVersionID belongs to Secrets Manager.
type DynamicReferencePin struct {
	Service          string `json:"service"`
	ParameterVersion int64  `json:"parameter_version,omitempty"`
	SecretVersionID  string `json:"secret_version_id,omitempty"`
}

type dynamicReference struct {
	service, name, jsonKey, stage, versionID string
	version                                  int64
}

var dynamicParameterName = regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`)

func parseDynamicReference(body string) (dynamicReference, error) {
	var ref dynamicReference
	ref.service, body, _ = strings.Cut(body, ":")
	switch ref.service {
	case "ssm", "ssm-secure":
		parts := strings.Split(body, ":")
		if len(parts) > 2 || !dynamicParameterName.MatchString(parts[0]) {
			return ref, invalid("SSM dynamic references require a parameter name and optional positive numeric version; labels and parameter ARNs are unsupported")
		}
		ref.name = parts[0]
		if len(parts) == 2 {
			version, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || version < 1 || strings.Trim(parts[1], "0123456789") != "" {
				return ref, invalid("SSM dynamic reference version must be a positive integer")
			}
			ref.version = version
		}
	case "secretsmanager":
		parts := strings.Split(body, ":")
		if strings.HasPrefix(body, "arn:") {
			if len(parts) < 7 || parts[2] != "secretsmanager" || parts[5] != "secret" {
				return ref, invalid("Secrets Manager dynamic reference requires a secret name or ARN")
			}
			ref.name = strings.Join(parts[:7], ":")
			parts = parts[7:]
		} else {
			ref.name = parts[0]
			parts = parts[1:]
		}
		if ref.name == "" || len(parts) > 4 {
			return ref, invalid("Invalid Secrets Manager dynamic reference segments")
		}
		if len(parts) > 0 && parts[0] != "" && parts[0] != "SecretString" {
			return ref, invalid("Secrets Manager dynamic references support only SecretString")
		}
		if len(parts) > 1 {
			ref.jsonKey = parts[1]
		}
		if len(parts) > 2 {
			ref.stage = parts[2]
		}
		if len(parts) > 3 {
			ref.versionID = parts[3]
		}
		if ref.stage != "" && ref.versionID != "" {
			return ref, invalid("Secrets Manager dynamic references cannot specify both version-stage and version-id")
		}
		if len(ref.stage) > 256 || ref.versionID != "" && (len(ref.versionID) < 32 || len(ref.versionID) > 64) {
			return ref, invalid("Invalid Secrets Manager dynamic reference version-stage or version-id length")
		}
	default:
		return ref, invalid("Unsupported dynamic reference service")
	}
	if strings.HasSuffix(body, "\\") {
		return ref, invalid("Invalid dynamic reference syntax")
	}
	return ref, nil
}

// The AWS ssm-secure property allowlist is intentionally independent of the
// locally implemented handlers: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references-ssm-secure-strings.html
var secureParameterProperties = map[string][]string{
	"AWS::DirectoryService::MicrosoftAD":   {"Password"},
	"AWS::DirectoryService::SimpleAD":      {"Password"},
	"AWS::ElastiCache::ReplicationGroup":   {"AuthToken"},
	"AWS::IAM::User":                       {"LoginProfile/Password"},
	"AWS::KinesisFirehose::DeliveryStream": {"RedshiftDestinationConfiguration/Password"},
	"AWS::OpsWorks::App":                   {"Source/Password"},
	"AWS::OpsWorks::Stack":                 {"CustomCookbooksSource/Password", "RdsDbInstances/*/DbPassword"},
	"AWS::RDS::DBCluster":                  {"MasterUserPassword"},
	"AWS::RDS::DBInstance":                 {"MasterUserPassword"},
	"AWS::Redshift::Cluster":               {"MasterUserPassword"},
}

func dynamicPathMatches(pattern, path string) bool {
	a, b := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != "*" && a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateDynamicResourceProperties(typeName string, properties Properties) error {
	return validateDynamicResourcePropertiesMode(typeName, properties, false)
}

func validateDynamicResourcePropertiesMode(typeName string, properties Properties, fragments bool) error {
	return walkDynamicProperty(map[string]any(properties), "", func(text, path string) error {
		if !strings.Contains(text, "{{resolve:") {
			return nil
		}
		secure := strings.Contains(text, "{{resolve:ssm-secure:") || strings.Contains(text, "{{resolve:secretsmanager:")
		if secure && (strings.HasPrefix(typeName, "Custom::") || typeName == "AWS::CloudFormation::CustomResource") {
			return invalid("Secure dynamic references are not supported in custom resources")
		}
		if (typeName == "AWS::EC2::Instance" || typeName == "AWS::EC2::LaunchTemplate" || typeName == "AWS::AutoScaling::LaunchConfiguration") && (path == "UserData" || path == "LaunchTemplateData/UserData") {
			return invalid("Dynamic references are not supported in EC2 UserData")
		}
		for rest := text; ; {
			start := strings.Index(rest, "{{resolve:")
			if start < 0 {
				return nil
			}
			rest = rest[start+len("{{resolve:"):]
			end := strings.Index(rest, "}}")
			if end < 0 && !fragments {
				return invalid("Unterminated dynamic reference")
			}
			if end < 0 {
				end = len(rest)
			}
			ref := dynamicReference{}
			if fragments && (end == len(rest) || strings.Contains(rest[:end], "${")) {
				ref.service, _, _ = strings.Cut(rest[:end], ":")
			} else {
				var err error
				ref, err = parseDynamicReference(rest[:end])
				if err != nil {
					return err
				}
			}
			if ref.service == "ssm-secure" {
				allowed := false
				for _, pattern := range secureParameterProperties[typeName] {
					allowed = allowed || dynamicPathMatches(pattern, path)
				}
				if !allowed {
					return invalid(fmt.Sprintf("SSM Secure reference is not supported in: [%s/Properties/%s]", typeName, path))
				}
			}
			if ref.service == "ssm-secure" || ref.service == "secretsmanager" {
				if dynamicIdentifierProperty(resourceSchemas[typeName], path) {
					// AWS warns that identifiers may expose plaintext. This is a
					// deliberate emulator safety limit, not an AWS syntax rule.
					// TODO: Comeback support secure identifier properties with credential-safe lifecycle addressing.
					return failure("NotImplementedException", "Secure dynamic references in resource identifiers are unsupported by stackd because identifiers are retained in CloudFormation state")
				}
			}
			if end == len(rest) {
				return nil
			}
			rest = rest[end+2:]
		}
	})
}

func dynamicIdentifierProperty(schema resourceSchema, path string) bool {
	parts := strings.Split(path, "/")
	for _, identifier := range schema.PrimaryIdentifier {
		if resourcePathsOverlap(resourcePathParts(identifier), parts) {
			return true
		}
	}
	for _, identifiers := range schema.AdditionalIdentifiers {
		for _, identifier := range identifiers {
			if resourcePathsOverlap(resourcePathParts(identifier), parts) {
				return true
			}
		}
	}
	return false
}

func walkDynamicProperty(value any, path string, visit func(string, string) error) error {
	switch v := value.(type) {
	case Properties:
		return walkDynamicProperty(map[string]any(v), path, visit)
	case map[string]any:
		if _, argument, intrinsic, _ := templateFunction(v); intrinsic {
			return walkDynamicProperty(argument, path, func(text, _ string) error { return visit(text, path) })
		}
		for _, key := range templateKeys(v) {
			child := key
			if path != "" {
				child = path + "/" + key
			}
			if err := walkDynamicProperty(v[key], child, visit); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := walkDynamicProperty(item, path+"/"+strconv.Itoa(i), visit); err != nil {
				return err
			}
		}
	case string:
		return visit(v, path)
	}
	return nil
}

func rejectSecureDynamicOutsideProperties(value any, location string) error {
	return walkDynamicProperty(value, "", func(text, _ string) error {
		if strings.Contains(text, "{{resolve:ssm-secure:") || strings.Contains(text, "{{resolve:secretsmanager:") {
			// TODO: Comeback support secure references outside Properties where AWS supports their evaluation.
			return failure("NotImplementedException", "Secure dynamic references outside resource Properties are unsupported by stackd: "+location)
		}
		return nil
	})
}
