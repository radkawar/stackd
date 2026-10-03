// Package roletemplates provides the captured AWS-managed role definitions.
package roletemplates

import (
	_ "embed"
	"encoding/json"

	iamapi "stackd/internal/awsapi/iam"
)

//go:embed data/aws.json
var snapshot []byte

// Lookup returns a detached generated contract, or nil when the ARN/version is
// absent. No network or source checkout is needed. The small catalogue is
// decoded per lookup so callers own every policy, parameter and optional field.
func Lookup(arn string, minor *iamapi.MinorVersionType) (*iamapi.RoleTemplateVersion, error) {
	var data struct {
		Templates []iamapi.RoleTemplateVersion `json:"templates"`
	}
	if err := json.Unmarshal(snapshot, &data); err != nil {
		return nil, err
	}
	for _, version := range data.Templates {
		if string(*version.TemplateArn) != arn {
			continue
		}
		requested := version.DefaultMinorVersion
		if minor != nil {
			requested = minor
		}
		if *requested == *version.MinorVersion {
			return &version, nil
		}
	}
	return nil, nil
}
