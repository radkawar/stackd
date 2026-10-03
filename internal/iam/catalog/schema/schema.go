// Package schema defines the generated IAM metadata used by service authorization
// and reports. It has no embedded data dependency, so iamgen can bootstrap.
package schema

type Service struct {
	Prefix    string     `json:"prefix"`
	Actions   []Action   `json:"actions"`
	Resources []Resource `json:"resources"`
}

type Action struct {
	Name          string   `json:"name"`
	Resources     []string `json:"resources,omitempty"`
	ConditionKeys []string `json:"condition_keys,omitempty"`
	Ambiguous     bool     `json:"ambiguous,omitempty"`
}

type Resource struct {
	Name         string   `json:"name"`
	ARNTemplates []string `json:"arn_templates"`
}
