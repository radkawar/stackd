package iam

import "time"

// PrincipalActivity is the latest authenticated API attempt for an IAM principal,
// service, action and region. Denied attempts count; authorization dependencies do
// not. PrincipalID preserves identity across renames without merging replacements.
type PrincipalActivity struct {
	PrincipalID       string
	PrincipalARN      string
	ServiceNamespace  string
	ActionName        string
	Region            string
	LastAuthenticated time.Time
}
