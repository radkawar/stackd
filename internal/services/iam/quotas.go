package iam

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

const (
	maxUsers                      = 5000
	maxGroups                     = 300
	maxRoles                      = 1000
	maxPolicies                   = 1500
	maxManagedPolicyCharacters    = 6144
	maxTrustPolicyCharacters      = 2048
	maxInstanceProfiles           = 1000
	maxServerCertificates         = 20
	maxSigningCertificatesPerUser = 2
	maxGroupsPerUser              = 10
	maxVersionsPerPolicy          = 5
	// Customer policy quota plus the captured AWS catalogue remains below
	// this distinct-policy usage limit; a test guards that stronger bound.
	maxPolicyVersionsInUse      = 10000
	maxAttachedPoliciesPerUser  = 10
	maxAttachedPoliciesPerGroup = 10
	maxAttachedPoliciesPerRole  = 20
)

// IAM's current default quotas are documented at:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
// Account-specific AWS quota increases do not change these local defaults.
func attachedPolicyQuota(kind string) int {
	if kind == "Role" {
		return maxAttachedPoliciesPerRole
	}
	if kind == "Group" {
		return maxAttachedPoliciesPerGroup
	}
	return maxAttachedPoliciesPerUser
}

// policySize counts document characters without insignificant JSON whitespace.
func policySize(document string) int {
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(document)); err != nil {
		return utf8.RuneCountInString(document)
	}
	return utf8.RuneCount(compact.Bytes())
}

func inlinePolicyQuota(kind string) int {
	switch kind {
	case "User":
		return 2048
	case "Group":
		return 5120
	case "Role":
		return 10240
	default:
		panic("iam: unknown identity kind")
	}
}
