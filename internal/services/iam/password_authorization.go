package iam

import "encoding/json"

// The account setting contributes an identity policy, so boundaries, session
// policies, SCPs and explicit denies still limit these permissions.
func passwordSelfManagementPolicies(userARN string) identityPolicies {
	document, _ := json.Marshal(struct {
		Version   string
		Statement []struct{ Effect, Action, Resource string }
	}{
		Version: "2012-10-17",
		Statement: []struct{ Effect, Action, Resource string }{
			{Effect: "Allow", Action: "iam:ChangePassword", Resource: userARN},
			{Effect: "Allow", Action: "iam:GetAccountPasswordPolicy", Resource: "*"},
		},
	})
	return identityPolicies{Inline: map[string]string{"account-password-self-management": string(document)}}
}
