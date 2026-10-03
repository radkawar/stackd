package cognitoidp

import (
	"slices"

	api "stackd/internal/awsapi/cognitoidp"
)

// Group claims are resolved at issuance, including refresh, rather than retained
// in the authentication family. Only explicitly ranked roles can be preferred.
func addGroupClaims(r Reader, user UserKey, access, id map[string]any) error {
	groups, err := r.GroupsForUser(user)
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		return nil
	}
	names := make([]string, len(groups))
	var roles []string
	var precedence *api.PrecedenceType
	preferred, ambiguous := "", false
	for i, group := range groups {
		names[i] = group.Key.Name
		role := value(group.Data.RoleArn)
		if role == "" {
			continue
		}
		roles = append(roles, role)
		rank := group.Data.Precedence
		if rank == nil {
			continue
		}
		if precedence == nil || *rank < *precedence {
			precedence, preferred, ambiguous = rank, role, false
		} else if *rank == *precedence && role != preferred {
			ambiguous = true
		}
	}
	access["cognito:groups"], id["cognito:groups"] = names, names
	if len(roles) != 0 {
		slices.Sort(roles)
		id["cognito:roles"] = slices.Compact(roles)
	}
	if preferred != "" && !ambiguous {
		id["cognito:preferred_role"] = preferred
	}
	return nil
}
