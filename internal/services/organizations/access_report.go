package organizations

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

var (
	ErrAccessReportManagementRequired = errors.New("organization access reports require the management account")
	ErrAccessReportSCPDisabled        = errors.New("organization access reports require service control policies")
	ErrAccessReportWrongOrganization  = errors.New("organization access report path identifies another organization")
	ErrAccessReportEntityNotFound     = errors.New("organization access report entity path does not exist")
	ErrAccessReportPolicyNotFound     = errors.New("organization access report service control policy does not exist")
	ErrAccessReportReadDenied         = errors.New("organization access report read permissions are denied")
)

// AccessReportAccount identifies an account whose activity belongs in a report.
type AccessReportAccount struct {
	AccountID  string
	EntityPath string
}

// AccessReportSnapshot is the detached Organizations input for an IAM access
// report. PolicyLevels determines the report's available services; an empty
// hierarchy is unrestricted (the management-account target). Accounts determines
// whose activity can be included.
//
// This snapshot is independent of IAM's transaction and activity snapshot.
type AccessReportSnapshot struct {
	PolicyLevels []iampolicy.PolicyLevel
	Accounts     []AccessReportAccount
}

// CheckAccessReportAccess checks current management-account membership and SCP
// availability. IAM separately authorizes its report operation.
func (s *Service) CheckAccessReportAccess(ctx context.Context) error {
	_, err := s.accessReportOrganization(ctx)
	return err
}

func (s *Service) accessReportOrganization(ctx context.Context) (*orgState, error) {
	m := awsctx.FromContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.Partition == "" || m.AccountID == "" {
		return nil, ErrAccessReportManagementRequired
	}
	record, _, err := s.storage.Load(ctx, m.Partition)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state := decodeState(record, m.Partition, m.AccountID)
	o := state.orgs[state.memberships[m.AccountID]]
	if o == nil || o.organization.MasterAccountID != m.AccountID {
		return nil, ErrAccessReportManagementRequired
	}
	if !o.policyEnabled("SERVICE_CONTROL_POLICY") {
		return nil, ErrAccessReportSCPDisabled
	}
	return o, nil
}

// AccessReportSnapshot resolves a report selection from one Organizations read.
// The caller must separately authorize the IAM report operation. This method
// owns organization membership, management-account eligibility, path validation,
// and SCP/account selection.
func (s *Service) AccessReportSnapshot(ctx context.Context, entityPath, policyID string) (AccessReportSnapshot, error) {
	o, err := s.accessReportOrganization(ctx)
	if err != nil {
		return AccessReportSnapshot{}, err
	}
	// The API rejects trailing slashes and empty path components, although the
	// user guide also illustrates trailing-slash paths.
	parts := strings.Split(entityPath, "/")
	if len(parts) < 2 {
		return AccessReportSnapshot{}, ErrAccessReportEntityNotFound
	}
	if parts[0] != o.organization.ID {
		return AccessReportSnapshot{}, ErrAccessReportWrongOrganization
	}
	if parts[1] != o.root.ID {
		return AccessReportSnapshot{}, ErrAccessReportEntityNotFound
	}
	for i := 2; i < len(parts); i++ {
		if !o.parentExists(parts[i-1]) || !o.targetExists(parts[i]) || o.parents[parts[i]] != parts[i-1] {
			return AccessReportSnapshot{}, ErrAccessReportEntityNotFound
		}
	}
	target := parts[len(parts)-1]
	if err := s.authorizeAccessReport(ctx, o, parts[1:], policyID); err != nil {
		return AccessReportSnapshot{}, err
	}
	out := AccessReportSnapshot{Accounts: []AccessReportAccount{}}
	if target == o.organization.MasterAccountID {
		// The optional policy is ignored for this SCP-exempt target, including
		// policy IDs which do not identify any current organization policy.
		out.Accounts = append(out.Accounts, AccessReportAccount{AccountID: target, EntityPath: entityPath})
		return out, nil
	}
	if policyID != "" {
		p, ok := o.policies[policyID]
		if !ok || p.PolicySummary.Type != "SERVICE_CONTROL_POLICY" {
			return AccessReportSnapshot{}, ErrAccessReportPolicyNotFound
		}
		out.PolicyLevels = []iampolicy.PolicyLevel{{TargetID: target, Documents: []iampolicy.Policy{{Source: p.PolicySummary.ARN, Document: p.Content}}}}
	} else {
		out.PolicyLevels = o.controlPolicyLevels(target, "SERVICE_CONTROL_POLICY")
	}
	for id := range o.accounts {
		if id == o.organization.MasterAccountID {
			continue
		}
		// Walk only as far as the selected entity. A policy attached above a
		// selected OU/account does not select account data for a policy report.
		attached := policyID == ""
		current := id
		for current != "" {
			attached = attached || slices.Contains(o.attachments[current], policyID)
			if current == target {
				break
			}
			current = o.parents[current]
		}
		if current != target || !attached {
			continue
		}
		accountPath := strings.TrimSuffix(o.entityPath(id), "/")
		out.Accounts = append(out.Accounts, AccessReportAccount{AccountID: id, EntityPath: accountPath})
	}
	slices.SortFunc(out.Accounts, func(a, b AccessReportAccount) int { return strings.Compare(a.AccountID, b.AccountID) })
	if err := ctx.Err(); err != nil {
		return AccessReportSnapshot{}, err
	}
	return out, nil
}

func (s *Service) authorizeAccessReport(ctx context.Context, o *orgState, hierarchy []string, policyID string) error {
	m := awsctx.FromContext(ctx)
	target := hierarchy[len(hierarchy)-1]
	if target == o.organization.MasterAccountID {
		policyID = ""
	}
	var plan []authorization.Request
	add := func(action, id string) {
		conditions := map[string][]string{}
		if action == "ListPoliciesForTarget" {
			conditions["organizations:PolicyType"] = []string{"SERVICE_CONTROL_POLICY"}
		}
		plan = append(plan, organizationPermission(o, m.Partition, m.AccountID, action, id, conditions))
	}
	add("ListRoots", "*")
	for _, id := range hierarchy {
		if id != o.root.ID {
			add("ListParents", id)
		}
		add("ListPoliciesForTarget", id)
	}
	if policyID != "" {
		add("DescribePolicy", policyID)
		add("ListTargetsForPolicy", policyID)
	} else {
		policies := make(map[string]bool)
		for _, targetID := range hierarchy {
			for _, id := range o.attachments[targetID] {
				if o.policies[id].PolicySummary.Type == "SERVICE_CONTROL_POLICY" {
					policies[id] = true
				}
			}
		}
		for _, id := range slices.Sorted(maps.Keys(policies)) {
			add("DescribePolicy", id)
		}
		if o.parentExists(target) {
			add("ListChildren", target)
			for _, id := range slices.Sorted(maps.Keys(o.units)) {
				for parent := o.parents[id]; parent != ""; parent = o.parents[parent] {
					if parent == target {
						add("ListChildren", id)
						break
					}
				}
			}
		}
	}
	s.mu.RLock()
	authorizer := s.authorizer
	s.mu.RUnlock()
	instant := s.clock.Now()
	// Management membership was checked in the same detached Organizations
	// read. Reuse that SCP exemption while IAM evaluates dependency permissions.
	ctx = context.WithValue(ctx, policySnapshotKey{}, policySnapshot{source: s, partition: m.Partition, account: m.AccountID, organization: o.organization.ID, path: o.organization.ID + "/" + o.root.ID + "/"})
	for _, permission := range plan {
		permission.EvaluationTime = &instant
		if err := authorizer.Authorize(ctx, permission); err != nil {
			if err.StatusCode >= 500 {
				return err
			}
			return ErrAccessReportReadDenied
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}
