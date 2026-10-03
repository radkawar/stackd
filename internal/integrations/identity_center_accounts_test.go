package integrations

import (
	"testing"

	"stackd/internal/services/identitycenter"
	"stackd/storage/organizations"
)

func TestIdentityCenterAccountAdmission(t *testing.T) {
	storage := organizations.NewMemory(nil)
	state := organizations.PartitionRecord{Organizations: []organizations.OrganizationRecord{{
		Organization: organizations.OrganizationDetails{ID: "o-example", MasterAccountID: "111111111111", FeatureSet: "ALL"},
		Accounts:     []organizations.AccountRecord{{ID: "111111111111", State: "ACTIVE"}, {ID: "222222222222", State: "ACTIVE"}, {ID: "333333333333", State: "ACTIVE"}, {ID: "444444444444", State: "SUSPENDED"}},
		Services:     []organizations.ServiceAccessRecord{{Principal: "sso.amazonaws.com"}},
		Delegations:  []organizations.DelegationRecord{{AccountID: "222222222222", Principal: "sso.amazonaws.com"}},
	}, {
		Organization: organizations.OrganizationDetails{ID: "o-other", MasterAccountID: "555555555555", FeatureSet: "ALL"},
		Accounts:     []organizations.AccountRecord{{ID: "555555555555", State: "ACTIVE"}},
	}}}
	var revision uint64
	save := func() {
		t.Helper()
		ok, err := storage.CompareAndSwap(t.Context(), "aws", revision, state, nil)
		if err != nil || !ok {
			t.Fatalf("save Organizations state: %t %v", ok, err)
		}
		_, revision, err = storage.Load(t.Context(), "aws")
		if err != nil {
			t.Fatal(err)
		}
	}
	save()
	adapter := IdentityCenterAccounts{Storage: storage}
	for _, tc := range []struct {
		name, partition, owner, target string
		allowed                        bool
	}{
		{"local owner", "aws", "999999999999", "999999999999", true},
		{"management member", "aws", "111111111111", "333333333333", true},
		{"delegated member", "aws", "222222222222", "333333333333", true},
		{"ordinary member", "aws", "333333333333", "222222222222", false},
		{"delegated management", "aws", "222222222222", "111111111111", false},
		{"suspended target", "aws", "111111111111", "444444444444", false},
		{"suspended owner", "aws", "444444444444", "333333333333", false},
		{"foreign organization", "aws", "111111111111", "555555555555", false},
		{"unregistered target", "aws", "111111111111", "666666666666", false},
		{"foreign partition", "aws-cn", "111111111111", "333333333333", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := adapter.Allowed(t.Context(), identitycenter.Scope{Partition: tc.partition, AccountID: tc.owner, Region: "us-east-1"}, tc.target)
			if err != nil || allowed != tc.allowed {
				t.Fatalf("allowed=%t, want=%t: %v", allowed, tc.allowed, err)
			}
		})
	}
	delegated := identitycenter.Scope{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}
	state.Organizations[0].Delegations = []organizations.DelegationRecord{{AccountID: delegated.AccountID, Principal: "cloudtrail.amazonaws.com"}}
	save()
	if allowed, err := adapter.Allowed(t.Context(), delegated, "333333333333"); err != nil || allowed {
		t.Fatalf("non-SSO delegation authorized: %t %v", allowed, err)
	}
	state.Organizations[0].Services = nil
	save()
	if allowed, err := adapter.Allowed(t.Context(), identitycenter.Scope{Partition: "aws", AccountID: "111111111111"}, "333333333333"); err != nil || allowed {
		t.Fatalf("revoked trusted access authorized: %t %v", allowed, err)
	}
}
