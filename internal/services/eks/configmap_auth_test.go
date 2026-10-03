package eks

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"stackd/internal/awsctx"
)

type accessFixturePrincipals map[string]string

func (p accessFixturePrincipals) ResolvePrincipal(_ context.Context, arn string) (string, error) {
	if id := p[arn]; id != "" {
		return id, nil
	}
	return "", errors.New("principal no longer exists")
}

func TestAWSAuthPrimaryFixture(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/eks/access_authentication.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Authentication []struct {
			Name, Mode, CurrentID, EntryID, MapRole, WantUsername string
			MapUser, Role, Creator, Denied                        bool
			WantGroups                                            []string
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Authentication {
		t.Run(tc.Name, func(t *testing.T) {
			repo := NewMemoryRepository(nil)
			key := Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "fixture"}
			m := awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:user/developer", PrincipalID: "new-user"}
			if tc.Role {
				m.SessionType, m.IssuerARN, m.IssuerID = "AssumeRole", "arn:aws:iam::111111111111:role/team/developer", "new-user"
				m.PrincipalARN, m.PrincipalID = "arn:aws:sts::111111111111:assumed-role/developer/demo@example.test", "new-user:demo@example.test"
			}
			principal, _ := principalIdentity(m)
			cluster := Cluster{Key: key, ID: "incarnation", Status: "ACTIVE", AuthenticationMode: tc.Mode}
			if tc.Creator {
				cluster.CreatorARN, cluster.CreatorID, cluster.BootstrapAdmin = principal, "new-user", true
			}
			if err := repo.Update(t.Context(), func(tx Transaction) error {
				if err := tx.PutCluster(cluster); err != nil {
					return err
				}
				if tc.EntryID != "" {
					return tx.PutAccessEntry(AccessEntry{Key: key, PrincipalARN: principal, PrincipalID: tc.EntryID, Username: "api-user", Groups: []string{"api-viewers"}})
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			config := map[string]string{}
			if tc.MapUser {
				config["mapUsers"] = "- userarn: " + principal + "\n  username: legacy-user\n  groups: [viewers]\n"
			}
			if tc.MapRole != "" {
				config["mapRoles"] = "- rolearn: " + tc.MapRole + "\n  username: 'role:{{SessionNameRaw}}:{{AccountID}}'\n  groups: ['session:{{SessionName}}']\n"
			}
			s := &Service{repository: repo, principals: accessFixturePrincipals{principal: tc.CurrentID}}
			identity, _, _, err := s.kubernetesIdentity(t.Context(), key, cluster.ID, m, config, true)
			if tc.Denied {
				if err == nil {
					t.Fatalf("unauthorized authentication succeeded: %+v", identity)
				}
				return
			}
			if err != nil || identity.Username != tc.WantUsername || !slices.Equal(identity.Groups, tc.WantGroups) {
				t.Fatalf("identity = %+v, error = %v", identity, err)
			}
		})
	}
}
