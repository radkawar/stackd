package eks_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	native "stackd/compute/eks"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite"
	eksdb "stackd/storage/sqlite/eks"
)

type admissionCases struct {
	AssociationConditions []struct {
		Key, Value, Operator string
		Allowed              bool
	}
	Fargate []struct {
		Name             string
		Profiles, Labels int
		Error            string
	}
}

func readAdmissionCases(t *testing.T) admissionCases {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/eks/admission_contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases admissionCases
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

type associationPolicy string

func (p associationPolicy) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: string(p)}}}, nil
}

func TestPodIdentityAssociationSupportedConditions(t *testing.T) {
	for _, row := range readAdmissionCases(t).AssociationConditions {
		t.Run(row.Key, func(t *testing.T) {
			repository := domain.NewMemoryRepository(nil)
			key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "admission"}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:user/operator", PrincipalID: "AIDAOPERATOR"})
			if err := repository.Update(ctx, func(tx domain.Transaction) error {
				return tx.PutCluster(domain.Cluster{Key: key, ID: "cluster-id", Status: "ACTIVE", Tags: map[string]string{"owner": "platform"}})
			}); err != nil {
				t.Fatal(err)
			}
			operator := row.Operator
			if operator == "" {
				operator = "StringEquals"
			}
			document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"eks:CreatePodIdentityAssociation","Resource":"*","Condition":{%q:{%q:%q}}},{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`, operator, row.Key, row.Value)
			service := domain.New(domain.Config{Repository: repository, Authorizer: authorization.New(associationPolicy(document), nil), Principals: podFixturePrincipals{}})
			t.Cleanup(func() { _ = service.Close() })
			model, _ := awscatalog.LookupService("eks")
			op, _ := model.Operation("CreatePodIdentityAssociation")
			input := &api.CreatePodIdentityAssociationRequest{ClusterName: new(api.String(key.Name)), Namespace: new(api.String("payments")), ServiceAccount: new(api.String("processor")), RoleArn: new(api.String("arn:aws:iam::111111111111:role/pod")), TargetRoleArn: new(api.String("arn:aws:iam::111111111111:role/target")), Tags: api.TagMap{"team": "payments"}}
			_, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
			if row.Allowed && rejected != nil {
				t.Fatal(rejected)
			}
			if !row.Allowed && (rejected == nil || rejected.StatusCode != 403) {
				t.Fatalf("unsupported condition granted association: %v", rejected)
			}
			if err := repository.View(ctx, func(tx domain.Reader) error {
				associations, err := tx.PodIdentityAssociations(key)
				if err != nil {
					return err
				}
				want := 0
				if row.Allowed {
					want = 1
				}
				if len(associations) != want {
					t.Fatalf("persisted associations = %d, want %d", len(associations), want)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The command admission test does not run workloads. Native reconciliation is
// exercised separately; the role/subnet owner supplies already-approved inputs.
type admittedFargateRole struct{}

func (admittedFargateRole) ValidateFargateExecutionRole(context.Context, string, string) (string, error) {
	return "AROAFARGATE", nil
}
func (admittedFargateRole) ValidateFargateSubnets(context.Context, domain.Key, string, []string) error {
	return nil
}

type unavailableFargateRuntime struct{ native.Runtime }

func (unavailableFargateRuntime) ReconcileFargate(context.Context, native.FargateSpecification) error {
	return errors.New("native capacity is unavailable in the admission fixture")
}

func TestFargateAdmissionLimits(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, row := range readAdmissionCases(t).Fargate {
			t.Run(backend+"/"+row.Name, func(t *testing.T) {
				var repository domain.Repository = domain.NewMemoryRepository(nil)
				if backend == "sqlite" {
					db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "admission.sqlite"))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := db.Close(); err != nil {
							t.Error(err)
						}
					})
					repository = eksdb.New(db)
				}
				key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "admission"}
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.AccountID})
				if err := repository.Update(ctx, func(tx domain.Transaction) error {
					if err := tx.PutCluster(domain.Cluster{Key: key, ID: "cluster-id", Status: "ACTIVE"}); err != nil {
						return err
					}
					for i := range row.Profiles {
						if err := tx.PutFargateProfile(domain.FargateProfile{Key: key, ID: fmt.Sprint(i), Name: fmt.Sprintf("existing-%d", i), Status: "ACTIVE"}); err != nil {
							return err
						}
					}
					foreign := key
					foreign.AccountID = "222222222222"
					if err := tx.PutCluster(domain.Cluster{Key: foreign, ID: "foreign-cluster-id", Status: "ACTIVE"}); err != nil {
						return err
					}
					return tx.PutFargateProfile(domain.FargateProfile{Key: foreign, ID: "foreign-id", Name: "foreign", Status: "ACTIVE"})
				}); err != nil {
					t.Fatal(err)
				}
				service := domain.New(domain.Config{Repository: repository, Runtime: unavailableFargateRuntime{}, WorkloadRoles: admittedFargateRole{}})
				// Admission owns quota transitions; this fixture has no native cluster.
				service.JobDriver().Close()
				t.Cleanup(func() { _ = service.Close() })
				labels := api.FargateProfileLabel{}
				for i := range row.Labels {
					labels[api.String(fmt.Sprintf("label%d", i))] = "value"
				}
				model, _ := awscatalog.LookupService("eks")
				op, _ := model.Operation("CreateFargateProfile")
				input := &api.CreateFargateProfileRequest{ClusterName: new(api.String(key.Name)), FargateProfileName: new(api.String("candidate")), PodExecutionRoleArn: new(api.String("arn:aws:iam::111111111111:role/fargate")), ClientRequestToken: new(api.String("stable-token")), Selectors: api.FargateProfileSelectors{{Namespace: new(api.String("payments")), Labels: labels}}}
				command := awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}
				output, rejected := service.ExecuteCommand(ctx, command)
				if row.Error != "" {
					if rejected == nil || rejected.Code != row.Error {
						t.Fatalf("rejection = %v, want %s", rejected, row.Error)
					}
				} else {
					if rejected != nil {
						t.Fatal(rejected)
					}
					replay, err := service.ExecuteCommand(ctx, command)
					if err != nil {
						t.Fatalf("replay at quota: %v", err)
					}
					if *replay.(*api.CreateFargateProfileResponse).FargateProfile.FargateProfileArn != *output.(*api.CreateFargateProfileResponse).FargateProfile.FargateProfileArn {
						t.Fatal("replay changed profile")
					}
					// Both competing admissions must observe the committed tenth profile.
					var wg sync.WaitGroup
					for i := range 2 {
						wg.Go(func() {
							next := *input
							next.FargateProfileName = new(api.String(fmt.Sprintf("competitor-%d", i)))
							next.ClientRequestToken = nil
							command := command
							command.Input = &next
							if _, err := service.ExecuteCommand(ctx, command); err == nil || err.Code != "ResourceLimitExceededException" {
								t.Errorf("concurrent admission = %v", err)
							}
						})
					}
					wg.Wait()
				}
				if err := repository.View(ctx, func(tx domain.Reader) error {
					profiles, err := tx.FargateProfiles(key)
					if err != nil {
						return err
					}
					want := row.Profiles
					if row.Error == "" {
						want++
					}
					if len(profiles) != want {
						t.Fatalf("profiles = %d, want %d", len(profiles), want)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
