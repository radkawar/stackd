package configservice_test

import (
	domain "stackd/storage/configservice"
	"testing"
)

func TestPrivateControlClaimsRoundtrip(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository) {
		owner := domain.CloudFormationOwnership{Owner: "stack-resource", Token: "admitted-incarnation"}
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutRecorder(domain.Recorder{Scope: testScope, Name: "recorder", CFNOwnership: owner, StartOnCreate: true}); err != nil {
				return err
			}
			if err := tx.PutChannel(domain.Channel{Scope: testScope, Name: "channel", CFNOwnership: owner}); err != nil {
				return err
			}
			if err := tx.PutRule(domain.Rule{Scope: testScope, Name: "rule", CFNOwnership: owner}); err != nil {
				return err
			}
			if err := tx.PutAggregator(domain.Aggregator{Scope: testScope, Name: "aggregate", CFNOwnership: owner}); err != nil {
				return err
			}
			return tx.PutAggregationAuthorization(domain.AggregationAuthorization{Scope: testScope, AccountID: "222222222222", Region: "us-west-2", CFNOwnership: owner})
		}))
		check(t, repo.View(t.Context(), func(r domain.Reader) error {
			recorder, present, err := r.Recorder(testScope)
			if err != nil {
				return err
			}
			if !present || recorder.CFNOwnership != owner || !recorder.StartOnCreate {
				t.Fatalf("recorder private intent/claim: %#v", recorder)
			}
			channel, present, err := r.Channel(testScope)
			if err != nil {
				return err
			}
			if !present || channel.CFNOwnership != owner {
				t.Fatalf("channel claim: %#v", channel)
			}
			rules, err := r.Rules(testScope)
			if err != nil {
				return err
			}
			if len(rules) != 1 || rules[0].CFNOwnership != owner {
				t.Fatalf("rule claims: %#v", rules)
			}
			aggregators, err := r.Aggregators(testScope)
			if err != nil {
				return err
			}
			if len(aggregators) != 1 || aggregators[0].CFNOwnership != owner {
				t.Fatalf("aggregator claims: %#v", aggregators)
			}
			authorizations, err := r.AggregationAuthorizations(testScope)
			if err != nil {
				return err
			}
			if len(authorizations) != 1 || authorizations[0].CFNOwnership != owner {
				t.Fatalf("authorization claims: %#v", authorizations)
			}
			return nil
		}))
	})
}
