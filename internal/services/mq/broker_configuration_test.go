package mq

import (
	"errors"
	api "stackd/internal/awsapi/mq"
	"testing"
)

func automaticConfigurationInput() *api.CreateBrokerInput {
	in := &api.CreateBrokerInput{}
	text(&in.BrokerName, "automatic-configuration")
	text(&in.CreatorRequestId, "automatic-create-token")
	text(&in.EngineType, "ACTIVEMQ")
	text(&in.DeploymentMode, "SINGLE_INSTANCE")
	text(&in.HostInstanceType, "mq.t3.micro")
	boolean(&in.PubliclyAccessible, true)
	u := api.User{}
	text(&u.Username, "writer")
	text(&u.Password, "writer-password-123")
	in.Users = []api.User{u}
	return in
}

func TestAutomaticConfigurationOwnershipAndReplay(t *testing.T) {
	s, ctx, v := controlFixture(t)
	in := automaticConfigurationInput()
	create := func() string {
		t.Helper()
		var id string
		if err := s.repository.Attempt(ctx, func(tx Transaction) error {
			out, err := s.createBroker(tx.Context(), tx, in)
			if err == nil {
				id = value(out.BrokerId)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	v.ID = create()
	broker := storedBroker(t, s, v)
	if broker.Configuration.ID == "" {
		t.Fatal("automatic configuration is not retained")
	}
	var initial ConfigurationRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		initial, err = r.Configuration(v.Scope, broker.Configuration.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if initial.Scope != v.Scope || initial.Engine != broker.Engine || initial.EngineVersion != broker.EngineVersion || broker.Configuration.Revision != 1 || broker.Configuration.Data != initial.Revisions[0].Data {
		t.Fatalf("broker does not own the scoped immutable initial revision: %+v", broker.Configuration)
	}
	// Retry after the default resource has a new latest revision: the create must
	// retain its original identity and association, not mint another configuration.
	initial.Revisions = append(initial.Revisions, ConfigurationRevisionRecord{Revision: 2, Data: `<broker xmlns="http://activemq.apache.org/schema/core" advisorySupport="false"/>`, Created: s.clock.Now()})
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutConfiguration(initial) }); err != nil {
		t.Fatal(err)
	}
	if got := create(); got != v.ID {
		t.Fatalf("replay created broker %q instead of %q", got, v.ID)
	}
	if got := storedBroker(t, s, v).Configuration; got != broker.Configuration {
		t.Fatalf("replay changed initial configuration: %+v", got)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.AllConfigurations()
		if err == nil && (len(rows) != 1 || rows[0].ID != initial.ID) {
			t.Fatalf("replay leaked automatic configurations: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	in.CreatorRequestId = nil
	if err := s.repository.Attempt(ctx, func(tx Transaction) error { _, err := s.createBroker(tx.Context(), tx, in); return err }); err == nil {
		t.Fatal("duplicate broker name accepted")
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.AllConfigurations()
		if err == nil && len(rows) != 1 {
			t.Fatal("name conflict leaked automatic configuration")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type failingAutomaticBrokerWrite struct {
	Transaction
	failure error
}

func (t failingAutomaticBrokerWrite) PutBroker(BrokerRecord) error { return t.failure }

func TestAutomaticConfigurationRollsBackWithBroker(t *testing.T) {
	s, ctx, _ := controlFixture(t)
	failed := errors.New("broker write failed")
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.createBroker(tx.Context(), failingAutomaticBrokerWrite{Transaction: tx, failure: failed}, automaticConfigurationInput())
		return err
	})
	if !errors.Is(err, failed) {
		t.Fatalf("write failure lost: %v", err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.AllConfigurations()
		if err == nil && len(rows) != 0 {
			t.Fatalf("failed admission committed orphan configurations: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
