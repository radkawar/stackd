package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"stackd/clock"
	"stackd/internal/scheduler"
	"stackd/internal/services/eventbridge"
	"stackd/storage/memory"
)

type policyEventPublisher struct {
	publisher eventbridge.ServicePublisher
	ids       []string
	reject    error
}

func (p *policyEventPublisher) PublishEvent(ctx context.Context, e Event) error {
	p.ids = append(p.ids, e.ID)
	err := p.publisher.PublishEvent(ctx, eventbridge.EventRecord{ID: e.ID, Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: e.Scope.Partition, Account: e.Scope.AccountID, Region: e.Scope.Region}, Name: "default"}, Source: "aws.ssm", DetailType: e.DetailType, Detail: string(e.Detail), Resources: e.Resources, Time: e.At, Account: e.Scope.AccountID})
	if err != nil {
		return err
	}
	return p.reject
}

func TestPolicyDeadlinesAtomicAndOnce(t *testing.T) {
	schema := publishedPolicyDetailSchema(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	c := clock.NewManual(now)
	domain := memory.NewDomain()
	repo := NewMemoryRepository(domain)
	bus := eventbridge.NewMemoryRepository(domain)
	publisher := &policyEventPublisher{publisher: eventbridge.ServicePublisher{Repository: bus, Clock: c}}
	s := &Service{repository: repo, clock: c, events: publisher}
	key := ParameterKey{Scope: Scope{"aws", "123456789012", "us-east-1"}, Name: "/expiry"}
	policies, err := parsePolicies(`[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2026-09-01T02:00:00Z"}},{"Type":"ExpirationNotification","Version":"1.0","Attributes":{"Before":"1","Unit":"Hours"}},{"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"1","Unit":"Hours"}}]`, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if err := tx.PutParameter(ParameterRecord{Key: key, ARN: parameterARN(key), Type: "String", Tier: "Advanced", CurrentVersion: 1, Policies: policies}); err != nil {
			return err
		}
		return tx.PutVersion(VersionRecord{Key: VersionKey{key, 1}, Value: []byte("before"), Modified: now, Policies: policies})
	}); err != nil {
		t.Fatal(err)
	}
	driver := scheduler.New(c, policyJobs{s})
	defer driver.Close()
	if result, err := driver.RunDue(ctx, 10); err != nil || result.Processed != 0 || result.Next == nil || !result.Next.Equal(now.Add(time.Hour)) {
		t.Fatalf("before deadline: %#v %v", result, err)
	}
	if err := c.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	publisher.reject = errors.New("reject enclosing transaction after EventBridge admission")
	if _, err := driver.RunDue(ctx, 10); !errors.Is(err, publisher.reject) {
		t.Fatalf("publication rejection = %v", err)
	}
	failedID := publisher.ids[0]
	if err := bus.View(ctx, func(r eventbridge.Reader) error {
		_, err := r.Event(failedID)
		if !errors.Is(err, eventbridge.ErrNotFound) {
			t.Fatalf("rolled back event: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(ctx, func(r Reader) error {
		p, err := r.Parameter(key)
		if err != nil {
			return err
		}
		for _, policy := range p.Policies {
			if policy.Fired {
				t.Fatal("policy acknowledged despite rollback")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	publisher.reject, publisher.ids = nil, nil
	if result, err := driver.RunDue(ctx, 10); err != nil || result.Processed != 2 {
		t.Fatalf("notification drain: %#v %v", result, err)
	}
	kinds := make(map[string]bool)
	for _, id := range publisher.ids {
		if err := bus.View(ctx, func(r eventbridge.Reader) error {
			event, err := r.Event(id)
			if err != nil {
				return err
			}
			detail := assertPublishedPolicyEvent(t, schema, event, key.Name, policies)
			kinds[detail["policy-type"]] = true
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if !kinds["ExpirationNotification"] || !kinds["NoChangeNotification"] {
		t.Fatalf("notification types = %v", kinds)
	}
	// A reconstructed driver must not redeliver acknowledged policy deadlines.
	recovered := scheduler.New(c, policyJobs{&Service{repository: repo, clock: c, events: publisher}})
	defer recovered.Close()
	if result, err := recovered.RunDue(ctx, 10); err != nil || result.Processed != 0 {
		t.Fatalf("recovered notification drain: %#v %v", result, err)
	}
	if err := c.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	if result, err := recovered.RunDue(ctx, 10); err != nil || result.Processed != 1 {
		t.Fatalf("expiration drain: %#v %v", result, err)
	}
	if err := bus.View(ctx, func(r eventbridge.Reader) error {
		event, err := r.Event(publisher.ids[len(publisher.ids)-1])
		if err != nil {
			return err
		}
		detail := assertPublishedPolicyEvent(t, schema, event, key.Name, policies)
		if detail["policy-type"] != "Expiration" {
			t.Fatalf("expiration event = %#v", event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(ctx, func(r Reader) error {
		_, err := r.Parameter(key)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired parameter: %v", err)
		}
		versions, err := r.Versions(key)
		if err != nil {
			return err
		}
		if len(versions) != 0 {
			t.Fatalf("expiration retained versions: %v", versions)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyUpdateFencesSelectedDeadline(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	c := clock.NewManual(now)
	repo := NewMemoryRepository(nil)
	s := &Service{repository: repo, clock: c}
	key := ParameterKey{Scope: Scope{"aws", "123456789012", "us-east-1"}, Name: "/rotate"}
	policies, err := parsePolicies(`[{"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"1","Unit":"Hours"}}]`, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, func(tx Transaction) error {
		return tx.PutParameter(ParameterRecord{Key: key, CurrentVersion: 1, Policies: policies})
	}); err != nil {
		t.Fatal(err)
	}
	source := policyJobs{s}
	selected, found, err := source.Next(ctx)
	if err != nil || !found {
		t.Fatalf("selection: %v %v", found, err)
	}
	if err := c.Advance(30 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, func(tx Transaction) error {
		p, err := tx.Parameter(key)
		if err != nil {
			return err
		}
		p.CurrentVersion++
		p.Policies, err = refreshPolicies(p.Policies, c.Now())
		if err != nil {
			return err
		}
		return tx.PutParameter(p)
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Advance(30 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := source.Run(ctx, selected); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(ctx, func(r Reader) error {
		p, err := r.Parameter(key)
		if err != nil {
			return err
		}
		if p.Policies[0].Fired || !p.Policies[0].Due.Equal(now.Add(90*time.Minute)) {
			t.Fatalf("replacement policy = %#v", p.Policies[0])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The native registry fixture contains AWS's published schema, not an observed
// notification. Validate actual admitted events against that independent contract.
func publishedPolicyDetailSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/ssm/policy_event_schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Result struct {
			Output struct {
				Content string
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]any
		}
	}
	if err := json.Unmarshal([]byte(fixture.Result.Output.Content), &document); err != nil {
		t.Fatal(err)
	}
	const location = "urn:stackd:test:ssm:policy-action"
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(location, document.Components.Schemas["ParameterStorePolicyActionDetail"]); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(location)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func assertPublishedPolicyEvent(t *testing.T, schema *jsonschema.Schema, event eventbridge.EventRecord, name string, policies []ParameterPolicy) map[string]string {
	t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(event.Detail), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("admitted policy event violates published AWS schema: %v", err)
	}
	var detail map[string]string
	if err := json.Unmarshal([]byte(event.Detail), &detail); err != nil {
		t.Fatal(err)
	}
	if event.DetailType != "Parameter Store Policy Action" || detail["parameter-name"] != name || detail["parameter-type"] != "String" || detail["action-status"] != "SUCCESS" {
		t.Fatalf("policy action identity or outcome = %#v", event)
	}
	var content policyDocument
	if err := json.Unmarshal([]byte(detail["policy-content"]), &content); err != nil {
		t.Fatalf("policy-content is not a JSON policy string: %v", err)
	}
	for _, policy := range policies {
		if policy.Type != detail["policy-type"] {
			continue
		}
		if content.Type != policy.Type || content.Version != policy.Version || !maps.Equal(content.Attributes, policy.Attributes) {
			t.Fatalf("policy event lost triggered policy content: %#v", content)
		}
		return detail
	}
	t.Fatalf("policy event names an unconfigured policy: %s", detail["policy-type"])
	return nil
}
