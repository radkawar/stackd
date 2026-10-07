package integrations

import (
	"testing"

	"stackd/internal/services/cloudformation"
)

// Native UpdateEventBus accepts an empty ARN to remove a DLQ even though the
// pinned public request shape requires a nonempty ARN. Keep the public model
// validator unchanged and use the existing typed owner boundary for this reset.
// testdata/aws/eventbridge/bus_kms_control.json retains the native diagnostic.
func TestCFNEventBusOmittedDLQRemovesNativeConfiguration(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNEventPolicyFixture(t, backend)
			h := cfnEventBus{f.commands}
			initial := cloudformation.Properties{
				"Name": "declared-dlq", "Description": "with-dlq",
				"DeadLetterConfig": map[string]any{"Arn": "arn:aws:sqs:us-east-1:123456789012:failures"},
			}
			r := cfnWorkflowOwnerRequest("AWS::Events::EventBus", "Bus", initial)
			created, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			independent := cfnWorkflowOwnerRequest("AWS::Events::EventBusPolicy", "Policy", cloudformation.Properties{
				"EventBusName": r.PhysicalID, "StatementId": "independent", "Action": "events:PutEvents", "Principal": "111122223333",
			})
			if _, err := f.policy.Create(f.ctx, independent); err != nil {
				t.Fatal(err)
			}
			before := f.row(t, r.PhysicalID)
			if before.DeadLetterARN != initial["DeadLetterConfig"].(map[string]any)["Arn"] {
				t.Fatalf("native owner did not admit the declared DLQ: %+v", before)
			}
			f.reopen(t)
			h = cfnEventBus{f.commands}
			r.Previous = initial
			r.Properties = cloudformation.Properties{"Name": "declared-dlq", "Description": "without-dlq"}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			after := f.row(t, r.PhysicalID)
			if after.DeadLetterARN != "" || after.Description != "without-dlq" || after.Policy.Document != before.Policy.Document {
				t.Fatalf("declarative DLQ removal changed an independent policy or retained the queue: %+v", after)
			}
			if err := f.policy.creationOwned(f.ctx, independent, r.PhysicalID, "independent"); err != nil {
				t.Fatalf("unrelated configuration update discarded the native statement incarnation: %v", err)
			}
		})
	}
}
