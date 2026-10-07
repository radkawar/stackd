package integrations

import (
	"slices"
	"testing"

	api "stackd/internal/awsapi/ram"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ram"
)

// The real RAM owner records edge ownership; nothing here is mocked.
func TestCloudFormationRAMShareUpdatePreservesSeparatelyOwnedAssociations(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111", TransportKnown: true, SecureTransport: true, SourceIP: "192.0.2.10"})
	service := ram.New(ram.Config{})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ram": service})
	share := cfnRAMResourceShare{commands}
	principal := cfnRAMPrincipalAssociation{commands}
	live := func(arn string) []string {
		t.Helper()
		edges, err := share.edges(ctx, arn, "PRINCIPAL")
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(edges)
		return edges
	}
	inline := func(principals ...any) cloudformation.Properties {
		return cloudformation.Properties{"Name": "renamed", "Principals": principals, "Tags": []any{map[string]any{"Key": "team", "Value": "two"}}}
	}

	created := cloudformation.Properties{"Name": "original", "Principals": []any{"222222222222"}, "Tags": []any{map[string]any{"Key": "team", "Value": "one"}}}
	r := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Share", Token: "share-incarnation", Properties: created}
	result, err := share.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = result.PhysicalID
	separate := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Extra", Token: "association-incarnation", Properties: cloudformation.Properties{"ResourceShareArn": r.PhysicalID, "Principal": "333333333333"}}
	association, err := principal.Create(ctx, separate)
	if err != nil {
		t.Fatal(err)
	}
	separate.PhysicalID = association.PhysicalID

	// A Name/Tags-only update leaves the separately owned edge in place.
	r.Previous, r.Properties = created, inline("222222222222")
	if _, err = share.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := live(r.PhysicalID); !slices.Equal(got, []string{"222222222222", "333333333333"}) {
		t.Fatalf("share update removed a separately owned association: %v", got)
	}
	model, err := share.Read(ctx, r)
	if err != nil || model["Name"] != "renamed" || !slices.Equal(model["Principals"].([]any), []any{"222222222222"}) {
		t.Fatalf("share model mixed in a separately owned edge: %#v %v", model, err)
	}
	if tags := model["Tags"].([]any); len(tags) != 1 || tags[0].(map[string]any)["Value"] != "two" {
		t.Fatalf("share tags did not converge: %#v", tags)
	}

	// Adding and rolling back an inline edge converges without touching the other owner.
	added := inline("222222222222", "444444444444")
	r.Previous, r.Properties = r.Properties, added
	if _, err = share.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Previous, r.Properties = added, inline("222222222222")
	if _, err = share.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := live(r.PhysicalID); !slices.Equal(got, []string{"222222222222", "333333333333"}) {
		t.Fatalf("rollback did not converge to owned edges only: %v", got)
	}

	// The share cannot claim the other owner's edge, nor can another incarnation act for the share.
	r.Previous, r.Properties = r.Properties, inline("222222222222", "333333333333")
	if _, err = share.Update(ctx, r); err == nil {
		t.Fatal("share inline list adopted a separately owned association")
	}
	other := r
	other.Token, other.Properties = "replacement-incarnation", inline("444444444444")
	if _, err = share.Update(ctx, other); err == nil {
		t.Fatal("another share incarnation reconciled this share's edges")
	}
	if got := live(r.PhysicalID); !slices.Equal(got, []string{"222222222222", "333333333333"}) {
		t.Fatalf("rejected updates changed edges: %v", got)
	}
	// Public tags are not authority: forging stackd markers grants nothing.
	if _, rejected := cfnOrgIdentityCall[api.TagResourceResponse](ctx, commands, "ram", "TagResource", map[string]any{"resourceArn": r.PhysicalID, "tags": []map[string]string{{"key": cfnComputeTagPrefix + "incarnation", "value": other.Token}}}); rejected != nil {
		t.Fatal(rejected)
	}
	if err = share.Delete(ctx, other); err == nil {
		t.Fatal("forged ownership tag authorized deletion")
	}

	// The separate owner still holds its exact claim and can remove its own edge.
	if err = principal.Delete(ctx, separate); err != nil {
		t.Fatal(err)
	}
	if got := live(r.PhysicalID); !slices.Equal(got, []string{"222222222222"}) {
		t.Fatalf("separate association delete did not converge: %v", got)
	}
	if err = share.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = share.get(ctx, r.PhysicalID); !cfnRAMMissing(err) {
		t.Fatalf("owned share survived deletion: %v", err)
	}
}
