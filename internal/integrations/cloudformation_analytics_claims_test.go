package integrations

import (
	"errors"
	"testing"

	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/services/athena"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/glue"
)

// Public markers copied from a published request token are customer tags only.
func cfnAnalyticsCounterfeitMarkers(r cloudformation.ResourceRequest) map[string]string {
	return map[string]string{cfnComputeTagPrefix + "stack-id": r.StackID, cfnComputeTagPrefix + "logical-id": r.LogicalID, cfnComputeTagPrefix + "incarnation": r.Token}
}

func cfnAnalyticsModeledAbsent(err error) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && wire.Code == "ResourceNotFoundException"
}

type cfnAnalyticsClaimCase struct {
	kind, service, physicalID string
	properties                cloudformation.Properties
	setup                     func(t *testing.T, commands StepFunctionsCommands)
	createOp, deleteOp        string
	create                    func(markers map[string]string) map[string]any
	delete                    map[string]any
	// Registry and schema deletion is asynchronous, so their foreign row is pre-existing only.
	recreate bool
}

func cfnAnalyticsClaimCases() []cfnAnalyticsClaimCase {
	const account = "123456789012"
	jdbc := func() map[string]any {
		return map[string]any{"Name": "claimed-connection", "ConnectionType": "JDBC", "ConnectionProperties": map[string]any{"JDBC_CONNECTION_URL": "jdbc:postgresql://localhost/catalog", "USERNAME": "reader", "PASSWORD": "claimed-secret"}}
	}
	job := func() map[string]any {
		return map[string]any{"Name": "pythonshell", "PythonVersion": "3", "ScriptLocation": "s3://owned/job.py"}
	}
	definition := `{"type":"record","name":"Claimed","fields":[{"name":"id","type":"int"}]}`
	return []cfnAnalyticsClaimCase{
		{kind: "AWS::Glue::Workflow", service: "glue", physicalID: "claimed-workflow", recreate: true,
			properties: cloudformation.Properties{"Name": "claimed-workflow"},
			createOp:   "CreateWorkflow", create: func(m map[string]string) map[string]any { return map[string]any{"Name": "claimed-workflow", "Tags": m} },
			deleteOp: "DeleteWorkflow", delete: map[string]any{"Name": "claimed-workflow"}},
		{kind: "AWS::Glue::Trigger", service: "glue", physicalID: "claimed-trigger", recreate: true,
			properties: cloudformation.Properties{"Name": "claimed-trigger", "Type": "ON_DEMAND", "Actions": []any{map[string]any{"JobName": "absent-job"}}},
			createOp:   "CreateTrigger", create: func(m map[string]string) map[string]any {
				return map[string]any{"Name": "claimed-trigger", "Type": "ON_DEMAND", "Actions": []any{map[string]any{"JobName": "absent-job"}}, "Tags": m}
			},
			deleteOp: "DeleteTrigger", delete: map[string]any{"Name": "claimed-trigger"}},
		{kind: "AWS::Glue::Job", service: "glue", physicalID: "claimed-job", recreate: true,
			properties: cloudformation.Properties{"Name": "claimed-job", "Role": "arn:aws:iam::123456789012:role/job", "Command": job(), "MaxCapacity": 0.0625},
			createOp:   "CreateJob", create: func(m map[string]string) map[string]any {
				return map[string]any{"Name": "claimed-job", "Role": "arn:aws:iam::123456789012:role/job", "Command": job(), "MaxCapacity": 0.0625, "Tags": m}
			},
			deleteOp: "DeleteJob", delete: map[string]any{"JobName": "claimed-job"}},
		{kind: "AWS::Glue::Connection", service: "glue", physicalID: account + "|claimed-connection", recreate: true,
			properties: cloudformation.Properties{"CatalogId": account, "ConnectionInput": jdbc()},
			createOp:   "CreateConnection", create: func(m map[string]string) map[string]any {
				return map[string]any{"CatalogId": account, "ConnectionInput": jdbc(), "Tags": m}
			},
			deleteOp: "DeleteConnection", delete: map[string]any{"CatalogId": account, "ConnectionName": "claimed-connection"}},
		{kind: "AWS::Glue::Database", service: "glue", physicalID: "claimed_db", recreate: true,
			properties: cloudformation.Properties{"CatalogId": account, "DatabaseInput": map[string]any{"Name": "claimed_db"}},
			createOp:   "CreateDatabase", create: func(m map[string]string) map[string]any {
				return map[string]any{"CatalogId": account, "DatabaseInput": map[string]any{"Name": "claimed_db"}, "Tags": m}
			},
			deleteOp: "DeleteDatabase", delete: map[string]any{"CatalogId": account, "Name": "claimed_db"}},
		{kind: "AWS::Glue::Catalog", service: "glue", physicalID: "arn:aws:glue:us-east-1:123456789012:catalog/claimed-catalog", recreate: true,
			properties: cloudformation.Properties{"Name": "claimed-catalog"},
			createOp:   "CreateCatalog", create: func(m map[string]string) map[string]any {
				return map[string]any{"Name": "claimed-catalog", "CatalogInput": map[string]any{}, "Tags": m}
			},
			deleteOp: "DeleteCatalog", delete: map[string]any{"CatalogId": account + ":claimed-catalog"}},
		{kind: "AWS::Glue::Registry", service: "glue", physicalID: "arn:aws:glue:us-east-1:123456789012:registry/claimed-registry",
			properties: cloudformation.Properties{"Name": "claimed-registry"},
			createOp:   "CreateRegistry", create: func(m map[string]string) map[string]any {
				return map[string]any{"RegistryName": "claimed-registry", "Tags": m}
			}},
		{kind: "AWS::Glue::Schema", service: "glue", physicalID: "arn:aws:glue:us-east-1:123456789012:schema/schema-registry/claimed-schema",
			properties: cloudformation.Properties{"Name": "claimed-schema", "Registry": map[string]any{"Name": "schema-registry"}, "DataFormat": "AVRO", "Compatibility": "NONE", "SchemaDefinition": definition},
			setup: func(t *testing.T, commands StepFunctionsCommands) {
				t.Helper()
				if err := cfnComputeRun(cfnAnalyticsTestContext(), commands, "glue", "CreateRegistry", map[string]any{"RegistryName": "schema-registry"}); err != nil {
					t.Fatal(err)
				}
			},
			createOp: "CreateSchema", create: func(m map[string]string) map[string]any {
				return map[string]any{"RegistryId": map[string]any{"RegistryName": "schema-registry"}, "SchemaName": "claimed-schema", "DataFormat": "AVRO", "Compatibility": "NONE", "SchemaDefinition": definition, "Tags": m}
			}},
		{kind: "AWS::Athena::WorkGroup", service: "athena", physicalID: "claimed-group", recreate: true,
			properties: cloudformation.Properties{"Name": "claimed-group"},
			createOp:   "CreateWorkGroup", create: func(m map[string]string) map[string]any {
				return map[string]any{"Name": "claimed-group", "Tags": cfnComputeTagList(m)}
			},
			deleteOp: "DeleteWorkGroup", delete: map[string]any{"WorkGroup": "claimed-group", "RecursiveDeleteOption": true}},
		{kind: "AWS::Athena::DataCatalog", service: "athena", physicalID: "claimed-catalog", recreate: true,
			properties: cloudformation.Properties{"Name": "claimed-catalog", "Type": "GLUE", "Parameters": map[string]any{"catalog-id": account}},
			createOp:   "CreateDataCatalog", create: func(m map[string]string) map[string]any {
				return map[string]any{"Name": "claimed-catalog", "Type": "GLUE", "Parameters": map[string]any{"catalog-id": account}, "Tags": cfnComputeTagList(m)}
			},
			deleteOp: "DeleteDataCatalog", delete: map[string]any{"Name": "claimed-catalog"}},
	}
}

// These regressions enter the real Glue/Athena command owners. Public stackd
// markers copied from a request are never adopted; only the exact incarnation's
// private native claim recovers, mutates or deletes the resource.
func TestAnalyticsTaggedOwnersRequirePrivateClaims(t *testing.T) {
	ctx := cfnAnalyticsTestContext()
	glueOwner := glue.New(glue.Config{})
	athenaOwner := athena.New(athena.Config{})
	t.Cleanup(func() { _ = glueOwner.Close(); _ = athenaOwner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"glue": glueOwner, "athena": athenaOwner})
	handlers := CloudFormationAnalyticsHandlers(commands)
	for _, c := range cfnAnalyticsClaimCases() {
		t.Run(c.kind, func(t *testing.T) {
			h := handlers[c.kind]
			reader := h.(cloudformation.ResourceReader)
			recoverer, ok := h.(cloudformation.ResourceCreationRecoverer)
			if !ok {
				t.Fatalf("%s does not recover exact creation incarnations", c.kind)
			}
			native := func(operation string, input map[string]any) {
				t.Helper()
				if err := cfnComputeRun(ctx, commands, c.service, operation, input); err != nil {
					t.Fatalf("native %s: %v", operation, err)
				}
			}
			r := cfnAnalyticsTestRequest(c.kind, c.properties)
			r.LogicalID = "Claimed"
			owned := r
			owned.PhysicalID = c.physicalID
			direct := owned
			direct.CloudControl = true
			direct.Properties = nil
			markers := cfnAnalyticsCounterfeitMarkers(r)
			if c.setup != nil {
				c.setup(t, commands)
			}

			// A pre-existing native resource carrying this request's markers is not adoptable.
			native(c.createOp, c.create(markers))
			if got, err := h.Create(ctx, r); err == nil || got.PhysicalID != "" {
				t.Fatalf("counterfeit markers adopted a native resource: %v, %v", got, err)
			}
			if got, err := recoverer.RecoverCreation(ctx, r); err == nil || got.PhysicalID != "" || cfnAnalyticsModeledAbsent(err) {
				t.Fatalf("counterfeit markers recovered or certified absence: %v, %v", got, err)
			}
			if _, err := reader.Read(ctx, owned); err == nil {
				t.Fatal("counterfeit markers authorized an exact-incarnation observation")
			}
			if err := h.Delete(ctx, owned); err == nil {
				t.Fatal("counterfeit markers authorized deletion")
			}
			if _, err := reader.Read(ctx, direct); err != nil {
				t.Fatalf("native resource did not survive the rejected deletion: %v", err)
			}
			if !c.recreate {
				return
			}
			native(c.deleteOp, c.delete)

			// The exact incarnation claims privately and recovers with its own token.
			created, err := h.Create(ctx, r)
			if err != nil || created.PhysicalID != c.physicalID {
				t.Fatalf("create: %v, %v", created, err)
			}
			if replay, err := h.Create(ctx, owned); err != nil || replay.PhysicalID != c.physicalID {
				t.Fatalf("same-token replay: %v, %v", replay, err)
			}
			if recovered, err := recoverer.RecoverCreation(ctx, r); err != nil || recovered.PhysicalID != c.physicalID {
				t.Fatalf("same-token recovery: %v, %v", recovered, err)
			}
			if p, err := reader.Read(ctx, owned); err != nil {
				t.Fatalf("exact-incarnation read: %v", err)
			} else if tags, ok := p["Tags"].(map[string]string); ok && len(tags) != 0 {
				t.Fatalf("read exposed ownership tags: %v", tags)
			}
			foreign := owned
			foreign.Token = "foreign-incarnation"
			if _, err := reader.Read(ctx, foreign); err == nil {
				t.Fatal("foreign incarnation observed the private claim")
			}

			// A same-name native recreation with copied markers is a different incarnation.
			native(c.deleteOp, c.delete)
			native(c.createOp, c.create(markers))
			if _, err := reader.Read(ctx, owned); err == nil {
				t.Fatal("recreated resource was observed as the original incarnation")
			}
			update := owned
			update.Previous = owned.Properties
			if _, err := h.Update(ctx, update); err == nil {
				t.Fatal("recreated resource was mutated by the original incarnation")
			}
			if got, err := recoverer.RecoverCreation(ctx, r); err == nil || got.PhysicalID != "" || cfnAnalyticsModeledAbsent(err) {
				t.Fatalf("recreated resource was recovered or certified absent: %v, %v", got, err)
			}
			if err := h.Delete(ctx, owned); err == nil {
				t.Fatal("recreated resource was deleted by the original incarnation")
			}
			if _, err := reader.Read(ctx, direct); err != nil {
				t.Fatalf("recreated native resource did not survive: %v", err)
			}

			// Without an admitted row, recovery certifies absence and never creates.
			native(c.deleteOp, c.delete)
			if got, err := recoverer.RecoverCreation(ctx, r); !cfnAnalyticsModeledAbsent(err) || got.PhysicalID != "" {
				t.Fatalf("recovery without an admitted row: %v, %v", got, err)
			}
			if _, err := reader.Read(ctx, direct); !cfnAnalyticsMissing(err) {
				t.Fatalf("recovery admitted a new native resource: %v", err)
			}
		})
	}
}
