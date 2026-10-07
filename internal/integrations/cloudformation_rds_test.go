package integrations

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/rds"
)

// These tests execute the real RDS parameter owner. No command executor or
// service response is mocked: parameter coercion, reset, recovery and ownership
// are observed through that owner's repository and public read commands.
func TestRelationalParameterPublicationRecoveryAndCloudControl(t *testing.T) {
	for _, cluster := range []bool{false, true} {
		t.Run(fmt.Sprint("cluster=", cluster), func(t *testing.T) {
			repository := rds.NewMemoryRepository(nil)
			service := rds.New(rds.Config{Repository: repository})
			t.Cleanup(func() { _ = service.Close() })
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"rds": service})
			var handler cloudformation.ResourceHandler = cfnRDSParameterGroup{commands}
			nameProperty, kind, family := "DBParameterGroupName", "pg", "postgres17"
			if cluster {
				handler = cfnRDSClusterParameterGroup{commands}
				nameProperty, kind, family = "DBClusterParameterGroupName", "cluster-pg", "aurora-postgresql17"
			}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
			tags := make([]any, 50)
			for i := range tags {
				tags[i] = map[string]any{"Key": fmt.Sprintf("customer-%02d", i), "Value": "owned"}
			}
			before := cloudformation.Properties{nameProperty: "parameter-owner", "Family": family, "Description": "real publication", "Parameters": map[string]any{"max_connections": float64(150), "statement_timeout": "1000"}, "Tags": tags}
			r := cloudformation.ResourceRequest{StackID: "stack-one", StackName: "stack", LogicalID: "Parameters", Token: "incarnation-one", Properties: before}
			result, err := handler.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if result.Ref != "parameter-owner" {
				t.Fatalf("unexpected Ref %q", result.Ref)
			}
			if recovered, err := handler.Create(ctx, r); err != nil || recovered.PhysicalID != result.PhysicalID {
				t.Fatalf("create recovery = %#v, %v", recovered, err)
			}
			r.PhysicalID = result.PhysicalID
			if ready, err := handler.(cloudformation.ResourceStabilizer).Stabilize(ctx, r); err != nil || !ready {
				t.Fatalf("publication readiness = %v, %v", ready, err)
			}
			key := rds.Key{Scope: rds.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: kind, Name: result.PhysicalID}
			if err := repository.View(ctx, func(reader rds.Reader) error {
				group, err := reader.ParameterGroup(key)
				if err != nil {
					return err
				}
				if group.Parameters["max_connections"] != "150" || group.ApplyMethods["max_connections"] != "pending-reboot" || group.ApplyMethods["statement_timeout"] != "immediate" {
					t.Fatalf("wrong engine application contracts: %#v", group)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			other := r
			other.Token = "incarnation-two"
			if _, err := handler.Create(ctx, other); err == nil {
				t.Fatal("a new incarnation adopted an unrelated live group")
			}
			if err := handler.Delete(ctx, other); err == nil {
				t.Fatal("an unrelated incarnation deleted the live group")
			}
			reader := handler.(cloudformation.ResourceReader)
			model, err := reader.Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if public, ok := model["Tags"].([]any); !ok || len(public) != 50 {
				t.Fatalf("ownership tags consumed or leaked into customer tags: %#v", model["Tags"])
			}
			after := cloudformation.Properties{nameProperty: "parameter-owner", "Family": family, "Description": "real publication", "Parameters": map[string]any{"max_connections": float64(200)}}
			r.Previous, r.Properties, r.CloudControl = before, after, true
			if _, err := handler.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := repository.View(ctx, func(reader rds.Reader) error {
				group, err := reader.ParameterGroup(key)
				if err != nil {
					return err
				}
				if len(group.Parameters) != 1 || group.Parameters["max_connections"] != "200" {
					t.Fatalf("removed parameter was not reset: %#v", group.Parameters)
				}
				if len(group.Tags) != 0 || group.Owner != (rds.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}) {
					t.Fatalf("Cloud Control changed private native ownership: %#v", group)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Recreate the service around the actual owner repository, not a CFN
			// retained model, and roll the publication back to the old template.
			restarted := rds.New(rds.Config{Repository: repository})
			t.Cleanup(func() { _ = restarted.Close() })
			restartedCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"rds": restarted})
			if cluster {
				handler = cfnRDSClusterParameterGroup{restartedCommands}
			} else {
				handler = cfnRDSParameterGroup{restartedCommands}
			}
			r.Previous, r.Properties, r.CloudControl = after, before, false
			if _, err := handler.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			model, err = handler.(cloudformation.ResourceReader).Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			parameters := model["Parameters"].(map[string]any)
			if parameters["max_connections"] != "150" || parameters["statement_timeout"] != "1000" {
				t.Fatalf("rollback did not restore actual owner values: %#v", parameters)
			}
			if err := handler.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := handler.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := handler.(cloudformation.ResourceReader).Read(ctx, r); !cfnRDSMissing(err) {
				t.Fatalf("deleted group still visible: %v", err)
			}
		})
	}
}

func TestRelationalRestoreHintReplacementSemantics(t *testing.T) {
	instance := cfnRDSInstance{}
	before := cloudformation.Properties{"DBInstanceClass": "db.t3.micro", "Engine": "postgres", "DBSnapshotIdentifier": "initial-backup"}
	after := cloudformation.Properties{"DBInstanceClass": "db.t3.micro", "Engine": "postgres"}
	if replace, err := instance.Replacement(before, after); err != nil || replace {
		t.Fatalf("removing instance restore hint must preserve the database: %v, %v", replace, err)
	}
	after["DBSnapshotIdentifier"] = "different-backup"
	if replace, err := instance.Replacement(before, after); err != nil || !replace {
		t.Fatalf("changing instance restore source must replace: %v, %v", replace, err)
	}
	clusterBefore := cloudformation.Properties{"Engine": "aurora-postgresql", "SnapshotIdentifier": "initial-backup"}
	clusterAfter := cloudformation.Properties{"Engine": "aurora-postgresql"}
	if replace, err := (cfnRDSCluster{}).Replacement(clusterBefore, clusterAfter); err != nil || !replace {
		t.Fatalf("removing cluster restore hint must replace: %v, %v", replace, err)
	}
	restored := cloudformation.Properties{"SnapshotIdentifier": "initial-backup", "MasterUserPassword": "rotated-password"}
	if err := (cfnRDSCluster{}).Validate(restored); err != nil {
		t.Fatalf("restored RDS cluster cannot rotate its password: %v", err)
	}
	if err := (cfnDocDBCluster{}).Validate(restored); err != nil {
		t.Fatalf("restored DocumentDB cluster cannot rotate its password: %v", err)
	}
}

func TestRelationalNamesRemainValidAcrossRecovery(t *testing.T) {
	r := cloudformation.ResourceRequest{StackID: "stack", StackName: "123--STACK--", LogicalID: "--Parameters", Token: "one", Properties: cloudformation.Properties{}}
	name := cfnRDSName(r, "DBInstanceIdentifier", 63)
	if len(name) > 63 || name[0] < 'a' || name[0] > 'z' {
		t.Fatalf("generated invalid RDS identity %q", name)
	}
	for i := 1; i < len(name); i++ {
		if name[i] == '-' && name[i-1] == '-' {
			t.Fatalf("generated double hyphen in %q", name)
		}
	}
	r.PhysicalID = name
	if recovered := cfnRDSName(r, "DBInstanceIdentifier", 63); recovered != name {
		t.Fatalf("recovery renamed resource to %q", recovered)
	}
}

// Engine-backed edits use the same explicit native Docker prerequisites as the
// engine suites. Availability is obtained from real admission and a real writer,
// never from a seeded endpoint. Reopen reattaches that exact native incarnation.
func relationalUpdateFixture(t *testing.T, family string, automaticPort bool) (context.Context, cloudformation.ResourceRequest, func() cloudformation.ResourceHandler, func()) {
	t.Helper()
	typ := ""
	switch family {
	case "rds-instance":
		typ = "AWS::RDS::DBInstance"
	case "rds-cluster":
		typ = "AWS::RDS::DBCluster"
	case "docdb-instance":
		typ = "AWS::DocDB::DBInstance"
	case "docdb-cluster":
		typ = "AWS::DocDB::DBCluster"
	default:
		t.Fatalf("unknown relational family %q", family)
	}
	var selected relationalFenceCase
	for _, row := range relationalFenceCases() {
		if row.typ == typ && (family != "rds-instance" || row.properties["DBClusterIdentifier"] == nil) {
			selected = row
			break
		}
	}
	selected.properties = maps.Clone(selected.properties)
	selected.properties["Tags"] = []any{map[string]any{"Key": "customer", "Value": "before"}}
	if family != "docdb-instance" {
		selected.properties["DeletionProtection"] = false
		selected.properties["EngineVersion"] = "5.0"
		if selected.service == "rds" {
			selected.properties["EngineVersion"] = "17.11"
			selected.properties["CopyTagsToSnapshot"] = false
		}
	}
	var requestedPort int32
	if !automaticPort && family != "docdb-instance" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		requestedPort = int32(listener.Addr().(*net.TCPAddr).Port)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		selected.properties["Port"] = int64(requestedPort)
	}
	f := newRelationalFenceFixture(t, "memory", selected)
	r := cloudformation.ResourceRequest{StackID: "stack-one", StackName: "stack", LogicalID: "Database", Token: "native-incarnation", Type: typ, Properties: f.row.properties, DeletionPolicy: "Delete"}
	result, err := f.handler().Create(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = result.PhysicalID
	f.activate()
	originalID, claimed := f.nativeIdentity()
	if originalID == "" || !claimed {
		t.Fatal("real native admission did not retain its private incarnation")
	}
	verify := func() {
		t.Helper()
		if id, claimed := f.nativeIdentity(); id != originalID || !claimed {
			// Recovery runs through the native private-claim guard, not tags.
			t.Fatal("native edit changed the private resource incarnation")
		}
		if recovered, err := f.handler().(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != r.PhysicalID {
			t.Fatalf("native edit changed the exact private claim: %#v, %v", recovered, err)
		}
		if family != "docdb-instance" {
			var port int32
			var err error
			if selected.service == "rds" {
				port, err = f.services[len(f.services)-1].CloudFormationRequestedPort(f.ctx, selected.kind, r.PhysicalID)
			} else {
				port, err = f.documents[len(f.documents)-1].CloudFormationRequestedPort(f.ctx, selected.kind, r.PhysicalID)
			}
			if err != nil || port != requestedPort {
				t.Fatalf("native allocation mode changed: port=%d want=%d err=%v", port, requestedPort, err)
			}
		}
		f.assertEngine()
	}
	reopen := func() cloudformation.ResourceHandler {
		f.reopen()
		verify()
		return f.handler()
	}
	return f.ctx, r, reopen, verify
}

func assertRelationalConfiguration(t *testing.T, before, after cloudformation.Properties) {
	t.Helper()
	// These are persisted resource contracts, not scheduler status, transient
	// endpoints, or incidental defaults in a whole native response.
	for _, key := range []string{"DBInstanceIdentifier", "DBClusterIdentifier", "DBInstanceClass", "Engine", "EngineVersion", "MasterUsername", "DBName", "DatabaseName", "Port", "DeletionProtection", "CopyTagsToSnapshot", "EnableHttpEndpoint", "DBParameterGroupName", "DBClusterParameterGroupName", "Family", "Description", "DBSubnetGroupDescription", "SubnetIds", "Parameters", "Tags"} {
		old, oldPresent := before[key]
		current, present := after[key]
		if oldPresent != present || !reflect.DeepEqual(old, current) {
			t.Fatalf("native configuration %s changed: before=%#v after=%#v", key, old, current)
		}
	}
}

func TestRelationalMissingNativeRuntimeRejectsAdmissionAndRetainsUnavailableIntent(t *testing.T) {
	for _, cluster := range []bool{false, true} {
		t.Run(fmt.Sprint("cluster=", cluster), func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			repository := rds.NewMemoryRepository(nil)
			cipher := newRelationalOwnerCipher(t)
			service := rds.New(rds.Config{Repository: repository, Cipher: cipher, Clock: clock.NewManual(now)})
			t.Cleanup(func() { _ = service.Close() })
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"rds": service})
			var h cloudformation.ResourceHandler = cfnRDSInstance{commands}
			kind, engine := "db", "postgres"
			p := cloudformation.Properties{"DBInstanceIdentifier": "missing-runtime", "DBInstanceClass": "db.t3.micro", "Engine": engine, "MasterUsername": "owner", "MasterUserPassword": "test-password"}
			if cluster {
				h, kind, engine = cfnRDSCluster{commands}, "cluster", "aurora-postgresql"
				p = cloudformation.Properties{"DBClusterIdentifier": "missing-runtime", "Engine": engine, "MasterUsername": "owner", "MasterUserPassword": "test-password"}
			}
			r := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Database", Token: "native-incarnation", Properties: p}
			result, err := h.Create(ctx, r)
			var rejected *awswire.Error
			if !errors.As(err, &rejected) || rejected.Code != "InvalidParameterCombination" || result.PhysicalID != "" {
				t.Fatalf("missing runtime was not honestly rejected: %#v, %v", result, err)
			}
			key := rds.Key{Scope: rds.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: kind, Name: "missing-runtime"}
			if err := repository.View(ctx, func(reader rds.Reader) error {
				_, err := reader.Database(key)
				return err
			}); !errors.Is(err, rds.ErrNotFound) {
				t.Fatalf("missing prerequisite admitted a native resource: %v", err)
			}
			// A retained creation intent is not a fabricated available database.
			// Recovery without its runtime must remain unavailable and claimed.
			credentials, err := cipher.Seal(ctx, key.ARN(), "owner", "test-password")
			if err != nil {
				t.Fatal(err)
			}
			owner := rds.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}
			if err := repository.Update(ctx, func(tx rds.Transaction) error {
				return tx.PutDatabase(rds.Database{Key: key, ResourceID: r.Token, RuntimeID: r.Token, Owner: owner, Engine: engine, EngineVersion: "17.11", Class: "db.t3.micro", Username: "owner", Ciphertext: credentials, Status: "creating", Desired: "running", Operation: "create", Version: 1, Created: now, Due: now})
			}); err != nil {
				t.Fatal(err)
			}
			if drained, err := service.JobDriver().RunDue(ctx, 1); err != nil || drained.Processed != 1 {
				t.Fatalf("missing-runtime reconciliation: %#v, %v", drained, err)
			}
			if err := repository.View(ctx, func(reader rds.Reader) error {
				v, err := reader.Database(key)
				if err != nil {
					return err
				}
				if v.Status != "failed" || v.Endpoint.Address != "" || v.Endpoint.Port != 0 || v.Owner != owner || v.ResourceID != r.Token || v.RuntimeID != r.Token || v.Engine != engine || v.EngineVersion != "17.11" || v.Operation != "create" {
					t.Fatalf("missing runtime published availability or lost native intent/claim: %#v", v)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRelationalRejectedEditsRollbackToActualOwnerState(t *testing.T) {
	for _, test := range []struct {
		family, property string
		value            any
	}{
		{"rds-instance", "DBInstanceClass", "db.t3.large"},
		{"rds-instance", "EngineVersion", "18.0"},
		{"rds-instance", "Port", int64(15433)},
		{"rds-cluster", "EngineVersion", "18.0"},
		{"rds-cluster", "Port", int64(15433)},
		{"docdb-cluster", "EngineVersion", "8.0"},
		{"docdb-cluster", "Port", int64(27018)},
		{"docdb-instance", "DBInstanceClass", "db.t3.large"},
	} {
		t.Run(test.family+"/"+test.property, func(t *testing.T) {
			ctx, r, reopen, verify := relationalUpdateFixture(t, test.family, false)
			h := reopen()
			before, err := h.(cloudformation.ResourceReader).Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			original := r.Properties
			failed := maps.Clone(original)
			failed[test.property] = test.value
			if test.property == "Port" && failed["Port"] == original["Port"] {
				failed["Port"] = int64(1150)
				if original["Port"] == int64(1150) {
					failed["Port"] = int64(1151)
				}
			}
			failed["Tags"] = []any{map[string]any{"Key": "customer", "Value": "must-not-apply"}}
			if test.family != "docdb-instance" {
				failed["DeletionProtection"] = true
			}
			r.Previous, r.Properties = original, failed
			if result, err := h.Update(ctx, r); err == nil || result.PhysicalID != r.PhysicalID {
				t.Fatalf("unsupported edit = %#v, %v", result, err)
			}
			after, err := h.(cloudformation.ResourceReader).Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			assertRelationalConfiguration(t, before, after)
			verify()
			// Reopen around the real repository; Previous is now the failed edit,
			// not authoritative evidence that the native immutable field changed.
			h = reopen()
			r.Previous, r.Properties = failed, original
			if result, err := h.Update(ctx, r); err != nil || result.PhysicalID != r.PhysicalID {
				t.Fatalf("rejected-edit rollback = %#v, %v", result, err)
			}
			after, err = h.(cloudformation.ResourceReader).Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			assertRelationalConfiguration(t, before, after)
			verify()
		})
	}
}

func TestRelationalPortEditsRetainRealListenerAndAllocationMode(t *testing.T) {
	for _, family := range []string{"rds-instance", "rds-cluster", "docdb-cluster"} {
		for _, automatic := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/automatic=%v", family, automatic), func(t *testing.T) {
				ctx, r, reopen, verify := relationalUpdateFixture(t, family, automatic)
				h := reopen()
				initial, err := h.(cloudformation.ResourceReader).Read(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				port, ok := initial["Port"].(int64)
				if !ok || port < 1150 || port > 65535 {
					t.Fatalf("real native listener did not publish a valid port: %#v", initial["Port"])
				}
				original := r.Properties
				failed := maps.Clone(original)
				if automatic {
					failed["Port"] = int64(15433)
				} else {
					delete(failed, "Port")
				}
				r.Previous, r.Properties = original, failed
				if _, err := h.Update(ctx, r); err == nil {
					t.Fatal("native listener change/removal succeeded without an effect")
				}
				r.Previous, r.Properties = failed, original
				h = reopen()
				if _, err := h.Update(ctx, r); err != nil {
					t.Fatalf("listener rollback failed: %v", err)
				}
				model, err := h.(cloudformation.ResourceReader).Read(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				verify()
				if model["Port"] != port {
					t.Fatalf("live Port = %#v, want %d", model["Port"], port)
				}
				if !automatic {
					equivalent := maps.Clone(original)
					equivalent["Port"] = fmt.Sprint(port)
					r.Previous, r.Properties = original, equivalent
					if _, err := h.Update(ctx, r); err != nil {
						t.Fatalf("equivalent native port representation rejected: %v", err)
					}
				}
				verify()
			})
		}
	}
}

func TestRelationalSupportedControlsConvergeAndRemove(t *testing.T) {
	for _, family := range []string{"rds-instance", "rds-cluster", "docdb-cluster"} {
		t.Run(family, func(t *testing.T) {
			ctx, r, reopen, verify := relationalUpdateFixture(t, family, false)
			h := reopen()
			original := r.Properties
			changed := maps.Clone(original)
			changed["DeletionProtection"] = true
			if family != "docdb-cluster" {
				changed["CopyTagsToSnapshot"] = true
			}
			if family == "rds-cluster" {
				changed["EnableHttpEndpoint"] = true
			}
			r.Previous, r.Properties = original, changed
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			model, err := h.(cloudformation.ResourceReader).Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"DeletionProtection", "CopyTagsToSnapshot", "EnableHttpEndpoint"} {
				if changed[key] == true && model[key] != true {
					t.Fatalf("native control %s did not converge: %#v", key, model)
				}
			}
			verify()
			removed := maps.Clone(changed)
			for _, key := range []string{"DeletionProtection", "CopyTagsToSnapshot", "EnableHttpEndpoint", "Tags"} {
				delete(removed, key)
			}
			r.Previous, r.Properties = changed, removed
			h = reopen()
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			model, err = h.(cloudformation.ResourceReader).Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"DeletionProtection", "CopyTagsToSnapshot", "EnableHttpEndpoint"} {
				if value, present := model[key]; present && value != false {
					t.Fatalf("removed native control %s remains set: %#v", key, value)
				}
			}
			if tags := model["Tags"].([]any); len(tags) != 0 {
				t.Fatalf("removed customer tags remain: %#v", tags)
			}
			verify()
		})
	}
}

func TestRelationalCreationRecoveryRetainsOnlyExactAdmittedIncarnation(t *testing.T) {
	for _, family := range []string{"rds-instance", "rds-cluster", "docdb-instance", "docdb-cluster"} {
		t.Run(family, func(t *testing.T) {
			ctx, r, reopen, verify := relationalUpdateFixture(t, family, false)
			h := reopen()
			r.Properties = maps.Clone(r.Properties)
			if family == "rds-instance" || family == "docdb-instance" {
				r.Properties["DBInstanceClass"] = "db.t3.large"
			} else {
				r.Properties["EngineVersion"] = "unsupported-version"
			}
			result, err := h.Create(ctx, r)
			if err == nil || result.PhysicalID != r.PhysicalID {
				t.Fatalf("same-token rejected convergence lost admitted native ID: %#v, %v", result, err)
			}
			// Validation failure is also not proof that an earlier Create did not
			// admit this token. The recovery path must ignore the failed desired DTO.
			r.Properties["unsupported-property"] = true
			if result, err := h.Create(ctx, r); err == nil || result.PhysicalID != r.PhysicalID {
				t.Fatalf("invalid replay forgot admitted native ID: %#v, %v", result, err)
			}
			r.Token = "different-incarnation"
			if result, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, r); err == nil || result.PhysicalID != "" {
				t.Fatalf("foreign incarnation recovered as owned: %#v, %v", result, err)
			}
			verify()
		})
	}
}
