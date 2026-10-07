package integrations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	docdbengine "stackd/engine/docdb"
	rdsengine "stackd/engine/rds"
	"stackd/internal/awsapi"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/docdb"
	"stackd/internal/services/ec2"
	"stackd/internal/services/rds"
	"stackd/storage/sqlite"
	docdbdb "stackd/storage/sqlite/docdb"
	rdsdb "stackd/storage/sqlite/rds"
)

// Engine-backed ownership contracts share the existing explicit Docker opt-ins.
// Parameter/subnet ownership needs no engine and remains in the regular suite.
func newRelationalRDSEngine(t *testing.T) *rdsengine.Docker {
	t.Helper()
	if os.Getenv("STACKD_RDS_DOCKER") != "1" {
		t.Skip("set STACKD_RDS_DOCKER=1 with the pinned PostgreSQL and MySQL images installed")
	}
	runtime, err := rdsengine.NewDocker(rdsengine.DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: "cfn-rds-" + rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func newRelationalDocDBEngine(t *testing.T) *docdbengine.Docker {
	t.Helper()
	if os.Getenv("STACKD_DOCDB_DOCKER") != "1" {
		t.Skip("set STACKD_DOCDB_DOCKER=1 with the pinned MongoDB image installed")
	}
	runtime, err := docdbengine.NewDocker(docdbengine.DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: "cfn-docdb-" + rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func waitRelationalContract(t *testing.T, ctx context.Context, label string, ready func() (bool, error)) {
	t.Helper()
	for {
		done, err := ready()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if done {
			return
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatalf("%s: %v", label, ctx.Err())
		case <-timer.C:
		}
	}
}

type relationalOwnerCipher struct{ cipher.AEAD }

func newRelationalOwnerCipher(t *testing.T) relationalOwnerCipher {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return relationalOwnerCipher{aead}
}
func (c relationalOwnerCipher) Seal(_ context.Context, arn, username, password string) ([]byte, error) {
	plain, err := json.Marshal([]string{username, password})
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, c.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.AEAD.Seal(nonce, nonce, plain, []byte(arn)), nil
}
func (c relationalOwnerCipher) Open(_ context.Context, arn string, data []byte) (string, string, error) {
	if len(data) < c.NonceSize() {
		return "", "", fmt.Errorf("missing native credentials")
	}
	plain, err := c.AEAD.Open(nil, data[:c.NonceSize()], data[c.NonceSize():], []byte(arn))
	if err != nil {
		return "", "", err
	}
	var values []string
	if err := json.Unmarshal(plain, &values); err != nil {
		return "", "", err
	}
	if len(values) != 2 {
		return "", "", fmt.Errorf("invalid native credentials")
	}
	return values[0], values[1], nil
}

type relationalOwnerNetworks struct{ commands StepFunctionsCommands }

func (n relationalOwnerNetworks) ResolveSubnets(ctx context.Context, _ string, ids []string) ([]rds.Subnet, error) {
	out, err := cfnComputeCall[ec2api.DescribeSubnetsResult](ctx, n.commands, "ec2", "DescribeSubnets", map[string]any{"SubnetIds": ids})
	if err != nil {
		return nil, err
	}
	rows := make([]rds.Subnet, 0, len(out.Subnets))
	for _, subnet := range out.Subnets {
		rows = append(rows, rds.Subnet{ID: cfnComputeValue(subnet.SubnetId), VPCID: cfnComputeValue(subnet.VpcId), AvailabilityZone: cfnComputeValue(subnet.AvailabilityZone)})
	}
	return rows, nil
}
func (relationalOwnerNetworks) ValidateSecurityGroups(context.Context, string, string, []string) error {
	panic("unexpected security-group validation")
}

type relationalFenceCase struct {
	service, typ, kind, property, createAction string
	properties                                 cloudformation.Properties
}

func relationalFenceCases() []relationalFenceCase {
	return []relationalFenceCase{
		{"rds", "AWS::RDS::DBInstance", "db", "DBInstanceIdentifier", "CreateDBInstance", cloudformation.Properties{"DBInstanceClass": "db.t3.micro", "Engine": "postgres", "MasterUsername": "owner", "MasterUserPassword": "test-password"}},
		{"rds", "AWS::RDS::DBInstance", "db", "DBInstanceIdentifier", "CreateDBInstance", cloudformation.Properties{"DBInstanceClass": "db.t3.micro", "Engine": "aurora-postgresql", "DBClusterIdentifier": "dependency-cluster"}},
		{"rds", "AWS::RDS::DBCluster", "cluster", "DBClusterIdentifier", "CreateDBCluster", cloudformation.Properties{"Engine": "aurora-postgresql", "MasterUsername": "owner", "MasterUserPassword": "test-password"}},
		{"rds", "AWS::RDS::DBParameterGroup", "pg", "DBParameterGroupName", "CreateDBParameterGroup", cloudformation.Properties{"Family": "postgres17", "Description": "private owner", "Parameters": map[string]any{"statement_timeout": "1000"}}},
		{"rds", "AWS::RDS::DBClusterParameterGroup", "cluster-pg", "DBClusterParameterGroupName", "CreateDBClusterParameterGroup", cloudformation.Properties{"Family": "aurora-postgresql17", "Description": "private owner", "Parameters": map[string]any{"statement_timeout": "1000"}}},
		{"rds", "AWS::RDS::DBSubnetGroup", "subgrp", "DBSubnetGroupName", "CreateDBSubnetGroup", cloudformation.Properties{"DBSubnetGroupDescription": "private owner"}},
		{"docdb", "AWS::DocDB::DBCluster", "cluster", "DBClusterIdentifier", "CreateDBCluster", cloudformation.Properties{"MasterUsername": "owner", "MasterUserPassword": "test-password"}},
		{"docdb", "AWS::DocDB::DBInstance", "db", "DBInstanceIdentifier", "CreateDBInstance", cloudformation.Properties{"DBInstanceClass": "db.t3.micro", "DBClusterIdentifier": "dependency-cluster"}},
		{"docdb", "AWS::RDS::DBCluster", "cluster", "DBClusterIdentifier", "CreateDBCluster", cloudformation.Properties{"Engine": "docdb", "MasterUsername": "owner", "MasterUserPassword": "test-password"}},
		{"docdb", "AWS::RDS::DBInstance", "db", "DBInstanceIdentifier", "CreateDBInstance", cloudformation.Properties{"DBInstanceClass": "db.t3.micro", "Engine": "docdb", "DBClusterIdentifier": "dependency-cluster"}},
	}
}

type relationalFenceFixture struct {
	t               *testing.T
	ctx             context.Context
	row             relationalFenceCase
	rds             rds.Repository
	docdb           docdb.Repository
	db              *sql.DB
	path            string
	commands        StepFunctionsCommands
	networks        relationalOwnerNetworks
	cipher          relationalOwnerCipher
	services        []*rds.Service
	documents       []*docdb.Service
	runtime         *rdsengine.Docker
	documentRuntime *docdbengine.Docker
	engineReady     bool
}

func newRelationalFenceFixture(t *testing.T, backend string, row relationalFenceCase) *relationalFenceFixture {
	t.Helper()
	f := &relationalFenceFixture{t: t, row: row, cipher: newRelationalOwnerCipher(t)}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancel)
	f.ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "relational.sqlite")
		var err error
		f.db, err = sqlite.Open(f.ctx, f.path)
		if err != nil {
			t.Fatal(err)
		}
		f.rds, f.docdb = rdsdb.New(f.db), docdbdb.New(f.db)
	} else {
		f.rds, f.docdb = rds.NewMemoryRepository(nil), docdb.NewMemoryRepository(nil)
	}
	t.Cleanup(f.close)
	if row.kind == "db" || row.kind == "cluster" {
		if row.service == "rds" {
			f.runtime = newRelationalRDSEngine(t)
		} else {
			f.documentRuntime = newRelationalDocDBEngine(t)
		}
	}
	network := ec2.New(ec2.Config{})
	networkCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": network})
	f.networks = relationalOwnerNetworks{networkCommands}
	f.row.properties = maps.Clone(row.properties)
	f.row.properties[row.property] = "private-native-owner"
	if row.kind == "subgrp" {
		vpc, err := cfnComputeCall[ec2api.CreateVpcResult](f.ctx, networkCommands, "ec2", "CreateVpc", map[string]any{"CidrBlock": "10.0.0.0/16"})
		if err != nil {
			t.Fatal(err)
		}
		var ids []any
		for i, zone := range []string{"us-east-1a", "us-east-1b"} {
			subnet, err := cfnComputeCall[ec2api.CreateSubnetResult](f.ctx, networkCommands, "ec2", "CreateSubnet", map[string]any{"VpcId": cfnComputeValue(vpc.Vpc.VpcId), "CidrBlock": fmt.Sprintf("10.0.%d.0/24", i), "AvailabilityZone": zone})
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, cfnComputeValue(subnet.Subnet.SubnetId))
		}
		f.row.properties["SubnetIds"] = ids
	}
	f.openOwners()
	if row.service == "rds" && row.properties["DBClusterIdentifier"] != nil {
		if err := cfnComputeRun(f.ctx, f.commands, "rds", "CreateDBCluster", map[string]any{"DBClusterIdentifier": "dependency-cluster", "Engine": "aurora-postgresql", "MasterUsername": "owner", "MasterUserPassword": "test-password"}); err != nil {
			t.Fatal(err)
		}
	}
	if row.service == "docdb" && row.kind == "db" {
		if err := cfnComputeRun(f.ctx, f.commands, "docdb", "CreateDBCluster", map[string]any{"DBClusterIdentifier": "dependency-cluster", "Engine": "docdb", "MasterUsername": "owner", "MasterUserPassword": "test-password"}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func (f *relationalFenceFixture) openOwners() {
	var runtime rdsengine.Runtime
	var documentRuntime docdbengine.Runtime
	if f.runtime != nil {
		runtime = f.runtime
	}
	if f.documentRuntime != nil {
		documentRuntime = f.documentRuntime
	}
	d := docdb.New(docdb.Config{Repository: f.docdb, Runtime: documentRuntime, Cipher: f.cipher})
	s := rds.New(rds.Config{Repository: f.rds, Runtime: runtime, Cipher: f.cipher, Networks: f.networks, DocumentDB: DocumentDBQuery{Documents: d}})
	f.services, f.documents = append(f.services, s), append(f.documents, d)
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"rds": s, "docdb": d})
	if err := d.Start(); err != nil {
		f.t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		f.t.Fatal(err)
	}
}
func (f *relationalFenceFixture) reopen() {
	f.t.Helper()
	for _, s := range f.services {
		_ = s.Close()
	}
	f.services = nil
	for _, s := range f.documents {
		_ = s.Close()
	}
	f.documents = nil
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			f.t.Fatal(err)
		}
		var err error
		f.db, err = sqlite.Open(f.ctx, f.path)
		if err != nil {
			f.t.Fatal(err)
		}
		f.rds, f.docdb = rdsdb.New(f.db), docdbdb.New(f.db)
	}
	f.openOwners()
	if f.engineReady {
		f.waitReady()
		f.assertEngine()
	}
}

func (f *relationalFenceFixture) close() {
	for _, s := range f.services {
		_ = s.Close()
	}
	for _, s := range f.documents {
		_ = s.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if f.runtime != nil {
		var databases []rds.Database
		var snapshots []rds.Snapshot
		if err := f.rds.View(ctx, func(reader rds.Reader) error {
			var err error
			databases, err = reader.AllDatabases()
			if err != nil {
				return err
			}
			snapshots, err = reader.AllSnapshots()
			return err
		}); err != nil {
			f.t.Error(err)
		}
		for _, v := range snapshots {
			if err := f.runtime.DeleteSnapshot(ctx, v.RuntimeID); err != nil {
				f.t.Error(err)
			}
		}
		for _, v := range databases {
			if v.Cluster == "" {
				if err := f.runtime.Delete(ctx, v.RuntimeID); err != nil {
					f.t.Error(err)
				}
			}
		}
		_ = f.runtime.Close()
	}
	if f.documentRuntime != nil {
		var clusters []docdb.Cluster
		var snapshots []docdb.Snapshot
		if err := f.docdb.View(ctx, func(reader docdb.Reader) error {
			var err error
			clusters, err = reader.Clusters()
			if err != nil {
				return err
			}
			snapshots, err = reader.Snapshots()
			return err
		}); err != nil {
			f.t.Error(err)
		}
		for _, v := range snapshots {
			if err := f.documentRuntime.DeleteSnapshot(ctx, v.RuntimeID); err != nil {
				f.t.Error(err)
			}
		}
		for _, v := range clusters {
			if err := f.documentRuntime.Delete(ctx, v.RuntimeID); err != nil {
				f.t.Error(err)
			}
		}
		_ = f.documentRuntime.Close()
	}
	if f.db != nil {
		_ = f.db.Close()
	}
}

// A cluster shell is a valid native admission but proves nothing about an
// engine. Attach its real writer before exercising owner-backed mutations.
func (f *relationalFenceFixture) activate() {
	f.t.Helper()
	if f.row.kind != "db" && f.row.kind != "cluster" {
		return
	}
	if f.row.kind == "cluster" {
		engine := "docdb"
		if f.row.service == "rds" {
			engine = cfnComputeString(f.row.properties, "Engine")
		}
		if err := cfnComputeRun(f.ctx, f.commands, f.row.service, "CreateDBInstance", map[string]any{"DBInstanceIdentifier": "private-native-writer", "DBClusterIdentifier": "private-native-owner", "DBInstanceClass": "db.t3.micro", "Engine": engine}); err != nil {
			f.t.Fatal(err)
		}
	}
	f.engineReady = true
	f.waitReady()
	f.assertEngine()
}

func (f *relationalFenceFixture) waitReady() {
	f.t.Helper()
	r := cloudformation.ResourceRequest{PhysicalID: "private-native-owner", CloudControl: true}
	waitRelationalContract(f.t, f.ctx, "real native owner availability", func() (bool, error) {
		return f.handler().(cloudformation.ResourceStabilizer).Stabilize(f.ctx, r)
	})
}

func (f *relationalFenceFixture) assertEngine() {
	f.t.Helper()
	if f.row.service == "rds" {
		var database rds.Database
		key := rds.Key{Scope: rds.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: f.row.kind, Name: "private-native-owner"}
		if err := f.rds.View(f.ctx, func(reader rds.Reader) error {
			var err error
			database, err = reader.Database(key)
			if err == nil && database.Cluster != "" {
				key.Kind, key.Name = "cluster", database.Cluster
				database, err = reader.Database(key)
			}
			return err
		}); err != nil {
			f.t.Fatal(err)
		}
		user, password, err := f.cipher.Open(f.ctx, key.ARN(), database.Ciphertext)
		if err != nil {
			f.t.Fatal(err)
		}
		connection, err := rdsengine.Open(f.ctx, database.Engine, database.Endpoint, database.DatabaseName, user, password)
		if err != nil {
			f.t.Fatal(err)
		}
		defer connection.Close()
		var answer int
		if err := connection.QueryRowContext(f.ctx, "SELECT 41 + 1").Scan(&answer); err != nil || answer != 42 {
			f.t.Fatalf("actual authenticated listener: answer=%d err=%v", answer, err)
		}
		return
	}
	key := docdb.Key{Scope: docdb.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster", Name: "private-native-owner"}
	if f.row.kind == "db" {
		key.Name = "dependency-cluster"
	}
	var cluster docdb.Cluster
	if err := f.docdb.View(f.ctx, func(reader docdb.Reader) error {
		var err error
		cluster, err = reader.Cluster(key)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	user, password, err := f.cipher.Open(f.ctx, key.ARN(), cluster.Ciphertext)
	if err != nil {
		f.t.Fatal(err)
	}
	connection, err := docdbengine.Open(f.ctx, cluster.Endpoint, user, password)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := connection.Disconnect(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}
func (f *relationalFenceFixture) handler() cloudformation.ResourceHandler {
	return CloudFormationRelationalHandlers(f.commands)[f.row.typ]
}
func (f *relationalFenceFixture) nativeIdentity() (string, bool) {
	f.t.Helper()
	id, claimed := "", false
	if f.row.service == "rds" {
		key := rds.Key{Scope: rds.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: f.row.kind, Name: "private-native-owner"}
		if err := f.rds.View(f.ctx, func(r rds.Reader) error {
			switch key.Kind {
			case "db", "cluster":
				v, err := r.Database(key)
				id, claimed = v.ResourceID, v.Owner.Token != ""
				return err
			case "pg", "cluster-pg":
				v, err := r.ParameterGroup(key)
				id, claimed = v.ResourceID, v.Owner.Token != ""
				return err
			case "subgrp":
				v, err := r.SubnetGroup(key)
				id, claimed = v.ResourceID, v.Owner.Token != ""
				return err
			}
			return fmt.Errorf("unexpected RDS kind")
		}); err != nil {
			f.t.Fatal(err)
		}
	} else {
		key := docdb.Key{Scope: docdb.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: f.row.kind, Name: "private-native-owner"}
		if err := f.docdb.View(f.ctx, func(r docdb.Reader) error {
			if key.Kind == "cluster" {
				v, err := r.Cluster(key)
				id, claimed = v.RuntimeID, v.Owner.Token != ""
				return err
			}
			v, err := r.Instance(key)
			id, claimed = v.RuntimeID, v.Owner.Token != ""
			return err
		}); err != nil {
			f.t.Fatal(err)
		}
	}
	return id, claimed
}
func (f *relationalFenceFixture) arn() string {
	return "arn:aws:rds:us-east-1:111111111111:" + f.row.kind + ":private-native-owner"
}
func (f *relationalFenceFixture) recreateWithPublicMarkers(r cloudformation.ResourceRequest) {
	f.t.Helper()
	// Retire the real native incarnation before admitting a same-name successor.
	// Public marker copies are ordinary tags and must never recreate its claim.
	f.deleteNative(f.row.kind, "private-native-owner")
	input := cfnComputeCopy(f.row.properties, f.row.property, "DBInstanceClass", "DBClusterIdentifier", "Engine", "MasterUsername", "MasterUserPassword", "Description", "DBSubnetGroupDescription", "SubnetIds")
	if family := f.row.properties["Family"]; family != nil {
		input["DBParameterGroupFamily"] = family
	}
	if f.row.service == "docdb" {
		input["Engine"] = "docdb"
	}
	input["Tags"] = cfnComputeTagList(cfnComputeOwnedTags(cloudformation.ResourceRequest{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}))
	if err := cfnComputeRun(f.ctx, f.commands, f.row.service, f.row.createAction, input); err != nil {
		f.t.Fatal(err)
	}
	f.activate()
}

func (f *relationalFenceFixture) deleteNative(kind, name string) {
	f.t.Helper()
	if kind == "cluster" {
		f.deleteNative("db", "private-native-writer")
	}
	action, property := "", ""
	switch kind {
	case "db":
		action, property = "DeleteDBInstance", "DBInstanceIdentifier"
	case "cluster":
		action, property = "DeleteDBCluster", "DBClusterIdentifier"
	case "cluster-snapshot":
		action, property = "DeleteDBClusterSnapshot", "DBClusterSnapshotIdentifier"
	case "pg":
		action, property = "DeleteDBParameterGroup", "DBParameterGroupName"
	case "cluster-pg":
		action, property = "DeleteDBClusterParameterGroup", "DBClusterParameterGroupName"
	case "subgrp":
		action, property = "DeleteDBSubnetGroup", "DBSubnetGroupName"
	default:
		f.t.Fatalf("unexpected native deletion kind %q", kind)
	}
	input := map[string]any{property: name}
	if kind == "cluster" || kind == "db" && f.row.service == "rds" {
		input["SkipFinalSnapshot"] = true
	}
	if err := cfnComputeRun(f.ctx, f.commands, f.row.service, action, input); err != nil {
		f.t.Fatal(err)
	}
	waitRelationalContract(f.t, f.ctx, action, func() (bool, error) {
		if f.row.service == "rds" {
			key := rds.Key{Scope: rds.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: kind, Name: name}
			err := f.rds.View(f.ctx, func(reader rds.Reader) error {
				switch kind {
				case "db", "cluster":
					_, err := reader.Database(key)
					return err
				case "cluster-snapshot":
					_, err := reader.Snapshot(key)
					return err
				case "pg", "cluster-pg":
					_, err := reader.ParameterGroup(key)
					return err
				case "subgrp":
					_, err := reader.SubnetGroup(key)
					return err
				}
				return fmt.Errorf("unexpected native deletion kind %q", kind)
			})
			if errors.Is(err, rds.ErrNotFound) {
				return true, nil
			}
			return false, err
		}
		key := docdb.Key{Scope: docdb.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: kind, Name: name}
		err := f.docdb.View(f.ctx, func(reader docdb.Reader) error {
			switch kind {
			case "db":
				_, err := reader.Instance(key)
				return err
			case "cluster":
				_, err := reader.Cluster(key)
				return err
			case "cluster-snapshot":
				_, err := reader.Snapshot(key)
				return err
			}
			return fmt.Errorf("unexpected native deletion kind %q", kind)
		})
		if errors.Is(err, docdb.ErrNotFound) {
			return true, nil
		}
		return false, err
	})
}

func TestRelationalPrivateClaimsSurviveReopenAndRejectCounterfeitRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, row := range relationalFenceCases() {
			for _, ccCreate := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/cc=%v", backend, row.typ, ccCreate), func(t *testing.T) {
					f := newRelationalFenceFixture(t, backend, row)
					r := cloudformation.ResourceRequest{StackID: "stack-private", LogicalID: "Database", Token: "native-incarnation", Type: row.typ, Properties: f.row.properties, CloudControl: ccCreate, DeletionPolicy: "Delete"}
					first, err := f.handler().Create(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					r.PhysicalID = first.PhysicalID
					f.activate()
					originalID, claimed := f.nativeIdentity()
					if originalID == "" || !claimed {
						t.Fatal("native admission did not allocate an independent claimed incarnation")
					}
					// Public writers may forge or erase every old marker without
					// changing private authority, including on a CC-created resource.
					other := r
					other.Token = "counterfeit-incarnation"
					if err := cfnComputeRun(f.ctx, f.commands, row.service, "AddTagsToResource", map[string]any{"ResourceName": f.arn(), "Tags": cfnComputeTagList(cfnComputeOwnedTags(other))}); err != nil {
						t.Fatal(err)
					}
					f.reopen()
					h := f.handler()
					if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != first.PhysicalID {
						t.Fatalf("same-token private recovery after reopen: %#v, %v", recovered, err)
					}
					if repeated, err := h.Create(f.ctx, r); err != nil || repeated.PhysicalID != first.PhysicalID {
						t.Fatalf("same-token Create after reopen: %#v, %v", repeated, err)
					}
					if got, ok := f.nativeIdentity(); got != originalID || !ok {
						t.Fatal("reopen/recovery changed native identity or claim")
					}
					if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, other); err == nil || recovered.PhysicalID != "" {
						t.Fatalf("counterfeit public markers recovered another claim: %#v, %v", recovered, err)
					}
					// A private claim is not an IAM grant, and Cloud Control only
					// bypasses controller ownership, never current native IAM.
					unprivileged := awsctx.FromContext(f.ctx)
					unprivileged.PrincipalARN = "arn:aws:iam::111111111111:user/unpermitted"
					unprivileged.PrincipalID = "AIDAUNPERMITTED"
					unprivileged.UserName = "unpermitted"
					deniedContext := awsctx.WithMetadata(f.ctx, unprivileged)
					var denied *awswire.Error
					if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(deniedContext, r); !errors.As(err, &denied) || denied.Code != "AccessDenied" {
						t.Fatalf("private recovery bypassed current native IAM: %v", err)
					}
					ownedCC := r
					ownedCC.CloudControl = true
					ownedCC.Previous, ownedCC.Properties = r.Properties, maps.Clone(r.Properties)
					ownedCC.Properties["Tags"] = []any{map[string]any{"Key": "customer", "Value": "cloud-control-current-iam"}}
					if _, err := h.Update(deniedContext, ownedCC); !errors.As(err, &denied) || denied.Code != "AccessDenied" {
						t.Fatalf("CC mutation bypassed current native IAM: %v", err)
					}
					if _, err := h.Update(f.ctx, ownedCC); err != nil {
						t.Fatalf("IAM-permitted CC edit failed: %v", err)
					}
					if got, claimed := f.nativeIdentity(); got != originalID || !claimed {
						t.Fatal("ordinary CC edit transferred the private native claim")
					}
					if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != first.PhysicalID {
						t.Fatalf("CC edit changed the exact native claim: %#v, %v", recovered, err)
					}
					r.CloudControl = false
					r.Previous, r.Properties = r.Properties, maps.Clone(r.Properties)
					r.Properties["Tags"] = []any{map[string]any{"Key": "customer", "Value": "private-authority-still-current"}}
					if _, err := h.Update(f.ctx, r); err != nil {
						t.Fatalf("public marker forgery blocked authentic native claim: %v", err)
					}
					f.recreateWithPublicMarkers(r)
					f.reopen()
					h = f.handler()
					newID, claimed := f.nativeIdentity()
					if newID == originalID || newID == "" || claimed {
						t.Fatal("direct native recreation inherited a private claim or resource ID")
					}
					reader := h.(cloudformation.ResourceReader)
					before, err := reader.Read(f.ctx, r)
					if err != nil {
						t.Fatalf("native/CC reader refused IAM-permitted foreign row: %v", err)
					}
					switch row.typ {
					case "AWS::RDS::DBInstance":
						if before["DbiResourceId"] != "db-"+newID {
							t.Fatalf("native instance Read did not publish the actual member incarnation: %#v", before)
						}
					case "AWS::RDS::DBCluster":
						if before["DBClusterResourceId"] != "cluster-"+newID {
							t.Fatalf("native cluster Read did not publish the actual source incarnation: %#v", before)
						}
					case "AWS::DocDB::DBCluster":
						if before["ClusterResourceId"] != "cluster-"+newID {
							t.Fatalf("native DocumentDB Read did not publish the actual source incarnation: %#v", before)
						}
					}
					if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil || recovered.PhysicalID != "" {
						t.Fatalf("stale token adopted foreign recreation: %#v, %v", recovered, err)
					}
					if _, err := h.Update(f.ctx, r); err == nil {
						t.Fatal("stale CFN updated foreign recreation with copied markers")
					}
					if err := h.Delete(f.ctx, r); err == nil {
						t.Fatal("stale CFN deleted foreign recreation with copied markers")
					}
					cc := r
					cc.CloudControl, cc.Token = true, "cc-other-creation"
					if recovered, err := h.Create(f.ctx, cc); err == nil || recovered.PhysicalID != "" {
						t.Fatalf("CC Create bypassed private admission: %#v, %v", recovered, err)
					}
					after, err := reader.Read(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					assertRelationalConfiguration(t, before, after)
					if _, err := h.Update(f.ctx, cc); err != nil {
						t.Fatalf("CC mutation lost current native IAM permission: %v", err)
					}
					if got, ok := f.nativeIdentity(); got != newID || ok {
						t.Fatal("CC mutation transferred native ownership")
					}
					if f.engineReady {
						f.assertEngine()
					}
				})
			}
		}
	}
}

type relationalMutationRace struct {
	awscommands.CommandExecutor
	before func()
}

func (e *relationalMutationRace) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	if string(request.Operation.Name) == "AddTagsToResource" && e.before != nil {
		before := e.before
		e.before = nil
		before()
	}
	return e.CommandExecutor.ExecuteCommand(ctx, request)
}

func TestRelationalNativeMutationAtomicallyRejectsReadThenRecreateRace(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, row := range relationalFenceCases() {
			t.Run(backend+"/"+row.typ, func(t *testing.T) {
				f := newRelationalFenceFixture(t, backend, row)
				r := cloudformation.ResourceRequest{StackID: "stack-private", LogicalID: "Database", Token: "native-incarnation", Type: row.typ, Properties: f.row.properties, DeletionPolicy: "Delete"}
				first, err := f.handler().Create(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID, r.Previous = first.PhysicalID, r.Properties
				f.activate()
				r.Properties = maps.Clone(r.Properties)
				r.Properties["Tags"] = []any{map[string]any{"Key": "customer", "Value": "must-not-apply"}}
				oldID, _ := f.nativeIdentity()
				provider := "rds"
				executors := map[string]awscommands.CommandExecutor{
					"rds":   f.services[len(f.services)-1],
					"docdb": f.documents[len(f.documents)-1],
				}
				if row.typ == "AWS::DocDB::DBInstance" || row.typ == "AWS::DocDB::DBCluster" {
					provider = "docdb"
				}
				race := &relationalMutationRace{CommandExecutor: executors[provider], before: func() { f.recreateWithPublicMarkers(r) }}
				executors[provider] = race
				commands := NewStepFunctionsCommands(executors)
				h := CloudFormationRelationalHandlers(commands)[row.typ]
				if result, err := h.Update(f.ctx, r); err == nil || result.PhysicalID != first.PhysicalID {
					t.Fatalf("read/recreate race was not fenced at native mutation: %#v, %v", result, err)
				}
				newID, claimed := f.nativeIdentity()
				if newID == oldID || claimed {
					t.Fatal("race did not admit a distinct unclaimed native successor")
				}
				model, err := f.handler().(cloudformation.ResourceReader).Read(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				// Copied public markers remain ordinary customer metadata. The
				// rejected stale mutation must not install its requested tag.
				for _, raw := range model["Tags"].([]any) {
					tag, _ := cfnComputeObject(raw)
					if tag["Key"] == "customer" && tag["Value"] == "must-not-apply" {
						t.Fatalf("stale native mutation changed successor tags: %#v", model)
					}
				}
				if row.kind == "pg" || row.kind == "cluster-pg" {
					if len(model["Parameters"].(map[string]any)) != 0 {
						t.Fatalf("stale publication changed successor parameters: %#v", model)
					}
				}
			})
		}
	}
}

func (f *relationalFenceFixture) waitSnapshot(name string) {
	f.t.Helper()
	waitRelationalContract(f.t, f.ctx, "actual native backup completion", func() (bool, error) {
		status := ""
		var err error
		if f.row.service == "rds" {
			key := rds.Key{Scope: rds.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster-snapshot", Name: name}
			err = f.rds.View(f.ctx, func(reader rds.Reader) error {
				v, err := reader.Snapshot(key)
				status = v.Status
				return err
			})
		} else {
			key := docdb.Key{Scope: docdb.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster-snapshot", Name: name}
			err = f.docdb.View(f.ctx, func(reader docdb.Reader) error {
				v, err := reader.Snapshot(key)
				status = v.Status
				return err
			})
		}
		if err != nil {
			return false, err
		}
		return cfnRDSReady(status)
	})
	f.waitReady()
	f.assertEngine()
}
func (f *relationalFenceFixture) checkSnapshotClaim(r cloudformation.ResourceRequest, snapshotName, sourceID string) {
	f.t.Helper()
	if f.row.service == "rds" {
		key := rds.Key{Scope: rds.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster-snapshot", Name: snapshotName}
		if err := f.rds.View(f.ctx, func(reader rds.Reader) error {
			v, err := reader.Snapshot(key)
			if err != nil {
				return err
			}
			if v.Owner != (rds.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}) || v.SourceRuntimeID != sourceID || v.Status != "available" {
				f.t.Fatalf("completed native backup lost its private claim/source: %#v", v)
			}
			return nil
		}); err != nil {
			f.t.Fatal(err)
		}
	} else {
		key := docdb.Key{Scope: docdb.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster-snapshot", Name: snapshotName}
		if err := f.docdb.View(f.ctx, func(reader docdb.Reader) error {
			v, err := reader.Snapshot(key)
			if err != nil {
				return err
			}
			if v.Owner != (docdb.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}) || v.SourceRuntimeID != sourceID || v.Status != "available" {
				f.t.Fatalf("completed native backup lost its private claim/source: %#v", v)
			}
			return nil
		}); err != nil {
			f.t.Fatal(err)
		}
	}
}

func TestRelationalSnapshotPolicyRetainsPrivateBackupAndSourceClaims(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, row := range relationalFenceCases() {
			if row.kind != "cluster" {
				continue
			}
			t.Run(backend+"/"+row.typ, func(t *testing.T) {
				f := newRelationalFenceFixture(t, backend, row)
				r := cloudformation.ResourceRequest{StackID: "stack-private", LogicalID: "Database", Token: "native-incarnation", Type: row.typ, Properties: f.row.properties, DeletionPolicy: "Snapshot"}
				first, err := f.handler().Create(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = first.PhysicalID
				f.activate()
				sourceID, _ := f.nativeIdentity()
				// The snapshot policy must execute a real backup of this writer,
				// retain its private source claim, and survive repository reopen.
				if err := f.handler().Delete(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				name := cfnRDSFinalSnapshotName(r, r.PhysicalID)
				f.waitSnapshot(name)
				f.checkSnapshotClaim(r, name, sourceID)
				f.reopen()
				f.checkSnapshotClaim(r, name, sourceID)
				// Recreate that public snapshot name through native admission,
				// with identical source and counterfeit old controller markers.
				f.deleteNative("cluster-snapshot", name)
				tags := cfnComputeOwnedTags(cloudformation.ResourceRequest{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
				tags[cfnComputeTagPrefix+"snapshot-source"] = "cluster-" + sourceID
				if err := cfnComputeRun(f.ctx, f.commands, row.service, "CreateDBClusterSnapshot", map[string]any{"DBClusterIdentifier": r.PhysicalID, "DBClusterSnapshotIdentifier": name, "Tags": cfnComputeTagList(tags)}); err != nil {
					t.Fatal(err)
				}
				f.waitSnapshot(name)
				f.reopen()
				if ready, err := f.handler().(cloudformation.ResourceDeletionStabilizer).StabilizeDeletion(f.ctx, r); err == nil || ready {
					t.Fatalf("counterfeit snapshot certified private backup completion: %v, %v", ready, err)
				}
				if currentID, claimed := f.nativeIdentity(); currentID != sourceID || !claimed {
					t.Fatal("rejected snapshot recovery retired or transferred the real source")
				}
			})
		}
	}
}

type relationalPostAdmissionReadFailure struct {
	awscommands.CommandExecutor
	admitted bool
}

func (e *relationalPostAdmissionReadFailure) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	action := string(request.Operation.Name)
	if e.admitted && (action == "DescribeDBParameterGroups" || action == "DescribeDBClusterParameterGroups") {
		return nil, &awswire.Error{Code: "InternalFailure", Message: "Injected unavailable post-admission observer.", StatusCode: 500}
	}
	out, err := e.CommandExecutor.ExecuteCommand(ctx, request)
	if err == nil && (action == "CreateDBParameterGroup" || action == "CreateDBClusterParameterGroup") {
		e.admitted = true
	}
	return out, err
}
func TestRelationalParameterCreateReturnsActualIDWhenPostAdmissionReadFails(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, row := range relationalFenceCases() {
			if row.kind != "pg" && row.kind != "cluster-pg" {
				continue
			}
			t.Run(backend+"/"+row.typ, func(t *testing.T) {
				f := newRelationalFenceFixture(t, backend, row)
				r := cloudformation.ResourceRequest{StackID: "stack-private", LogicalID: "Parameters", Token: "native-incarnation", Type: row.typ, Properties: f.row.properties}
				observer := &relationalPostAdmissionReadFailure{CommandExecutor: f.services[len(f.services)-1]}
				commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"rds": observer})
				h := CloudFormationRelationalHandlers(commands)[row.typ]
				admitted, err := h.Create(f.ctx, r)
				if err == nil || admitted.PhysicalID != "private-native-owner" {
					t.Fatalf("post-admission observer failure forgot actual native ID: %#v, %v", admitted, err)
				}
				f.reopen()
				if recovered, err := f.handler().(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != admitted.PhysicalID {
					t.Fatalf("actual admission could not recover after reopen: %#v, %v", recovered, err)
				}
			})
		}
	}
}
