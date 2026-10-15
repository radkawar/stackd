package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	kafkaapi "stackd/internal/awsapi/kafka"
	kmsapi "stackd/internal/awsapi/kms"
	secretapi "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/kafka"
	"stackd/internal/services/kms"
	"stackd/internal/services/secretsmanager"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	iamdb "stackd/storage/sqlite/iam"
	journaldb "stackd/storage/sqlite/journal"
	kafkadb "stackd/storage/sqlite/kafka"
	kmsdb "stackd/storage/sqlite/kms"
	secretdb "stackd/storage/sqlite/secretsmanager"
)

// These tests use real IAM, Secrets Manager, KMS cryptography and shared
// repositories. Native broker protocol/security verification is separate.
type kafkaSCRAMFixture struct {
	t            *testing.T
	path         string
	db           *sql.DB
	clock        *clock.Manual
	root, caller context.Context
	identities   iam.Repository
	clusters     kafka.Repository
	keys         kms.Storage
	secrets      secretsmanager.Repository
	events       journal.Storage
	credentials  *identity.Store
	iam          *iam.Service
	kms          *kms.Service
	secret       *secretsmanager.Service
	kafka        *kafka.Service
	adapter      KafkaSecrets
	commands     StepFunctionsCommands
	user         iam.User
	clusterARN   string
}

func newKafkaSCRAMFixture(t *testing.T, backend string) *kafkaSCRAMFixture {
	f := &kafkaSCRAMFixture{t: t, clock: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)), clusterARN: "arn:aws:kafka:us-east-1:111111111111:cluster/scram/cluster-id"}
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "scram.sqlite")
		f.open()
	} else {
		d := memory.NewDomain()
		f.identities, f.clusters, f.keys, f.secrets, f.events = iam.NewMemoryRepository(d), kafka.NewMemoryRepository(d), kms.NewMemoryStorage(d), secretsmanager.NewMemoryRepository(d), journal.NewMemory(d)
	}
	f.start()
	f.user = iam.User{Arn: "arn:aws:iam::111111111111:user/scram-deployer", UserName: "scram-deployer", UserId: "AIDASCRAMDEPLOYER", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"allow": `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}}}
	f.setDeny("")
	credential, err := f.credentials.CreateAccessKey(identity.Principal{AccountID: "111111111111", ARN: f.user.Arn, ID: f.user.UserId, UserName: f.user.UserName})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, "us-east-1", "scram-test")
	if err != nil {
		t.Fatal(err)
	}
	f.caller = awsctx.WithMetadata(t.Context(), metadata)
	if err := f.clusters.Update(f.root, func(tx kafka.Transaction) error {
		return tx.PutCluster(kafka.ClusterRecord{Scope: kafka.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, ARN: f.clusterARN, Name: "scram", Incarnation: "immutable-cluster", KafkaVersion: "3.7.1", SecurityMode: "SASL_SCRAM", State: "ACTIVE", Brokers: 1, Version: 1, Created: f.clock.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}

func (f *kafkaSCRAMFixture) open() {
	var err error
	f.db, err = sqlite.Open(f.t.Context(), f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	f.identities, f.clusters, f.keys, f.secrets, f.events = iamdb.New(f.db), kafkadb.New(f.db), kmsdb.New(f.db), secretdb.New(f.db), journaldb.New(f.db)
}

func (f *kafkaSCRAMFixture) start() {
	f.credentials = identity.NewWithConfig(identity.Config{AccountID: "111111111111", Repository: iam.NewCredentialRepository(f.identities, nil), Clock: f.clock})
	root, err := f.credentials.Resolve(f.t.Context(), "111111111111")
	if err != nil {
		f.t.Fatal(err)
	}
	metadata, err := identity.RequestMetadata(root, root.AccessKeyID, "us-east-1", "scram-root")
	if err != nil {
		f.t.Fatal(err)
	}
	f.root = awsctx.WithMetadata(f.t.Context(), metadata)
	recorder := apievents.New(f.events)
	f.iam = iam.NewWithConfig(iam.Config{Repository: f.identities, Credentials: f.credentials, Clock: f.clock, APICallEvents: recorder})
	auth := authorization.NewWithClock(f.iam, nil, f.clock)
	f.kms = kms.NewWithConfig(kms.Config{Storage: f.keys, Authorizer: auth, Clock: f.clock, APIEvents: recorder})
	f.secret = secretsmanager.New(secretsmanager.Config{Repository: f.secrets, Authorizer: auth, Clock: f.clock, Keys: ServiceDataKeys{KMS: f.kms, Activity: f.iam, Service: "secretsmanager"}, Recorder: recorder})
	f.adapter = KafkaSecrets{Secrets: f.secret, KMS: f.kms, Activity: f.iam}
	f.kafka = kafka.New(kafka.Config{Repository: f.clusters, Authorizer: auth, Clock: f.clock, Secrets: f.adapter, Recorder: recorder})
	f.kafka.JobDriver().Close()
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kafka": f.kafka, "kms": f.kms, "secretsmanager": f.secret})
}

func (f *kafkaSCRAMFixture) close() {
	_ = f.kafka.Close()
	_ = f.secret.Close()
	_ = f.kms.Close()
	_ = f.iam.Close()
}
func (f *kafkaSCRAMFixture) reopen() {
	f.close()
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			f.t.Fatal(err)
		}
		f.open()
	}
	f.start()
}
func (f *kafkaSCRAMFixture) setDeny(statement string) {
	f.t.Helper()
	delete(f.user.IdentityPolicies.Inline, "deny")
	if statement != "" {
		f.user.IdentityPolicies.Inline["deny"] = statement
	}
	if err := f.identities.Update(f.root, func(tx iam.WriteTx) error {
		return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "111111111111"}, f.user)
	}); err != nil {
		f.t.Fatal(err)
	}
}
func (f *kafkaSCRAMFixture) run(ctx context.Context, service, action string, input map[string]any) error {
	return cfnComputeRun(ctx, f.commands, service, action, input)
}
func (f *kafkaSCRAMFixture) key() string {
	f.t.Helper()
	out, err := cfnComputeCall[kmsapi.CreateKeyOutput](f.root, f.commands, "kms", "CreateKey", map[string]any{})
	if err != nil {
		f.t.Fatal(err)
	}
	return string(*out.KeyMetadata.Arn)
}
func (f *kafkaSCRAMFixture) secretARN(key, name string) string {
	f.t.Helper()
	out, err := cfnComputeCall[secretapi.CreateSecretOutput](f.root, f.commands, "secretsmanager", "CreateSecret", map[string]any{"Name": "AmazonMSK_" + name, "KmsKeyId": key, "SecretString": `{"username":"alice","password":"first-password"}`})
	if err != nil {
		f.t.Fatal(err)
	}
	return string(*out.ARN)
}
func (f *kafkaSCRAMFixture) cluster() kafka.ClusterRecord {
	f.t.Helper()
	var row kafka.ClusterRecord
	if err := f.clusters.View(f.root, func(r kafka.Reader) error { var err error; row, err = r.Cluster(f.clusterARN); return err }); err != nil {
		f.t.Fatal(err)
	}
	return row
}
func (f *kafkaSCRAMFixture) associate(ctx context.Context, secrets ...string) error {
	return f.run(ctx, "kafka", "BatchAssociateScramSecret", map[string]any{"ClusterArn": f.clusterARN, "SecretArnList": secrets})
}
func (f *kafkaSCRAMFixture) grants(key string) []kmsapi.GrantListEntry {
	f.t.Helper()
	out, err := cfnComputeCall[kmsapi.ListGrantsOutput](f.root, f.commands, "kms", "ListGrants", map[string]any{"KeyId": key})
	if err != nil {
		f.t.Fatal(err)
	}
	return out.Grants
}
func (f *kafkaSCRAMFixture) policy(secret string) string {
	f.t.Helper()
	out, rejected := f.secret.GetResourcePolicy(f.root, &secretapi.GetResourcePolicyInput{SecretId: new(secretapi.SecretIdType(secret))})
	if rejected != nil {
		f.t.Fatal(rejected)
	}
	if out.ResourcePolicy == nil {
		return ""
	}
	return string(*out.ResourcePolicy)
}
func (f *kafkaSCRAMFixture) load(cluster, incarnation string, association kafka.SCRAMAssociation) (kafka.SCRAMUser, error) {
	var user kafka.SCRAMUser
	var rejected error
	err := f.clusters.Update(f.root, func(tx kafka.Transaction) error {
		user, rejected = f.adapter.LoadSCRAM(tx.Context(), cluster, incarnation, association)
		return nil
	})
	if err != nil {
		return kafka.SCRAMUser{}, err
	}
	return user, rejected
}
func kafkaSCRAMRequireDenied(t *testing.T, err error) {
	t.Helper()
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || !strings.Contains(rejected.Code, "AccessDenied") {
		t.Fatalf("expected current-authority denial, got %v", err)
	}
}

func TestKafkaSCRAMGrantRotationReassociationAndRetirement(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newKafkaSCRAMFixture(t, backend)
			key := f.key()
			secret := f.secretARN(key, "lifecycle")
			legacy := kafka.SCRAMAssociation{SecretARN: secret}
			if err := f.clusters.Update(f.root, func(tx kafka.Transaction) error {
				row, err := tx.Cluster(f.clusterARN)
				if err != nil {
					return err
				}
				row.Secrets = []kafka.SCRAMAssociation{legacy}
				return tx.PutCluster(row)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.load(f.clusterARN, "immutable-cluster", legacy); err == nil {
				t.Fatal("policy-only legacy association gained KMS authority")
			}
			if err := f.associate(f.caller, secret); err != nil {
				t.Fatal(err)
			}
			association := f.cluster().Secrets[0]
			if association.SecretARN != secret || association.KMSKeyARN != key || association.GrantID == "" || association.Incarnation != "immutable-cluster" {
				t.Fatalf("missing durable grant ownership: %#v", association)
			}
			grants := f.grants(key)
			if len(grants) != 1 || string(*grants[0].GranteePrincipal) != "kafka.amazonaws.com" || string(*grants[0].RetiringPrincipal) != "kafka.amazonaws.com" || !slices.Equal(grants[0].Operations, kmsapi.GrantOperationList{"Decrypt", "DescribeKey"}) || len(grants[0].Constraints.EncryptionContextSubset) != 1 || string(grants[0].Constraints.EncryptionContextSubset["SecretARN"]) != secret {
				t.Fatalf("unexpected local least-privilege grant: %#v", grants)
			}
			keyPolicy, err := cfnComputeCall[kmsapi.GetKeyPolicyOutput](f.root, f.commands, "kms", "GetKeyPolicy", map[string]any{"KeyId": key, "PolicyName": "default"})
			if err != nil || strings.Contains(string(*keyPolicy.Policy), "kafka.amazonaws.com") {
				t.Fatal("association rewrote customer key policy", err)
			}
			policy := f.policy(secret)
			if !strings.Contains(policy, f.clusterARN) || !strings.Contains(policy, "aws:SourceAccount") || !strings.Contains(policy, "secretsmanager:DescribeSecret") {
				t.Fatal("secret policy lost exact source/current metadata scope", policy)
			}
			user, err := f.load(f.clusterARN, association.Incarnation, association)
			if err != nil || user.Password != "first-password" {
				t.Fatalf("real grant did not decrypt current secret: %#v %v", user, err)
			}
			_, err = f.load(strings.Replace(f.clusterARN, "/scram/", "/foreign/", 1), association.Incarnation, association)
			kafkaSCRAMRequireDenied(t, err)
			if _, err = f.load(f.clusterARN, "replacement-incarnation", association); err == nil {
				t.Fatal("stale cluster incarnation read a retained grant")
			}
			if err = f.adapter.ReleaseSCRAM(f.root, f.clusterARN, "replacement-incarnation", association); err == nil {
				t.Fatal("stale cluster incarnation retired a retained grant")
			}
			if err := f.run(f.root, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": secret, "SecretString": `{"username":"alice","password":"rotated-password"}`, "ClientRequestToken": strings.Repeat("b", 32)}); err != nil {
				t.Fatal(err)
			}
			f.reopen()
			if got := f.cluster().Secrets[0]; got != association {
				t.Fatalf("reopen lost association identity: %#v", got)
			}
			user, err = f.load(f.clusterARN, association.Incarnation, association)
			if err != nil || user.Password != "rotated-password" {
				t.Fatal("same-key AWSCURRENT rotation failed", err)
			}
			var restricted map[string]any
			if err := json.Unmarshal([]byte(string(*keyPolicy.Policy)), &restricted); err != nil {
				t.Fatal(err)
			}
			restricted["Statement"] = append(restricted["Statement"].([]any), map[string]any{
				"Effect": "Deny", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*",
				"Condition": map[string]any{"StringEquals": map[string]string{"kms:EncryptionContext:SecretARN": secret}},
			})
			document, err := json.Marshal(restricted)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.run(f.root, "kms", "PutKeyPolicy", map[string]any{"KeyId": key, "PolicyName": "default", "Policy": string(document)}); err != nil {
				t.Fatal(err)
			}
			_, err = f.load(f.clusterARN, association.Incarnation, association)
			kafkaSCRAMRequireDenied(t, err)
			if err := f.run(f.root, "kms", "PutKeyPolicy", map[string]any{"KeyId": key, "PolicyName": "default", "Policy": string(*keyPolicy.Policy)}); err != nil {
				t.Fatal(err)
			}
			if err := f.run(f.root, "kms", "DisableKey", map[string]any{"KeyId": key}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.load(f.clusterARN, association.Incarnation, association); err == nil {
				t.Fatal("disabled key retained native credential authority")
			}
			if err := f.run(f.root, "kms", "EnableKey", map[string]any{"KeyId": key}); err != nil {
				t.Fatal(err)
			}
			if err := f.run(f.root, "kms", "RevokeGrant", map[string]any{"KeyId": key, "GrantId": association.GrantID}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.load(f.clusterARN, association.Incarnation, association); err == nil {
				t.Fatal("revoked grant borrowed customer root key policy")
			}
			if err := f.associate(f.caller, secret); err != nil {
				t.Fatal("explicit reassociation could not replace revoked grant", err)
			}
			association = f.cluster().Secrets[0]
			otherKey := f.key()
			inspection, err := cfnComputeCall[kmsapi.CreateGrantOutput](f.root, f.commands, "kms", "CreateGrant", map[string]any{"KeyId": otherKey, "GranteePrincipal": "kafka.amazonaws.com", "Operations": []string{"DescribeKey"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.run(f.root, "secretsmanager", "UpdateSecret", map[string]any{"SecretId": secret, "KmsKeyId": otherKey}); err != nil {
				t.Fatal(err)
			}
			// Even independent permission to inspect the new key must not let an
			// old association fall back to the prior key's retained envelope.
			if _, err := f.load(f.clusterARN, association.Incarnation, association); err == nil || !strings.Contains(err.Error(), "re-associate") {
				t.Fatal("CMK change did not enforce the canonical association fence", err)
			}
			if err := f.run(f.root, "kms", "RevokeGrant", map[string]any{"KeyId": otherKey, "GrantId": string(*inspection.GrantId)}); err != nil {
				t.Fatal(err)
			}
			foreign, err := cfnComputeCall[kmsapi.CreateGrantOutput](f.root, f.commands, "kms", "CreateGrant", map[string]any{"KeyId": key, "GranteePrincipal": "kafka.amazonaws.com", "RetiringPrincipal": "kafka.amazonaws.com", "Operations": []string{"Decrypt"}, "Name": "unowned-grant", "Constraints": map[string]any{"EncryptionContextSubset": map[string]string{"SecretARN": secret}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.associate(f.caller, secret); err != nil {
				t.Fatal(err)
			}
			association = f.cluster().Secrets[0]
			if association.KMSKeyARN != otherKey || len(f.grants(otherKey)) != 1 {
				t.Fatal("reassociation did not bind the current CMK")
			}
			remaining := f.grants(key)
			if len(remaining) != 1 || string(*remaining[0].GrantId) != string(*foreign.GrantId) {
				t.Fatal("reassociation retired a foreign grant")
			}
			user, err = f.load(f.clusterARN, association.Incarnation, association)
			if err != nil || user.Password != "rotated-password" {
				t.Fatal("reassociated current key did not decrypt", err)
			}
			// The old key deliberately retains a foreign Decrypt grant and an
			// envelope. Neither may replace current-key authority after repair.
			if err := f.run(f.root, "kms", "DisableKey", map[string]any{"KeyId": otherKey}); err != nil {
				t.Fatal(err)
			}
			f.reopen()
			public, rejected := f.secret.GetSecretValue(f.root, &secretapi.GetSecretValueInput{SecretId: new(secretapi.SecretIdType(secret))})
			if rejected != nil || public.SecretString == nil || !strings.Contains(string(*public.SecretString), "rotated-password") {
				t.Fatal("unconstrained public historical-envelope fallback changed", rejected)
			}
			if _, err := f.load(f.clusterARN, association.Incarnation, association); err == nil {
				t.Fatal("disabled current CMK fell back to a foreign old-key grant")
			}
			if err := f.run(f.root, "kms", "EnableKey", map[string]any{"KeyId": otherKey}); err != nil {
				t.Fatal(err)
			}
			f.setDeny(`{"Statement":{"Effect":"Deny","Action":"kms:Decrypt","Resource":"` + otherKey + `"}}`)
			_, err = f.adapter.ResolveSCRAM(f.caller, f.clusterARN, secret)
			kafkaSCRAMRequireDenied(t, err)
			f.setDeny("")
			currentPolicy, err := cfnComputeCall[kmsapi.GetKeyPolicyOutput](f.root, f.commands, "kms", "GetKeyPolicy", map[string]any{"KeyId": otherKey, "PolicyName": "default"})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.run(f.root, "kms", "PutKeyPolicy", map[string]any{"KeyId": otherKey, "PolicyName": "default", "Policy": string(document)}); err != nil {
				t.Fatal(err)
			}
			_, err = f.load(f.clusterARN, association.Incarnation, association)
			kafkaSCRAMRequireDenied(t, err)
			if err := f.run(f.root, "kms", "PutKeyPolicy", map[string]any{"KeyId": otherKey, "PolicyName": "default", "Policy": string(*currentPolicy.Policy)}); err != nil {
				t.Fatal(err)
			}
			if err := f.run(f.caller, "kafka", "BatchDisassociateScramSecret", map[string]any{"ClusterArn": f.clusterARN, "SecretArnList": []string{secret}}); err != nil {
				t.Fatal(err)
			}
			if len(f.cluster().Secrets) != 0 || len(f.grants(otherKey)) != 0 || f.policy(secret) != "" || len(f.grants(key)) != 1 {
				t.Fatal("disassociation leaked owned authority or retired foreign authority")
			}
		})
	}
}

func TestKafkaSCRAMAssociationFailureRollsBackGrantPolicyAndIntent(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newKafkaSCRAMFixture(t, backend)
			key := f.key()
			secret := f.secretARN(key, "rollback")
			original := f.cluster()
			f.setDeny(`{"Statement":{"Effect":"Deny","Action":"kms:CreateGrant","Resource":"*"}}`)
			kafkaSCRAMRequireDenied(t, f.associate(f.caller, secret))
			if len(f.grants(key)) != 0 || f.policy(secret) != "" || len(f.cluster().Secrets) != 0 || f.cluster().Version != original.Version {
				t.Fatal("denied grant provision mutated association state")
			}
			f.setDeny(`{"Statement":{"Effect":"Deny","Action":"secretsmanager:PutResourcePolicy","Resource":"*"}}`)
			kafkaSCRAMRequireDenied(t, f.associate(f.caller, secret))
			if len(f.grants(key)) != 0 || f.policy(secret) != "" || len(f.cluster().Secrets) != 0 {
				t.Fatal("policy failure orphaned a newly created grant")
			}
			page, err := f.events.LookupAPICalls(f.root, journal.APICallQuery{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", Start: f.clock.Now().Add(-time.Minute), End: f.clock.Now().Add(time.Minute), Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			deniedGrant, completedGrant, deniedParent := false, false, false
			for _, event := range page.Events {
				call := event.APICallCompleted
				if call == nil {
					continue
				}
				if call.EventName == "CreateGrant" && call.Identity.PrincipalID == f.user.UserId {
					deniedGrant = deniedGrant || call.ErrorCode != ""
					completedGrant = completedGrant || call.ErrorCode == ""
				}
				if call.EventName == "BatchAssociateScramSecret" && call.ErrorCode != "" {
					deniedParent = true
				}
				encoded, _ := json.Marshal(call)
				if strings.Contains(string(encoded), "first-password") {
					t.Fatal("audit exposed SCRAM plaintext")
				}
			}
			if !deniedGrant || !completedGrant || !deniedParent {
				t.Fatalf("rollback lost actual child/parent API outcomes: deniedGrant=%v completedGrant=%v deniedParent=%v", deniedGrant, completedGrant, deniedParent)
			}
			f.setDeny("")
			if err := f.associate(f.caller, secret); err != nil {
				t.Fatal(err)
			}
			association := f.cluster().Secrets[0]
			policy := f.policy(secret)
			f.setDeny(`{"Statement":{"Effect":"Deny","Action":"kms:RetireGrant","Resource":"*"}}`)
			kafkaSCRAMRequireDenied(t, f.run(f.caller, "kafka", "BatchDisassociateScramSecret", map[string]any{"ClusterArn": f.clusterARN, "SecretArnList": []string{secret}}))
			kafkaSCRAMRequireDenied(t, f.associate(f.caller, secret))
			kafkaSCRAMRequireDenied(t, f.run(f.caller, "kafka", "DeleteCluster", map[string]any{"ClusterArn": f.clusterARN}))
			if f.cluster().Secrets[0] != association || f.policy(secret) != policy || len(f.grants(key)) != 1 || f.cluster().State != "ACTIVE" {
				t.Fatal("denied retirement erased desired state, policy or retained grant")
			}
			f.setDeny(`{"Statement":{"Effect":"Deny","Action":"secretsmanager:DeleteResourcePolicy","Resource":"*"}}`)
			kafkaSCRAMRequireDenied(t, f.run(f.caller, "kafka", "BatchDisassociateScramSecret", map[string]any{"ClusterArn": f.clusterARN, "SecretArnList": []string{secret}}))
			f.reopen()
			if f.cluster().Secrets[0] != association || f.policy(secret) != policy || len(f.grants(key)) != 1 {
				t.Fatal("policy-removal failure did not restore retired grant across reopen")
			}
			if _, err := f.load(f.clusterARN, association.Incarnation, association); err != nil {
				t.Fatal("rollback lost real decrypt authority", err)
			}
			if err := f.run(f.root, "kafka", "DeleteCluster", map[string]any{"ClusterArn": f.clusterARN}); err != nil {
				t.Fatal(err)
			}
			if len(f.cluster().Secrets) != 0 || len(f.grants(key)) != 0 || f.policy(secret) != "" || f.cluster().State != "DELETING" {
				t.Fatal("cluster deletion did not retire its retained SCRAM authority")
			}
		})
	}
}

func TestKafkaSCRAMBatchFailureAndAliasRejection(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newKafkaSCRAMFixture(t, backend)
			first, second := f.key(), f.key()
			a, b := f.secretARN(first, "first"), f.secretARN(second, "second")
			deny, _ := json.Marshal(map[string]any{"Statement": map[string]any{"Effect": "Deny", "Action": "kms:CreateGrant", "Resource": second}})
			f.setDeny(string(deny))
			kafkaSCRAMRequireDenied(t, f.associate(f.caller, a, b))
			if len(f.grants(first)) != 0 || len(f.grants(second)) != 0 || f.policy(a) != "" || f.policy(b) != "" || len(f.cluster().Secrets) != 0 {
				t.Fatal("later batch failure committed earlier secret authority")
			}
			if err := f.run(f.root, "kms", "CreateAlias", map[string]any{"AliasName": "alias/scram-unsupported", "TargetKeyId": first}); err != nil {
				t.Fatal(err)
			}
			if err := f.run(f.root, "secretsmanager", "UpdateSecret", map[string]any{"SecretId": a, "KmsKeyId": "alias/scram-unsupported"}); err != nil {
				t.Fatal(err)
			}
			out, err := cfnComputeCall[kafkaapi.BatchAssociateScramSecretOutput](f.root, f.commands, "kafka", "BatchAssociateScramSecret", map[string]any{"ClusterArn": f.clusterARN, "SecretArnList": []string{a}})
			if err != nil || len(out.UnprocessedScramSecrets) != 1 || string(*out.UnprocessedScramSecrets[0].ErrorCode) != "BadRequestException" || len(f.grants(first)) != 0 {
				t.Fatal("SCRAM association accepted undocumented alias authority", err)
			}
		})
	}
}
