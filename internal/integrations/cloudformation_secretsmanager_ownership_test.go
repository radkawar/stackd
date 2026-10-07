package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/kms"
	"stackd/internal/services/lambda"
	"stackd/internal/services/secretsmanager"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	keydb "stackd/storage/sqlite/kms"
	lambdadb "stackd/storage/sqlite/lambda"
	secretdb "stackd/storage/sqlite/secretsmanager"
)

type cfnSecretCommands struct {
	*secretsmanager.Service
	lose         string
	beforeAction string
	before       func()
}

func (c *cfnSecretCommands) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	action := string(r.Operation.Name)
	if c.before != nil && action == c.beforeAction {
		fn := c.before
		c.before = nil
		fn()
	}
	out, err := c.Service.ExecuteCommand(ctx, r)
	if err == nil && action == c.lose {
		c.lose = ""
		return nil, &awswire.Error{Code: "InternalServiceError", Message: "lost admitted reply", StatusCode: 500}
	}
	return out, err
}

type cfnSecretFixture struct {
	t           *testing.T
	ctx         context.Context
	db          *sql.DB
	path        string
	repository  secretsmanager.Repository
	keys        kms.Storage
	functions   lambda.Repository
	owner       *secretsmanager.Service
	keyOwner    *kms.Service
	lambdaOwner *lambda.Service
	executor    *cfnSecretCommands
	commands    StepFunctionsCommands
	source      *clock.Manual
}

func newCFNSecretFixture(t *testing.T, backend string) *cfnSecretFixture {
	f := &cfnSecretFixture{t: t, ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"}), source: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))}
	// The owner fixture calls real KMS directly; the assembled controller uses
	// ServiceDataKeys with its real IAM recorder for authenticated HTTP callers.
	f.ctx = kms.WithViaService(f.ctx, "secretsmanager")
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "secrets.sqlite")
		f.open()
	} else {
		d := memory.NewDomain()
		f.repository = secretsmanager.NewMemoryRepository(d)
		f.keys = kms.NewMemoryStorage(d)
		f.functions = lambda.NewMemoryRepository(d)
	}
	f.start()
	t.Cleanup(func() {
		f.close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	key := lambda.FunctionKey{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "rotation"}
	if err := f.functions.Update(f.ctx, func(tx lambda.Transaction) error {
		return tx.PutFunction(lambda.FunctionRecord{Key: key, Runtime: "python3.12", Handler: "index.handler", Role: "arn:aws:iam::111111111111:role/execution", State: "Active", Architecture: "x86_64", Timeout: 3, MemoryMB: 128, EphemeralMB: 512, Revision: "native", DeploymentRevision: "deployment", Modified: f.source.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	f.call("lambda", "AddPermission", map[string]any{"FunctionName": "rotation", "StatementId": "secrets", "Action": "lambda:InvokeFunction", "Principal": "secretsmanager.amazonaws.com"})
	return f
}
func (f *cfnSecretFixture) open() {
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	f.repository = secretdb.New(f.db)
	f.keys = keydb.New(f.db)
	f.functions = lambdadb.New(f.db)
}
func (f *cfnSecretFixture) start() {
	f.keyOwner = kms.NewWithConfig(kms.Config{Storage: f.keys, Clock: f.source})
	f.lambdaOwner = lambda.New(lambda.Config{Repository: f.functions, Clock: f.source})
	f.owner = secretsmanager.New(secretsmanager.Config{Repository: f.repository, Clock: f.source, Keys: f.keyOwner, Rotation: SecretRotation{Lambda: f.lambdaOwner}})
	f.executor = &cfnSecretCommands{Service: f.owner}
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"secretsmanager": f.executor, "lambda": f.lambdaOwner})
}
func (f *cfnSecretFixture) close() {
	_ = f.owner.Close()
	_ = f.lambdaOwner.Close()
	_ = f.keyOwner.Close()
}
func (f *cfnSecretFixture) reopen() {
	f.close()
	if f.db != nil {
		_ = f.db.Close()
		f.open()
	}
	f.start()
}
func (f *cfnSecretFixture) call(service, action string, in map[string]any) map[string]any {
	f.t.Helper()
	body, _ := json.Marshal(in)
	out, err := f.commands.Call(f.ctx, service, action, body)
	if err != nil {
		f.t.Fatalf("%s: %v", action, err)
	}
	encoded, _ := json.Marshal(out.Output)
	var value map[string]any
	if len(encoded) > 0 && json.Unmarshal(encoded, &value) != nil {
		f.t.Fatalf("response: %s", encoded)
	}
	return value
}
func cfnSecretRequest(kind string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: "AWS::SecretsManager::" + kind, StackID: "stack", StackName: "stack", LogicalID: kind, Token: "incarnation-a", Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Properties: p}
}
func (f *cfnSecretFixture) value(id string) map[string]any {
	f.t.Helper()
	out := f.call("secretsmanager", "GetSecretValue", map[string]any{"SecretId": id})
	var value map[string]any
	if json.Unmarshal([]byte(out["SecretString"].(string)), &value) != nil {
		f.t.Fatal("not JSON")
	}
	return value
}

func TestCFNSecretPrivateClaimRecoveryAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSecretFixture(t, backend)
			r := cfnSecretRequest("Secret", cloudformation.Properties{"Name": "owned", "SecretString": `{"username":"user","password":"first"}`})
			h := cfnSecret{f.commands}
			// Secrets Manager excludes ':' from tags; reject the old public
			// marker spelling instead of widening its native contract.
			rawTags, err := json.Marshal(map[string]any{"Name": "owned", "SecretString": "{}", "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))})
			if err != nil {
				t.Fatal(err)
			}
			if _, rejected := f.commands.Call(f.ctx, "secretsmanager", "CreateSecret", rawTags); rejected == nil || rejected.Code != "InvalidParameterException" {
				t.Fatalf("invalid public marker admitted: %v", rejected)
			}
			forgedTags := map[string]string{"stackd-cloudformation-incarnation": r.Token, "owner": cfnMessagingHash(cfnMessagingMarker(r))}
			outsider := f.call("secretsmanager", "CreateSecret", map[string]any{"Name": "owned", "SecretString": "{}", "Tags": cfnComputeTagList(forgedTags)})
			foreign := outsider["ARN"].(string)
			if out, err := h.Create(f.ctx, r); err == nil || out.PhysicalID != "" {
				t.Fatalf("counterfeit adopted: %+v %v", out, err)
			}
			stale := r
			stale.PhysicalID = foreign
			if err := h.Delete(f.ctx, stale); err == nil {
				t.Fatal("counterfeit deleted")
			}
			f.call("secretsmanager", "DescribeSecret", map[string]any{"SecretId": foreign})
			f.call("secretsmanager", "DeleteSecret", map[string]any{"SecretId": foreign, "ForceDeleteWithoutRecovery": true})
			f.executor.lose = "CreateSecret"
			if _, err := h.Create(f.ctx, r); err == nil {
				t.Fatal("lost response not injected")
			}
			created, err := h.RecoverCreation(f.ctx, r)
			if err != nil || created.PhysicalID == "" {
				t.Fatalf("recovery: %+v %v", created, err)
			}
			f.reopen()
			h = cfnSecret{f.commands}
			recovered, err := h.Create(f.ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("reopen recovery: %+v %v", recovered, err)
			}
			r.PhysicalID = created.PhysicalID
			unprivileged := awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:user/outsider", PrincipalID: "outsider"})
			if _, err := h.RecoverCreation(unprivileged, r); err == nil || cfnSecretMissing(err) {
				t.Fatalf("private recovery bypassed current IAM: %v", err)
			}
			if _, err := h.Update(unprivileged, r); err == nil {
				t.Fatal("private mutation bypassed current IAM")
			}
			f.call("secretsmanager", "TagResource", map[string]any{"SecretId": r.PhysicalID, "Tags": cfnComputeTagList(map[string]string{"stackd-cloudformation-incarnation": "counterfeit"})})
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"Name": "owned", "SecretString": `{"username":"user","password":"first"}`, "Description": "private"}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			p, err := h.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(p)
			if strings.Contains(string(body), "Ownership") || strings.Contains(string(body), "cfn_owner") {
				t.Fatalf("claim leaked: %s", body)
			}
			f.call("secretsmanager", "DeleteSecret", map[string]any{"SecretId": r.PhysicalID, "ForceDeleteWithoutRecovery": true})
			recreated := f.call("secretsmanager", "CreateSecret", map[string]any{"Name": "owned", "SecretString": "{}", "Tags": cfnComputeTagList(forgedTags)})
			newARN := recreated["ARN"].(string)
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatalf("stale exact ARN delete: %v", err)
			}
			r.PhysicalID = newARN
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("foreign new ARN accepted copied owner tags")
			}
			f.reopen()
			f.call("secretsmanager", "DescribeSecret", map[string]any{"SecretId": newARN})
			r.CloudControl = true
			h = cfnSecret{f.commands}
			if _, err := h.Create(f.ctx, r); err == nil {
				t.Fatal("CC create adopted outsider")
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatalf("CC direct delete: %v", err)
			}
		})
	}
}

func TestCFNSecretPolicyPrivateEdgeIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSecretFixture(t, backend)
			parent, err := (cfnSecret{f.commands}).Create(f.ctx, cfnSecretRequest("Secret", cloudformation.Properties{"Name": "parent"}))
			if err != nil {
				t.Fatal(err)
			}
			document := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}}}
			r := cfnSecretRequest("ResourcePolicy", cloudformation.Properties{"SecretId": parent.PhysicalID, "ResourcePolicy": document})
			h := cfnSecretPolicy{f.commands}
			raw, _ := json.Marshal(document)
			f.call("secretsmanager", "PutResourcePolicy", map[string]any{"SecretId": parent.PhysicalID, "ResourcePolicy": string(raw)})
			f.call("secretsmanager", "TagResource", map[string]any{"SecretId": parent.PhysicalID, "Tags": cfnComputeTagList(map[string]string{"stackd-cloudformation-policy": cfnMessagingHash(cfnMessagingMarker(r))})})
			if out, err := h.Create(f.ctx, r); err == nil || out.PhysicalID != "" {
				t.Fatalf("borrowed parent/forged policy claim: %+v %v", out, err)
			}
			f.call("secretsmanager", "DeleteResourcePolicy", map[string]any{"SecretId": parent.PhysicalID})
			f.executor.lose = "PutResourcePolicy"
			created, err := h.Create(f.ctx, r)
			if err == nil || created.PhysicalID != parent.PhysicalID {
				t.Fatalf("admitted error identity: %+v %v", created, err)
			}
			f.reopen()
			h = cfnSecretPolicy{f.commands}
			again, err := h.RecoverCreation(f.ctx, r)
			if err != nil || again.PhysicalID != parent.PhysicalID {
				t.Fatalf("edge reopen: %+v %v", again, err)
			}
			r.PhysicalID = parent.PhysicalID
			f.call("secretsmanager", "DeleteResourcePolicy", map[string]any{"SecretId": parent.PhysicalID})
			f.call("secretsmanager", "PutResourcePolicy", map[string]any{"SecretId": parent.PhysicalID, "ResourcePolicy": string(raw)})
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			out := f.call("secretsmanager", "GetResourcePolicy", map[string]any{"SecretId": parent.PhysicalID})
			if out["ResourcePolicy"] == nil {
				t.Fatal("independent policy deleted")
			}
			if _, err := h.Update(f.ctx, r); err == nil {
				t.Fatal("independent policy replaced")
			}
			r.CloudControl = true
			if _, err := h.Create(f.ctx, r); err == nil {
				t.Fatal("CC create adopted policy")
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNSecretRotationPrivateNativeSchedule(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSecretFixture(t, backend)
			secret := f.call("secretsmanager", "CreateSecret", map[string]any{"Name": "rotation", "SecretString": "{}"})["ARN"].(string)
			r := cfnSecretRequest("RotationSchedule", cloudformation.Properties{"SecretId": secret, "RotationLambdaARN": "arn:aws:lambda:us-east-1:111111111111:function:rotation", "RotationRules": map[string]any{"AutomaticallyAfterDays": 1}})
			h := cfnSecretRotation{f.commands}
			created, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			f.reopen()
			h = cfnSecretRotation{f.commands}
			recovered, err := h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("schedule recovery: %+v %v", recovered, err)
			}
			r.PhysicalID = secret
			if err := f.repository.View(f.ctx, func(reader secretsmanager.Reader) error {
				row, err := reader.Secret(secretsmanager.SecretKey{Scope: secretsmanager.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "rotation"})
				if err != nil {
					return err
				}
				work, err := reader.Rotation(row.Key)
				if err == nil && (work.ARN != secret || work.Token != cfnSecretToken(r, "rotation") || work.Step != 0) {
					t.Fatalf("native rotation job lost: %+v", work)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			wrong := r
			wrong.Token = "outsider"
			f.call("secretsmanager", "TagResource", map[string]any{"SecretId": secret, "Tags": cfnComputeTagList(map[string]string{"stackd-cloudformation-rotation": cfnMessagingHash(cfnMessagingMarker(wrong))})})
			if _, err := h.Update(f.ctx, wrong); err == nil {
				t.Fatal("forged rotation marker overwrote native schedule")
			}
			if err := h.Delete(f.ctx, wrong); err != nil {
				t.Fatal(err)
			}
			if got := f.call("secretsmanager", "DescribeSecret", map[string]any{"SecretId": secret}); got["RotationEnabled"] != true {
				t.Fatal("foreign cleanup canceled real schedule")
			}
		})
	}
}

func TestCFNSecretAttachmentPrivateAtomicMetadata(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSecretFixture(t, backend)
			secret := f.call("secretsmanager", "CreateSecret", map[string]any{"Name": "attachment", "SecretString": `{"username":"user","password":"first"}`})["ARN"].(string)
			r := cfnSecretRequest("SecretTargetAttachment", cloudformation.Properties{"SecretId": secret, "TargetId": "database", "TargetType": "AWS::RDS::DBInstance"})
			h := cfnSecretAttachment{f.commands}
			metadata := `{"engine":"postgres","host":"database.native","port":5432,"dbInstanceIdentifier":"database"}`
			effect := func(ctx context.Context, arn string) error {
				return cfnComputeRun(ctx, f.commands, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": arn, "SecretString": metadata})
			}
			admitted, err := h.aspect().create(f.ctx, r, effect)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			f.reopen()
			h = cfnSecretAttachment{f.commands}
			if recovered, err := h.RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != secret {
				t.Fatalf("attachment reopen: %+v %v", recovered, err)
			}
			// Credential edits which leave connection metadata intact keep the live edge.
			f.call("secretsmanager", "PutSecretValue", map[string]any{"SecretId": secret, "SecretString": `{"username":"user","password":"second","engine":"postgres","host":"database.native","port":5432,"dbInstanceIdentifier":"database"}`})
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			v := f.value(secret)
			if v["password"] != "second" || v["username"] != "user" || v["host"] != nil {
				t.Fatalf("native metadata delete replaced credentials: %+v", v)
			}
			effect = func(ctx context.Context, arn string) error {
				return cfnComputeRun(ctx, f.commands, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": arn, "SecretString": metadata})
			}
			if _, err := h.aspect().create(f.ctx, r, effect); err != nil {
				t.Fatal(err)
			}
			f.call("secretsmanager", "PutSecretValue", map[string]any{"SecretId": secret, "SecretString": `{"password":"foreign"}`})
			f.call("secretsmanager", "PutSecretValue", map[string]any{"SecretId": secret, "SecretString": `{"password":"foreign","engine":"postgres","host":"database.native","port":5432,"dbInstanceIdentifier":"database"}`})
			f.call("secretsmanager", "TagResource", map[string]any{"SecretId": secret, "Tags": cfnComputeTagList(map[string]string{"stackd-cloudformation-target-attachment": cfnMessagingHash(cfnMessagingMarker(r))})})
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if v := f.value(secret); v["dbInstanceIdentifier"] != "database" || v["password"] != "foreign" {
				t.Fatalf("recreated foreign attachment destroyed: %+v", v)
			}
			if _, err := h.aspect().create(f.ctx, r, effect); err == nil {
				t.Fatal("independent recreated metadata adopted")
			}
			r.CloudControl = true
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if v := f.value(secret); v["password"] != "foreign" || v["host"] != nil {
				t.Fatalf("CC metadata delete corrupted value: %+v", v)
			}
		})
	}
}

func TestCFNSecretPrivateEdgeMutationTimeFence(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSecretFixture(t, backend)
			secret := f.call("secretsmanager", "CreateSecret", map[string]any{"Name": "race", "SecretString": `{"password":"owned"}`})["ARN"].(string)
			policy := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}}}
			r := cfnSecretRequest("ResourcePolicy", cloudformation.Properties{"SecretId": secret, "ResourcePolicy": policy})
			h := cfnSecretPolicy{f.commands}
			created, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			raw, _ := json.Marshal(policy)
			f.executor.beforeAction = "DeleteResourcePolicy"
			f.executor.before = func() {
				f.call("secretsmanager", "PutResourcePolicy", map[string]any{"SecretId": secret, "ResourcePolicy": string(raw)})
			}
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("claim observation was used as mutation authority")
			}
			if f.call("secretsmanager", "GetResourcePolicy", map[string]any{"SecretId": secret})["ResourcePolicy"] == nil {
				t.Fatal("racing foreign policy removed")
			}
			f.call("secretsmanager", "DeleteResourcePolicy", map[string]any{"SecretId": secret})
			attachment := cfnSecretRequest("SecretTargetAttachment", cloudformation.Properties{"SecretId": secret, "TargetId": "database", "TargetType": "AWS::RDS::DBInstance"})
			a := cfnSecretAttachment{f.commands}
			effect := func(ctx context.Context, arn string) error {
				return cfnComputeRun(ctx, f.commands, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": arn, "SecretString": `{"engine":"postgres","host":"owned.native","port":5432,"dbInstanceIdentifier":"database"}`})
			}
			created, err = a.aspect().create(f.ctx, attachment, effect)
			if err != nil {
				t.Fatal(err)
			}
			attachment.PhysicalID = created.PhysicalID
			f.executor.beforeAction = "PutSecretValue"
			f.executor.before = func() {
				f.call("secretsmanager", "PutSecretValue", map[string]any{"SecretId": secret, "SecretString": `{"password":"foreign","engine":"postgres","host":"foreign.native","port":5432,"dbInstanceIdentifier":"database"}`})
			}
			if err := a.Delete(f.ctx, attachment); err == nil {
				t.Fatal("attachment mutation bypassed current private claim")
			}
			if v := f.value(secret); v["host"] != "foreign.native" || v["password"] != "foreign" {
				t.Fatalf("racing metadata destroyed: %+v", v)
			}
		})
	}
}
