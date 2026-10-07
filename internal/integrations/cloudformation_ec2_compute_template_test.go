package integrations

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	ssmapi "stackd/internal/awsapi/ssm"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/internal/services/ssm"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqliam "stackd/storage/sqlite/iam"
	sqlssm "stackd/storage/sqlite/ssm"
)

type cfnEC2ComputeOwnerExecutor struct {
	*ec2.Service
	execute cfnEC2ComputeTestExecutor
}

func (e cfnEC2ComputeOwnerExecutor) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	return e.execute(ctx, r)
}

func TestCFNEC2LaunchTemplateVersionRecoveryAndABA(t *testing.T) {
	owner := ec2.New(ec2.Config{Repository: ec2.NewMemoryRepository(memory.NewDomain())})
	t.Cleanup(func() { owner.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	loseReply := true
	versions := 0
	executor := cfnEC2ComputeTestExecutor(func(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
		out, err := owner.ExecuteCommand(ctx, req)
		if req.Operation.Name == "CreateLaunchTemplateVersion" && err == nil {
			versions++
			if loseReply {
				loseReply = false
				return nil, &awswire.Error{Code: "RequestTimeout", Message: "reply lost after the real owner committed", StatusCode: 504}
			}
		}
		return out, err
	})
	h := cfnEC2LaunchTemplate{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": cfnEC2ComputeOwnerExecutor{Service: owner, execute: executor}})}
	a := cloudformation.Properties{"LaunchTemplateName": "version-recovery", "LaunchTemplateData": map[string]any{"InstanceType": "t3.micro"}}
	b := cloudformation.Properties{"LaunchTemplateName": "version-recovery", "LaunchTemplateData": map[string]any{"InstanceType": "t3.small"}}
	r := cfnEC2ComputeTestRequest("AWS::EC2::LaunchTemplate")
	r.Properties = a
	initial, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = initial.PhysicalID
	r.Previous = a
	r.Properties = b
	if _, err := h.Update(ctx, r); err == nil {
		t.Fatal("lost native reply did not reach the CFN controller")
	}
	recovered, err := h.Update(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if versions != 1 || recovered.Attributes["LatestVersionNumber"] != "2" {
		t.Fatalf("retry appended a duplicate version: %d %+v", versions, recovered)
	}
	r.Previous = b
	r.Properties = a
	if _, err := h.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Previous = a
	r.Properties = b
	final, err := h.Update(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if versions != 3 || final.Attributes["LatestVersionNumber"] != "4" {
		t.Fatalf("ABA reused a historical version instead of restoring the latest: %d %+v", versions, final)
	}
	if ready, err := h.Stabilize(ctx, r); err != nil || !ready {
		t.Fatalf("latest native version does not reflect the desired data: %v %v", ready, err)
	}
	live, err := h.Read(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if !cfnEC2ComputeEqual(live["LaunchTemplateData"], b["LaunchTemplateData"]) {
		t.Fatalf("native latest version is stale: %+v", live)
	}
}

// These controls use real native owners and durable repositories. Dropping a
// committed reply is a transport fault, never a substitute runtime backend.
func TestCFNEC2ComputePrivateControlOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"LaunchTemplate", "KeyPair"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
				domain := memory.NewDomain()
				var repo ec2.Repository = ec2.NewMemoryRepository(domain)
				var parameters ssm.Repository = ssm.NewMemoryRepository(domain)
				var identities iam.Repository = iam.NewMemoryRepository(domain)
				var identity *iam.Service
				var db *sql.DB
				path := filepath.Join(t.TempDir(), "compute.sqlite")
				var owner *ec2.Service
				var secrets *ssm.Service
				var commands StepFunctionsCommands
				var h cloudformation.ResourceHandler
				loseReply := true
				creates := 0
				open := func() {
					if backend == "sqlite" {
						var err error
						db, err = sqlite.Open(ctx, path)
						if err != nil {
							t.Fatal(err)
						}
						repo = sqlec2.New(db)
						parameters = sqlssm.New(db)
						identities = sqliam.New(db)
					}
					identity = iam.NewWithConfig(iam.Config{Repository: identities})
					authorizer := authorization.New(identity, nil)
					owner = ec2.New(ec2.Config{Repository: repo, Authorizer: authorizer})
					secrets = ssm.New(ssm.Config{Repository: parameters, Authorizer: authorizer})
					executor := cfnEC2ComputeOwnerExecutor{Service: owner, execute: func(callctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
						out, err := owner.ExecuteCommand(callctx, req)
						if err == nil && (req.Operation.Name == "CreateLaunchTemplate" || req.Operation.Name == "ImportKeyPair") {
							creates++
							if loseReply {
								loseReply = false
								return nil, &awswire.Error{Code: "RequestTimeout", Message: "native commit reply lost", StatusCode: 504}
							}
						}
						return out, err
					}}
					commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": executor, "ssm": secrets, "iam": identity})
					h = CloudFormationEC2ComputeHandlers(commands)["AWS::EC2::"+kind]
				}
				closeOwners := func() {
					_ = owner.Close()
					_ = secrets.Close()
					_ = identity.Close()
					if db != nil {
						_ = db.Close()
					}
				}
				open()
				t.Cleanup(closeOwners)
				publicKey, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				sshPublic, err := ssh.NewPublicKey(publicKey)
				if err != nil {
					t.Fatal(err)
				}
				public := string(ssh.MarshalAuthorizedKey(sshPublic))
				r := cfnEC2ComputeTestRequest("AWS::EC2::" + kind)
				r.CloudControl = true
				tags := []any{map[string]any{"Key": "customer", "Value": "live"}, map[string]any{"Key": "stackd:cloudformation:incarnation", "Value": "customer-value"}}
				if kind == "KeyPair" {
					r.Properties = cloudformation.Properties{"KeyName": "private-control", "PublicKeyMaterial": public, "Tags": tags}
				} else {
					r.Properties = cloudformation.Properties{"LaunchTemplateName": "private-control", "LaunchTemplateData": map[string]any{"InstanceType": "t3.micro"}, "TagSpecifications": []any{map[string]any{"ResourceType": "launch-template", "Tags": tags}}}
				}
				if _, err := h.Create(ctx, r); err == nil || !strings.Contains(err.Error(), "RequestTimeout") {
					t.Fatalf("expected lost committed native reply, got %v", err)
				}
				recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = recovered.PhysicalID
				replay, err := h.Create(ctx, r)
				if err != nil || replay.PhysicalID != r.PhysicalID || creates != 1 {
					t.Fatalf("creation replay duplicated or adopted native state: %+v %v creates=%d", replay, err, creates)
				}
				r.CloudControl = false
				nativeID := r.PhysicalID
				if kind == "KeyPair" {
					nativeID = recovered.Attributes["KeyPairId"].(string)
				}
				reader := h.(cloudformation.ResourceReader)
				live, err := reader.Read(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "KeyPair" {
					if live["KeyPairId"] != nativeID || live["KeyName"] != r.PhysicalID {
						t.Fatalf("private read conflated key name and native identity: %+v", live)
					}
					observedPublic, _, _, _, err := ssh.ParseAuthorizedKey([]byte(live["PublicKeyMaterial"].(string)))
					if err != nil || string(observedPublic.Marshal()) != string(sshPublic.Marshal()) {
						t.Fatalf("private read lost imported public material: %+v %v", live, err)
					}
				}
				observedTags := live["Tags"]
				if kind == "LaunchTemplate" {
					observedTags = live["TagSpecifications"].([]any)[0].(map[string]any)["Tags"]
				}
				if !cfnEC2ComputeEqual(observedTags, tags) {
					t.Fatalf("customer stackd tags were hidden or replaced: %+v", observedTags)
				}
				wrong := r
				wrong.Token = "stale-incarnation"
				if _, err := reader.Read(ctx, wrong); err == nil {
					t.Fatal("foreign incarnation read privately claimed row")
				}
				if err := h.Delete(ctx, wrong); err == nil {
					t.Fatal("foreign incarnation deleted privately claimed row")
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, wrong); err == nil {
					t.Fatal("foreign incarnation recovered creation")
				}
				// Remove every customer tag. This neither revokes nor backfills ownership.
				if err := cfnComputeRun(ctx, commands, "ec2", "DeleteTags", map[string]any{"Resources": []string{nativeID}, "Tags": []map[string]string{{"Key": "customer"}, {"Key": "stackd:cloudformation:incarnation"}}}); err != nil {
					t.Fatal(err)
				}
				live, err = reader.Read(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				observedTags = live["Tags"]
				if kind == "LaunchTemplate" {
					observedTags = live["TagSpecifications"].([]any)[0].(map[string]any)["Tags"]
				}
				if !cfnEC2ComputeEqual(observedTags, []any{}) {
					t.Fatalf("private read backfilled public markers: %+v", observedTags)
				}
				if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, r); err != nil || out.PhysicalID != r.PhysicalID {
					t.Fatalf("removing tags revoked native recovery: %+v %v", out, err)
				}
				forged := map[string]string{"stackd:cloudformation:stack-id": r.StackID, "stackd:cloudformation:logical-id": r.LogicalID, "stackd:cloudformation:incarnation": r.Token}
				nativeCreate := func(name string) (string, string) {
					t.Helper()
					if kind == "KeyPair" {
						out, err := cfnComputeCall[api.ImportKeyPairResult](ctx, commands, "ec2", "ImportKeyPair", map[string]any{"KeyName": name, "PublicKeyMaterial": public, "TagSpecifications": []map[string]any{{"ResourceType": "key-pair", "Tags": cfnComputeTagList(forged)}}})
						if err != nil {
							t.Fatal(err)
						}
						return cfnComputeValue(out.KeyName), cfnComputeValue(out.KeyPairId)
					}
					out, err := cfnComputeCall[api.CreateLaunchTemplateResult](ctx, commands, "ec2", "CreateLaunchTemplate", map[string]any{"LaunchTemplateName": name, "LaunchTemplateData": map[string]any{"InstanceType": "t3.micro"}, "TagSpecifications": []map[string]any{{"ResourceType": "launch-template", "Tags": cfnComputeTagList(forged)}}})
					if err != nil {
						t.Fatal(err)
					}
					return cfnComputeValue(out.LaunchTemplate.LaunchTemplateId), cfnComputeValue(out.LaunchTemplate.LaunchTemplateId)
				}
				foreignID, foreignNativeID := nativeCreate("forged-public-owner")
				foreign := r
				foreign.PhysicalID = foreignID
				if _, err := reader.Read(ctx, foreign); err == nil {
					t.Fatal("forged public markers granted ownership")
				}
				if err := h.Delete(ctx, foreign); err == nil {
					t.Fatal("forged public markers granted deletion")
				}
				// A trusted context for one row cannot authorize writes to another row.
				deleteOperation := "DeleteLaunchTemplate"
				deleteInput := map[string]any{"LaunchTemplateId": foreignNativeID}
				if kind == "KeyPair" {
					deleteOperation = "DeleteKeyPair"
					deleteInput = map[string]any{"KeyPairId": foreignNativeID}
				}
				err = cfnComputeRun(ec2.WithCloudFormationMutation(ctx, r.Type, cfnEC2NativeIdentity(r), nativeID), commands, "ec2", deleteOperation, deleteInput)
				var rejected *awswire.Error
				if !errors.As(err, &rejected) || rejected.Code != "IncorrectState" {
					t.Fatalf("native context admitted a different actual row: %v", err)
				}
				visibleForeign := foreign
				visibleForeign.CloudControl = true
				if _, err := reader.Read(ctx, visibleForeign); err != nil {
					t.Fatalf("native wrong-target fence erased foreign row: %v", err)
				}
				wrong.Previous = wrong.Properties
				if _, err := h.Update(ctx, wrong); err == nil {
					t.Fatal("foreign incarnation updated privately claimed row")
				}
				// List must inspect each actual native row ID, not r.PhysicalID.
				listRequest := r
				listRequest.PhysicalID = "deliberately-not-a-row"
				rows, err := reader.List(ctx, listRequest)
				if err != nil || len(rows) != 1 || rows[0].Identifier != r.PhysicalID {
					t.Fatalf("list lost exact native row ownership: %+v %v", rows, err)
				}
				// Cloud Control native mutations retain a claim, but cannot acquire one.
				cc := r
				cc.CloudControl = true
				cc.Previous = cc.Properties
				if _, err := h.Update(ctx, cc); err != nil {
					t.Fatal(err)
				}
				if _, err := reader.Read(ctx, r); err != nil {
					t.Fatalf("ordinary CC update dropped claim: %v", err)
				}
				cc = foreign
				cc.CloudControl = true
				cc.Previous = cc.Properties
				if _, err := h.Update(ctx, cc); err != nil {
					t.Fatal(err)
				}
				if _, err := reader.Read(ctx, foreign); err == nil {
					t.Fatal("ordinary CC update acquired private claim")
				}
				for _, dimension := range []string{"partition", "account", "region"} {
					metadata := awsctx.FromContext(ctx)
					switch dimension {
					case "partition":
						metadata.Partition = "aws-cn"
					case "account":
						metadata.AccountID = "210987654321"
						metadata.PrincipalARN = "arn:aws:iam::210987654321:root"
						metadata.PrincipalID = "210987654321"
					case "region":
						metadata.Region = "us-west-2"
					}
					other := awsctx.WithMetadata(ctx, metadata)
					if _, err := reader.Read(other, r); err == nil {
						t.Fatalf("read crossed %s boundary", dimension)
					}
					if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(other, r); err == nil {
						t.Fatalf("receipt crossed %s boundary", dimension)
					}
				}
				deniedMetadata := awsctx.FromContext(ctx)
				deniedMetadata.PrincipalARN = "arn:aws:iam::123456789012:user/denied"
				deniedMetadata.PrincipalID = "denied"
				denied := awsctx.WithMetadata(ctx, deniedMetadata)
				if _, err := reader.Read(denied, r); err == nil {
					t.Fatal("private read bypassed current IAM")
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(denied, r); err == nil {
					t.Fatal("private receipt recovery bypassed current IAM")
				}
				if _, err := reader.List(denied, r); err == nil {
					t.Fatal("private list bypassed current IAM")
				}
				if err := h.Delete(denied, r); err == nil {
					t.Fatal("private delete bypassed current IAM")
				}
				err = cfnComputeRun(ec2.WithCloudFormationMutation(denied, r.Type, cfnEC2NativeIdentity(r), nativeID), commands, "ec2", deleteOperation, deleteInput)
				rejected = nil
				if !errors.As(err, &rejected) || rejected.Code != "UnauthorizedOperation" {
					t.Fatalf("native fence replaced current IAM denial: %v", err)
				}
				user, err := cfnComputeCall[iamapi.CreateUserResponse](ctx, commands, "iam", "CreateUser", map[string]any{"UserName": "recoverer"})
				if err != nil {
					t.Fatal(err)
				}
				if err := cfnComputeRun(ctx, commands, "iam", "PutUserPolicy", map[string]any{"UserName": "recoverer", "PolicyName": "current-recovery", "PolicyDocument": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`}); err != nil {
					t.Fatal(err)
				}
				recoveryMetadata := awsctx.FromContext(ctx)
				recoveryMetadata.PrincipalARN = cfnComputeValue(user.User.Arn)
				recoveryMetadata.PrincipalID = cfnComputeValue(user.User.UserId)
				recoverer := awsctx.WithMetadata(ctx, recoveryMetadata)
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(recoverer, r); err != nil {
					t.Fatalf("authorized current recovery failed: %v", err)
				}
				if err := cfnComputeRun(ctx, commands, "iam", "DeleteUserPolicy", map[string]any{"UserName": "recoverer", "PolicyName": "current-recovery"}); err != nil {
					t.Fatal(err)
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(recoverer, r); err == nil {
					t.Fatal("native receipt reused revoked IAM authorization")
				}
				if kind == "LaunchTemplate" {
					unclaimed := r
					unclaimed.Token = "unclaimed-client-token"
					unclaimed.PhysicalID = ""
					unclaimed.Properties = cloudformation.Properties{"LaunchTemplateName": "unclaimed-client-token", "LaunchTemplateData": map[string]any{"InstanceType": "t3.micro"}}
					native, err := cfnComputeCall[api.CreateLaunchTemplateResult](ctx, commands, "ec2", "CreateLaunchTemplate", map[string]any{"LaunchTemplateName": "unclaimed-client-token", "ClientToken": cfnComputeHash(unclaimed.Token), "LaunchTemplateData": map[string]any{"InstanceType": "t3.micro"}})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := h.Create(ctx, unclaimed); err == nil {
						t.Fatal("client-token replay admitted an existing unclaimed template")
					}
					if err := cfnEC2NativeOwned(ctx, commands, unclaimed, cfnComputeValue(native.LaunchTemplate.LaunchTemplateId)); err == nil {
						t.Fatal("rejected replay attached a private claim")
					}
				}
				closeOwners()
				open()
				reader = h.(cloudformation.ResourceReader)
				if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, r); err != nil || out.PhysicalID != r.PhysicalID {
					t.Fatalf("reopen lost native claim or receipt: %+v %v", out, err)
				}
				if kind == "KeyPair" {
					// Imported keys have no private-material receipt. Even exact forged SSM
					// metadata and an ID-shaped name cannot make their parameters deletable.
					if _, err := cfnComputeCall[ssmapi.PutParameterResult](ctx, commands, "ssm", "PutParameter", map[string]any{"Name": "/ec2/keypair/" + nativeID, "Type": "String", "Value": "customer-owned", "Tags": cfnComputeTagList(forged)}); err != nil {
						t.Fatal(err)
					}
				}
				if err := h.Delete(ctx, r); err != nil {
					t.Fatal(err)
				}
				if kind == "KeyPair" {
					out, err := cfnComputeCall[ssmapi.GetParameterResult](ctx, commands, "ssm", "GetParameter", map[string]any{"Name": "/ec2/keypair/" + nativeID})
					if err != nil || cfnComputeValue(out.Parameter.Value) != "customer-owned" {
						t.Fatalf("imported key deleted parameter without private receipt: %+v %v", out, err)
					}
				}
				reusedID, _ := nativeCreate("private-control")
				stale := r
				stale.PhysicalID = reusedID
				if _, err := reader.Read(ctx, stale); err == nil {
					t.Fatal("name reuse resurrected stale native ownership")
				}
				if err := h.Delete(ctx, stale); err == nil {
					t.Fatal("stale claim deleted replacement native row")
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, r); err == nil {
					t.Fatal("stale receipt recovered a replacement native row")
				}
			})
		}
	}
}
