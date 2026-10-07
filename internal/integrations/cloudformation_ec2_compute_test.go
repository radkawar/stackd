package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

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
	"stackd/internal/services/kms"
	"stackd/internal/services/ssm"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqliam "stackd/storage/sqlite/iam"
	sqlkms "stackd/storage/sqlite/kms"
	sqlssm "stackd/storage/sqlite/ssm"
)

type cfnEC2ComputeTestExecutor func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)

func (f cfnEC2ComputeTestExecutor) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	return f(ctx, r)
}
func cfnEC2ComputeTestCommands(f cfnEC2ComputeTestExecutor) StepFunctionsCommands {
	return NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": f})
}
func cfnEC2ComputeTestRequest(kind string) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: kind, StackID: "stack-id", StackName: "stack", LogicalID: "Resource", Token: "incarnation", Properties: cloudformation.Properties{}}
}
func cfnEC2ComputeTestTags(r cloudformation.ResourceRequest) api.TagList {
	out := api.TagList{}
	for _, tag := range cfnComputeTagList(cfnEC2NetworkDesiredTags(r)) {
		out = append(out, api.Tag{Key: new(api.String(tag["Key"])), Value: new(api.String(tag["Value"]))})
	}
	return out
}

func TestCFNEC2ComputeRegistryUsesOfficialOwnerTypes(t *testing.T) {
	registry := CloudFormationEC2ComputeHandlers(StepFunctionsCommands{})
	for _, kind := range []string{"Instance", "LaunchTemplate", "Volume", "VolumeAttachment", "KeyPair", "SnapshotBlockPublicAccess"} {
		if registry["AWS::EC2::"+kind] == nil {
			t.Fatalf("missing %s", kind)
		}
	}
	if len(registry) != 6 || registry["AWS::EC2::Snapshot"] != nil {
		t.Fatal("invented nonofficial snapshot resource")
	}
}

func TestCFNEC2InstanceTranslatesCFNWithoutMutatingProperties(t *testing.T) {
	r := cfnEC2ComputeTestRequest("AWS::EC2::Instance")
	r.Properties = cloudformation.Properties{
		"ImageId": "ami-00000000000000001", "InstanceType": "t3.micro", "Monitoring": true, "IamInstanceProfile": "profile",
		"CreditSpecification":             map[string]any{"CPUCredits": "standard"},
		"NetworkInterfaces":               []any{map[string]any{"DeviceIndex": "0", "GroupSet": []any{"sg-00000000000000001"}, "SubnetId": "subnet-00000000000000001"}},
		"BlockDeviceMappings":             []any{map[string]any{"DeviceName": "/dev/sdb", "NoDevice": map[string]any{}}},
		"PropagateTagsToVolumeOnCreation": true,
	}
	in, err := cfnEC2InstanceLaunch(r)
	if err != nil {
		t.Fatal(err)
	}
	if in["CreditSpecification"].(map[string]any)["CpuCredits"] != "standard" {
		t.Fatal("CFN CPUCredits did not translate")
	}
	network := in["NetworkInterfaces"].([]any)[0].(map[string]any)
	if network["DeviceIndex"] != int64(0) || network["Groups"] == nil || network["GroupSet"] != nil {
		t.Fatalf("network input %+v", network)
	}
	if r.Properties["NetworkInterfaces"].([]any)[0].(map[string]any)["DeviceIndex"] != "0" {
		t.Fatal("mutated resolved properties")
	}
	if in["BlockDeviceMappings"].([]any)[0].(map[string]any)["NoDevice"] != "" {
		t.Fatal("NoDevice did not translate")
	}
	if len(in["TagSpecifications"].([]map[string]any)) != 2 {
		t.Fatal("volume tags not propagated")
	}
	if in["MinCount"] != 1 || in["MaxCount"] != 1 || in["ClientToken"] == "" {
		t.Fatal("launch cardinality or recovery token missing")
	}
}

func TestCFNEC2OfficialReplacementRules(t *testing.T) {
	mapping := func(size int, remove bool) cloudformation.Properties {
		return cloudformation.Properties{"BlockDeviceMappings": []any{map[string]any{"DeviceName": "/dev/sda1", "Ebs": map[string]any{"VolumeSize": size, "DeleteOnTermination": remove}}}}
	}
	if replace, err := (cfnEC2Instance{}).Replacement(mapping(8, true), mapping(8, false)); err != nil || replace {
		t.Fatalf("DeleteOnTermination replaced instance: %v %v", replace, err)
	}
	if replace, err := (cfnEC2Instance{}).Replacement(mapping(8, true), mapping(16, true)); err != nil || !replace {
		t.Fatalf("volume resizing did not replace instance: %v %v", replace, err)
	}
	if replace, _ := (cfnEC2KeyPair{}).Replacement(cloudformation.Properties{}, cloudformation.Properties{"Tags": []any{map[string]any{"Key": "k", "Value": "v"}}}); !replace {
		t.Fatal("KeyPair Tags must replace per official schema")
	}
	if replace, _ := (cfnEC2LaunchTemplate{}).Replacement(cloudformation.Properties{"LaunchTemplateData": map[string]any{"InstanceType": "t3.micro"}}, cloudformation.Properties{"LaunchTemplateData": map[string]any{"InstanceType": "t3.small"}}); replace {
		t.Fatal("launch template data update must version, not replace")
	}
	if _, err := (cfnEC2Volume{}).Replacement(cloudformation.Properties{"AvailabilityZone": "us-east-1a"}, cloudformation.Properties{"AvailabilityZone": "us-east-1b"}); err == nil {
		t.Fatal("AWS forbids volume AZ updates")
	}
}

func TestCFNEC2InstanceStabilizationDoesNotInventRuntimeSuccess(t *testing.T) {
	r := cfnEC2ComputeTestRequest("AWS::EC2::Instance")
	// This command-translation unit test does not claim a native launch succeeded.
	r.CloudControl = true
	r.PhysicalID = "i-00000000000000001"
	state := "pending"
	calls := 0
	commands := cfnEC2ComputeTestCommands(func(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
		calls++
		if req.Operation.Name != "DescribeInstances" {
			t.Fatalf("pending/failed instance mutated via %s", req.Operation.Name)
		}
		return &api.DescribeInstancesResult{Reservations: api.ReservationList{{Instances: api.InstanceList{{InstanceId: new(api.String(r.PhysicalID)), State: &api.InstanceState{Name: new(api.InstanceStateName(state))}, Tags: cfnEC2ComputeTestTags(r)}}}}}, nil
	})
	h := cfnEC2Instance{commands}
	if ready, err := h.Stabilize(t.Context(), r); ready || err != nil {
		t.Fatalf("pending readiness %v %v", ready, err)
	}
	state = "terminated"
	if ready, err := h.Stabilize(t.Context(), r); ready || err == nil {
		t.Fatalf("failed runtime readiness %v %v", ready, err)
	}
	if calls != 2 {
		t.Fatalf("unexpected observations %d", calls)
	}
}

func TestCFNEC2ComputeDiscoveryPreservesIAMDenial(t *testing.T) {
	denial := &awswire.Error{Code: "UnauthorizedOperation", Message: "current role denied", StatusCode: 403}
	commands := cfnEC2ComputeTestCommands(func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error) { return nil, denial })
	for name, handler := range CloudFormationEC2ComputeHandlers(commands) {
		reader := handler.(cloudformation.ResourceReader)
		if _, err := reader.List(t.Context(), cloudformation.ResourceRequest{CloudControl: true}); !errors.Is(err, denial) {
			t.Fatalf("%s list lost IAM denial: %v", name, err)
		}
	}
}

// Public tags, including forged legacy edge markers, never prove an attachment
// slot claim; only the native EC2 relation receipt does.
func TestCFNEC2AttachmentRecoveryRejectsUnrelatedRelation(t *testing.T) {
	r := cfnEC2ComputeTestRequest("AWS::EC2::VolumeAttachment")
	r.Properties = cloudformation.Properties{"VolumeId": "vol-00000000000000001", "InstanceId": "i-00000000000000001", "Device": "/dev/sdh"}
	calls := 0
	commands := cfnEC2ComputeTestCommands(func(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
		calls++
		if req.Operation.Name != "DescribeVolumes" {
			t.Fatalf("unproven relation issued %s", req.Operation.Name)
		}
		forged := api.TagList{{Key: new(api.String("stackd:cloudformation:edge-" + cfnComputeHash(r.Type+"/i-00000000000000001"))), Value: new(api.String(cfnEC2NativeIdentity(r)))}}
		return &api.DescribeVolumesResult{Volumes: api.VolumeList{{VolumeId: new(api.String("vol-00000000000000001")), Tags: forged, Attachments: api.VolumeAttachmentList{{VolumeId: new(api.String("vol-00000000000000001")), InstanceId: new(api.String("i-00000000000000001")), Device: new(api.String("/dev/sdh")), State: new(api.VolumeAttachmentState("attached"))}}}}}, nil
	})
	h := cfnEC2VolumeAttachment{commands}
	if _, err := h.Create(t.Context(), r); err == nil {
		t.Fatal("public edge marker adopted a live attachment")
	}
	r.PhysicalID = cfnEC2AttachmentID("vol-00000000000000001", "i-00000000000000001")
	if _, err := h.Read(t.Context(), r); err == nil {
		t.Fatal("stack read adopted foreign attachment")
	}
	if rows, err := h.List(t.Context(), r); err != nil || len(rows) != 0 {
		t.Fatalf("stack discovery exposed foreign attachment: %+v %v", rows, err)
	}
	if err := h.Delete(t.Context(), r); err == nil {
		t.Fatal("stack deletion detached an unproven attachment")
	}
	cc := r
	cc.CloudControl = true
	if _, err := h.Create(t.Context(), cc); err == nil {
		t.Fatal("Cloud Control create adopted a foreign attachment")
	}
	if _, err := h.Read(t.Context(), cc); err != nil {
		t.Fatalf("direct read was not authoritative: %v", err)
	}
	if rows, err := h.List(t.Context(), cc); err != nil || len(rows) != 1 || rows[0].Identifier != cc.PhysicalID {
		t.Fatalf("official composite discovery: %+v %v", rows, err)
	}
	absent := r
	absent.PhysicalID = ""
	before := calls
	if _, err := h.Read(t.Context(), absent); err == nil || calls != before {
		t.Fatalf("missing physical identity looked up customer property IDs: %v", err)
	}
}

func TestCFNEC2GeneratedKeyPairPrivatePersistenceIsAtomic(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			domain := memory.NewDomain()
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			var ec2Repo ec2.Repository = ec2.NewMemoryRepository(domain)
			var ssmRepo ssm.Repository = ssm.NewMemoryRepository(domain)
			var iamRepo iam.Repository = iam.NewMemoryRepository(domain)
			var keyStorage kms.Storage = kms.NewMemoryStorage(domain)
			var db *sql.DB
			dbPath := filepath.Join(t.TempDir(), "key-material.sqlite")
			if backend == "sqlite" {
				var err error
				db, err = sqlite.Open(ctx, dbPath)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				ec2Repo = sqlec2.New(db)
				ssmRepo = sqlssm.New(db)
				iamRepo = sqliam.New(db)
				keyStorage = sqlkms.New(db)
			}
			identityOwner := iam.NewWithConfig(iam.Config{Repository: iamRepo})
			t.Cleanup(func() { _ = identityOwner.Close() })
			authorizer := authorization.New(identityOwner, nil)
			ec2Owner := ec2.New(ec2.Config{Repository: ec2Repo, Authorizer: authorizer})
			ssmOwner := ssm.New(ssm.Config{Repository: ssmRepo, Authorizer: authorizer})
			t.Cleanup(func() { _ = ec2Owner.Close(); _ = ssmOwner.Close() })
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": ec2Owner, "ssm": ssmOwner})
			r := cfnEC2ComputeTestRequest("AWS::EC2::KeyPair")
			r.Properties = cloudformation.Properties{"KeyName": "atomic-key", "KeyType": "ed25519"}
			if _, err := (cfnEC2KeyPair{commands}).Create(ctx, r); err == nil {
				t.Fatal("generated key succeeded without real SecureString encryption")
			}
			pairs, err := cfnComputeCall[api.DescribeKeyPairsResult](ctx, commands, "ec2", "DescribeKeyPairs", map[string]any{})
			if err != nil || len(pairs.KeyPairs) != 0 {
				t.Fatalf("failed private persistence left orphan key: %+v %v", pairs, err)
			}
			keys := kms.NewWithConfig(kms.Config{Storage: keyStorage})
			identityCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": identityOwner})
			credential, err := cfnComputeCall[iamapi.CreateAccessKeyOutput](ctx, identityCommands, "iam", "CreateAccessKey", map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			authenticated := awsctx.FromContext(ctx)
			authenticated.AccessKeyID = cfnComputeValue(credential.AccessKey.AccessKeyId)
			ctx = awsctx.WithMetadata(ctx, authenticated)
			secureOwner := ssm.New(ssm.Config{Repository: ssmRepo, Authorizer: authorizer, Keys: ServiceDataKeys{KMS: keys, Activity: identityOwner, Service: "ssm"}})
			t.Cleanup(func() { keys.Close(); secureOwner.Close() })
			commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": ec2Owner, "ssm": secureOwner})
			h := cfnEC2KeyPair{commands}
			result, err := h.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := h.Create(ctx, r)
			if err != nil || recovered.PhysicalID != result.PhysicalID || recovered.Attributes["KeyPairId"] != result.Attributes["KeyPairId"] {
				t.Fatalf("key recovery changed incarnation: %+v %v", recovered, err)
			}
			ccRecovery := r
			ccRecovery.CloudControl = true
			if replay, err := h.Create(ctx, ccRecovery); err != nil || replay.Attributes["KeyPairId"] != result.Attributes["KeyPairId"] {
				t.Fatalf("Cloud Control key retry did not recover its exact claim: %+v %v", replay, err)
			}
			wrong := r
			wrong.Token = "different-incarnation"
			if _, err := h.Create(ctx, wrong); err == nil {
				t.Fatal("recovered key from a different resource incarnation")
			}
			wrong.CloudControl = true
			if _, err := h.Create(ctx, wrong); err == nil {
				t.Fatal("Cloud Control adopted a foreign key incarnation")
			}
			otherAccount := awsctx.FromContext(ctx)
			otherAccount.AccountID = "210987654321"
			otherAccount.PrincipalARN = "arn:aws:iam::210987654321:root"
			otherAccount.PrincipalID = "210987654321"
			if rows, err := h.List(awsctx.WithMetadata(ctx, otherAccount), cloudformation.ResourceRequest{CloudControl: true}); err != nil || len(rows) != 0 {
				t.Fatalf("key leaked across accounts: %d %v", len(rows), err)
			}
			metadata := awsctx.FromContext(ctx)
			metadata.Region = "us-west-2"
			if rows, err := h.List(awsctx.WithMetadata(ctx, metadata), cloudformation.ResourceRequest{CloudControl: true}); err != nil || len(rows) != 0 {
				t.Fatalf("key leaked across regions: %d %v", len(rows), err)
			}
			metadata = awsctx.FromContext(ctx)
			metadata.PrincipalARN = "arn:aws:iam::123456789012:user/denied"
			metadata.PrincipalID = "denied"
			denied := r
			denied.PhysicalID = result.PhysicalID
			denied.CloudControl = true
			if _, err := h.Read(awsctx.WithMetadata(ctx, metadata), denied); err == nil {
				t.Fatal("live key read bypassed current IAM")
			}
			id := result.Attributes["KeyPairId"].(string)
			alternate := r
			alternate.PhysicalID = id
			alternate.CloudControl = true
			if p, err := h.Read(ctx, alternate); err != nil || p["KeyName"] != result.PhysicalID {
				t.Fatalf("official additional KeyPairId did not resolve: %+v %v", p, err)
			}
			parameter, err := cfnComputeCall[ssmapi.GetParameterResult](ctx, commands, "ssm", "GetParameter", map[string]any{"Name": "/ec2/keypair/" + id, "WithDecryption": true})
			if err != nil || parameter.Parameter == nil || !strings.Contains(cfnComputeValue(parameter.Parameter.Value), "PRIVATE KEY") {
				t.Fatalf("missing persisted private key: %v", err)
			}
			if parameter.Parameter.Type == nil || *parameter.Parameter.Type != "SecureString" {
				t.Fatal("private key was not encrypted")
			}
			encrypted, err := cfnComputeCall[ssmapi.GetParameterResult](ctx, commands, "ssm", "GetParameter", map[string]any{"Name": "/ec2/keypair/" + id})
			if err != nil || encrypted.Parameter == nil {
				t.Fatalf("encrypted key read failed: %v", err)
			}
			if strings.Contains(cfnComputeValue(encrypted.Parameter.Value), "PRIVATE KEY") {
				t.Fatal("undecrypted parameter exposed private key")
			}
			// Even account root cannot use the AWS-managed SSM key without the
			// genuine service-forwarding context supplied by ServiceDataKeys.
			if _, _, denial := keys.Encrypt(ctx, "alias/aws/ssm", []byte("direct caller"), nil); denial == nil || denial.Code != "AccessDeniedException" {
				t.Fatalf("default SSM key admitted direct encryption: %v", denial)
			}
			// Restart the actual owners and reopen SQLite: both encrypted bytes and the
			// native material receipt must survive, not merely an adapter-local cache.
			_ = secureOwner.Close()
			_ = ssmOwner.Close()
			_ = ec2Owner.Close()
			_ = keys.Close()
			_ = identityOwner.Close()
			if db != nil {
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				db, err = sqlite.Open(ctx, dbPath)
				if err != nil {
					t.Fatal(err)
				}
				ec2Repo = sqlec2.New(db)
				ssmRepo = sqlssm.New(db)
				iamRepo = sqliam.New(db)
				keyStorage = sqlkms.New(db)
			}
			identityOwner = iam.NewWithConfig(iam.Config{Repository: iamRepo})
			authorizer = authorization.New(identityOwner, nil)
			ec2Owner = ec2.New(ec2.Config{Repository: ec2Repo, Authorizer: authorizer})
			keys = kms.NewWithConfig(kms.Config{Storage: keyStorage})
			secureOwner = ssm.New(ssm.Config{Repository: ssmRepo, Authorizer: authorizer, Keys: ServiceDataKeys{KMS: keys, Activity: identityOwner, Service: "ssm"}})
			commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": ec2Owner, "ssm": secureOwner})
			identityCommands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": identityOwner})
			h = cfnEC2KeyPair{commands}
			if generated, err := h.privateReceipt(ctx, id); err != nil || !generated {
				t.Fatalf("restart lost exact native material receipt: %v %v", generated, err)
			}
			if out, err := h.RecoverCreation(ctx, r); err != nil || out.Attributes["KeyPairId"] != id {
				t.Fatalf("restart lost generated key creation receipt: %+v %v", out, err)
			}
			if out, err := cfnComputeCall[ssmapi.GetParameterResult](ctx, commands, "ssm", "GetParameter", map[string]any{"Name": "/ec2/keypair/" + id, "WithDecryption": true}); err != nil || out.Parameter == nil || !strings.Contains(cfnComputeValue(out.Parameter.Value), "PRIVATE KEY") {
				t.Fatalf("restart lost real encrypted key material: %+v %v", out, err)
			}
			r.PhysicalID = result.PhysicalID
			// Current EC2 deletion IAM must run before the private-material sink;
			// a role that can delete SSM parameters still cannot erase key material.
			for _, admission := range []struct{ name, policy string }{
				{"denied-native-delete", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeKeyPairs","ssm:*"],"Resource":"*"}]}`},
				{"denied-private-delete", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:*","ssm:DescribeParameters","ssm:GetParameter"],"Resource":"*"}]}`},
			} {
				user, err := cfnComputeCall[iamapi.CreateUserResponse](ctx, identityCommands, "iam", "CreateUser", map[string]any{"UserName": admission.name})
				if err != nil {
					t.Fatal(err)
				}
				if err := cfnComputeRun(ctx, identityCommands, "iam", "PutUserPolicy", map[string]any{"UserName": admission.name, "PolicyName": "delete-boundary", "PolicyDocument": admission.policy}); err != nil {
					t.Fatal(err)
				}
				metadata := awsctx.FromContext(ctx)
				metadata.PrincipalARN = cfnComputeValue(user.User.Arn)
				metadata.PrincipalID = cfnComputeValue(user.User.UserId)
				metadata.AccessKeyID = ""
				if err := h.Delete(awsctx.WithMetadata(ctx, metadata), r); err == nil {
					t.Fatalf("%s erased key or material", admission.name)
				}
				if _, err := h.Read(ctx, r); err != nil {
					t.Fatalf("%s left native key deleted: %v", admission.name, err)
				}
				if _, err := cfnComputeCall[ssmapi.GetParameterResult](ctx, commands, "ssm", "GetParameter", map[string]any{"Name": "/ec2/keypair/" + id}); err != nil {
					t.Fatalf("%s erased material despite rejected native transaction: %v", admission.name, err)
				}
			}
			if err := h.Delete(ctx, alternate); err != nil {
				t.Fatal(err)
			}
			if _, err := h.get(ctx, result.PhysicalID); !cfnEC2Missing(err) {
				t.Fatalf("alternate identifier deletion left the key alive: %v", err)
			}
			if _, err := cfnComputeCall[ssmapi.GetParameterResult](ctx, commands, "ssm", "GetParameter", map[string]any{"Name": "/ec2/keypair/" + id}); !cfnMessagingMissing(err, "ParameterNotFound") {
				t.Fatalf("private parameter survived deletion: %v", err)
			}
			next := r
			next.PhysicalID = ""
			next.Token = "next-incarnation"
			second, err := h.Create(ctx, next)
			if err != nil {
				t.Fatal(err)
			}
			next.PhysicalID = second.PhysicalID
			if err := cfnComputeRun(ctx, commands, "ec2", "DeleteKeyPair", map[string]any{"KeyName": second.PhysicalID}); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(ctx, next); err != nil {
				t.Fatalf("private cleanup after external key deletion: %v", err)
			}
			if _, err := cfnComputeCall[ssmapi.GetParameterResult](ctx, commands, "ssm", "GetParameter", map[string]any{"Name": "/ec2/keypair/" + second.Attributes["KeyPairId"].(string)}); err != nil {
				t.Fatalf("missing native key granted private parameter deletion authority: %v", err)
			}
			next.PhysicalID = ""
			next.Token = "missing-secret-incarnation"
			third, err := h.Create(ctx, next)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(ctx, commands, "ssm", "DeleteParameter", map[string]any{"Name": "/ec2/keypair/" + third.Attributes["KeyPairId"].(string)}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Create(ctx, next); err == nil {
				t.Fatal("recovered generated key without its durable private parameter")
			}
			next.PhysicalID = third.PhysicalID
			if err := h.Delete(ctx, next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNEC2InstanceResultRefreshesFinalOwnerAttributes(t *testing.T) {
	r := cfnEC2ComputeTestRequest("AWS::EC2::Instance")
	r.CloudControl = true // Attribute projection only, not a native runtime success.
	r.PhysicalID = "i-00000000000000001"
	commands := cfnEC2ComputeTestCommands(func(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
		if request.Operation.Name != "DescribeInstances" {
			t.Fatalf("result issued %s", request.Operation.Name)
		}
		return &api.DescribeInstancesResult{Reservations: api.ReservationList{{Instances: api.InstanceList{{InstanceId: new(api.String(r.PhysicalID)), PublicIpAddress: new(api.String("203.0.113.7")), VpcId: new(api.String("vpc-00000000000000001")), State: &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))}, Tags: cfnEC2ComputeTestTags(r)}}}}}, nil
	})
	result, err := (cfnEC2Instance{commands}).Result(t.Context(), r)
	if err != nil || result.PhysicalID != r.PhysicalID || result.Ref != r.PhysicalID || result.Attributes["InstanceId"] != r.PhysicalID || result.Attributes["PublicIp"] != "203.0.113.7" || result.Attributes["VpcId"] != "vpc-00000000000000001" {
		t.Fatalf("final attributes %+v %v", result, err)
	}
}

func TestCFNEC2InstanceConditionalResizeReadsOwnerArchitecture(t *testing.T) {
	r := cfnEC2ComputeTestRequest("AWS::EC2::Instance")
	r.CloudControl = true // Replacement translation only; private ownership is exercised with real owners.
	r.PhysicalID = "i-00000000000000001"
	r.Previous = cloudformation.Properties{"InstanceType": "t3.micro"}
	r.Properties = cloudformation.Properties{"InstanceType": "t4g.micro"}
	architecture := "arm64"
	commands := cfnEC2ComputeTestCommands(func(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
		switch request.Operation.Name {
		case "DescribeInstances":
			return &api.DescribeInstancesResult{Reservations: api.ReservationList{{Instances: api.InstanceList{{InstanceId: new(api.String(r.PhysicalID)), Architecture: new(api.ArchitectureValues("x86_64")), RootDeviceType: new(api.DeviceType("ebs")), Tags: cfnEC2ComputeTestTags(r)}}}}}, nil
		case "DescribeInstanceTypes":
			return &api.DescribeInstanceTypesResult{InstanceTypes: api.InstanceTypeInfoList{{InstanceType: new(api.InstanceType("t4g.micro")), ProcessorInfo: &api.ProcessorInfo{SupportedArchitectures: api.ArchitectureTypeList{api.ArchitectureType(architecture)}}}}}, nil
		default:
			t.Fatalf("replacement performed effect %s", request.Operation.Name)
			return nil, nil
		}
	})
	h := cfnEC2Instance{commands}
	if decision, err := h.ReplacementPlan(r.Previous, r.Properties); err != nil || decision != "Conditional" {
		t.Fatalf("public plan %s %v", decision, err)
	}
	if replace, err := h.ReplacementForResource(t.Context(), r); err != nil || !replace {
		t.Fatalf("incompatible architecture must replace: %v %v", replace, err)
	}
	architecture = "x86_64"
	if replace, err := h.ReplacementForResource(t.Context(), r); err != nil || replace {
		t.Fatalf("compatible owner architecture should resize: %v %v", replace, err)
	}
}
