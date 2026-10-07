package integrations

import (
	"path/filepath"
	"testing"

	configapi "stackd/internal/awsapi/configservice"
	gdapi "stackd/internal/awsapi/guardduty"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	config "stackd/internal/services/configservice"
	gd "stackd/internal/services/guardduty"
	"stackd/storage/sqlite"
	configsqlite "stackd/storage/sqlite/configservice"
	gdsqlite "stackd/storage/sqlite/guardduty"
)

func TestConfigGuardDutyPrivateIncarnationsReopenAndCounterfeit(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
			cr := config.NewMemoryRepository(nil)
			gr := gd.NewMemoryRepository(nil)
			var configRepo config.Repository = cr
			var guardRepo gd.Repository = gr
			path := filepath.Join(t.TempDir(), "owners.sqlite")
			var closeDB func()
			open := func() {
				db, err := sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				closeDB = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
				}
				configRepo = configsqlite.New(db)
				guardRepo = gdsqlite.New(db)
			}
			if kind == "sqlite" {
				open()
				defer func() { closeDB() }()
			}
			detector := "0123456789abcdef0123456789abcdef"
			if err := guardRepo.Update(ctx, func(tx gd.Transaction) error {
				return tx.PutDetector(gd.Detector{Scope: gd.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, ID: detector, ARN: "arn:aws:guardduty:us-east-1:111111111111:detector/" + detector})
			}); err != nil {
				t.Fatal(err)
			}
			var cs *config.Service
			var gs *gd.Service
			var commands StepFunctionsCommands
			services := func() {
				cs = config.New(config.Config{Repository: configRepo})
				gs = gd.New(gd.Config{Repository: guardRepo})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"configservice": cs, "guardduty": gs})
			}
			services()
			defer func() { _ = cs.Close(); _ = gs.Close() }()
			auth := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Authorization", Token: "auth-create", Properties: cloudformation.Properties{"AuthorizedAccountId": "222222222222", "AuthorizedAwsRegion": "us-west-2"}}
			filter := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Filter", Token: "filter-create", Properties: cloudformation.Properties{"DetectorId": detector, "Name": "owner-filter", "FindingCriteria": map[string]any{"Criterion": map[string]any{"severity": map[string]any{"Gte": 7}}}}}
			requests := []cloudformation.ResourceRequest{auth, filter}
			handlers := func() []cloudformation.ResourceHandler {
				return []cloudformation.ResourceHandler{cfnConfigAuthorization{commands}, cfnGuardDutyFilter{commands}}
			}
			for i, h := range handlers() {
				res, err := h.Create(ctx, requests[i])
				if err != nil {
					t.Fatal(err)
				}
				requests[i].PhysicalID = res.PhysicalID
			}
			// Customer marker mutation is allowed, but cannot destroy a private claim.
			arn := "arn:aws:config:us-east-1:111111111111:aggregation-authorization/222222222222/us-west-2"
			if err := cfnComputeRun(ctx, commands, "configservice", "TagResource", map[string]any{"ResourceArn": arn, "Tags": []any{map[string]any{"Key": cfnMessagingOwnerTag, "Value": "counterfeit"}, map[string]any{"Key": cfnMessagingTokenTag, "Value": "counterfeit"}}}); err != nil {
				t.Fatal(err)
			}
			filterARN := "arn:aws:guardduty:us-east-1:111111111111:detector/" + detector + "/filter/owner-filter"
			if err := cfnComputeRun(ctx, commands, "guardduty", "TagResource", map[string]any{"ResourceArn": filterARN, "Tags": map[string]string{cfnMessagingOwnerTag: "counterfeit", cfnMessagingTokenTag: "counterfeit"}}); err != nil {
				t.Fatal(err)
			}
			_ = cs.Close()
			_ = gs.Close()
			if kind == "sqlite" {
				closeDB()
				open()
			}
			services()
			for i, h := range handlers() {
				recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, requests[i])
				if err != nil || recovered.PhysicalID != requests[i].PhysicalID {
					t.Fatalf("%T private recovery after reopen: %#v %v", h, recovered, err)
				}
				replay := requests[i]
				replay.PhysicalID = ""
				res, err := h.Create(ctx, replay)
				if err != nil || res.PhysicalID != requests[i].PhysicalID {
					t.Fatalf("%T native same-token replay: %#v %v", h, res, err)
				}
				if _, err := h.(cloudformation.ResourceReader).Read(ctx, requests[i]); err != nil {
					t.Fatal(err)
				}
				denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:user/restricted", PrincipalID: "AIDARESTRICTED"})
				if res, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(denied, requests[i]); err == nil || cfnSecurityMissing(err) || res.PhysicalID != "" {
					t.Fatalf("%T private recovery bypassed current IAM: %#v %v", h, res, err)
				}
				if _, err := h.Update(denied, requests[i]); err == nil {
					t.Fatalf("%T private mutation bypassed current IAM", h)
				}
			}
			// Direct native deletion/recreation keeps native access while invalidating
			// the old CFN incarnation even at the identical public ARN/name/token.
			if err := cfnComputeRun(ctx, commands, "configservice", "DeleteAggregationAuthorization", map[string]any{"AuthorizedAccountId": "222222222222", "AuthorizedAwsRegion": "us-west-2"}); err != nil {
				t.Fatal(err)
			}
			tags := []any{map[string]any{"Key": cfnMessagingOwnerTag, "Value": cfnMessagingOwner(auth)}, map[string]any{"Key": cfnMessagingTokenTag, "Value": cfnMessagingHash(auth.Token)}}
			if _, err := cfnComputeCall[configapi.PutAggregationAuthorizationOutput](ctx, commands, "configservice", "PutAggregationAuthorization", map[string]any{"AuthorizedAccountId": "222222222222", "AuthorizedAwsRegion": "us-west-2", "Tags": tags}); err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(ctx, commands, "guardduty", "DeleteFilter", map[string]any{"DetectorId": detector, "FilterName": "owner-filter"}); err != nil {
				t.Fatal(err)
			}
			native := map[string]any{"DetectorId": detector, "Name": "owner-filter", "ClientToken": cfnMessagingHash(filter.Token), "FindingCriteria": filter.Properties["FindingCriteria"], "Tags": map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(filter), cfnMessagingTokenTag: cfnMessagingHash(filter.Token)}}
			if _, err := cfnComputeCall[gdapi.CreateFilterResponse](ctx, commands, "guardduty", "CreateFilter", native); err != nil {
				t.Fatal(err)
			}
			for i, h := range handlers() {
				if _, err := h.(cloudformation.ResourceReader).Read(ctx, requests[i]); !cfnSecurityClaimMismatch(err) {
					t.Fatalf("%T adopted counterfeit read: %v", h, err)
				}
				if _, err := h.Update(ctx, requests[i]); !cfnSecurityClaimMismatch(err) {
					t.Fatalf("%T changed counterfeit: %v", h, err)
				}
				if err := h.Delete(ctx, requests[i]); !cfnSecurityClaimMismatch(err) {
					t.Fatalf("%T deleted counterfeit: %v", h, err)
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(ctx, requests[i]); !cfnSecurityMissing(err) {
					t.Fatalf("%T recovered counterfeit: %v", h, err)
				}
				cc := requests[i]
				cc.CloudControl = true
				if _, err := h.(cloudformation.ResourceReader).Read(ctx, cc); err != nil {
					t.Fatalf("%T native/CC read blocked: %v", h, err)
				}
				cc.PhysicalID = ""
				if res, err := h.Create(ctx, cc); err == nil || res.PhysicalID != "" {
					t.Fatalf("%T CC CREATE adopted existing native control: %#v %v", h, res, err)
				}
			}
		})
	}
}
