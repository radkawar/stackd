package integrations

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	ddbapi "stackd/internal/awsapi/dynamodb"
	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/kinesis"
	"stackd/storage/sqlite"
	ddbstore "stackd/storage/sqlite/dynamodb"
	kinesisstore "stackd/storage/sqlite/kinesis"
)

// These fixtures retain actual native owner rows, as a process restart does.
// Every observation and public tag mutation below runs the real service; no
// executor synthesizes ownership or a modeled success for an unavailable engine.
func TestDynamoDBRetainedPrivateOwnerRejectsCounterfeitIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			metadata, scope := cfnDataTestContext()
			ctx := awsctx.WithMetadata(t.Context(), metadata)
			manual := clock.NewManual(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
			var repo dynamodb.Repository = dynamodb.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "tables.sqlite")
			open := func() {
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = ddbstore.New(db)
				}
			}
			open()
			r := cfnDataTestRequest(scope, "AWS::DynamoDB::Table", "Table", cloudformation.Properties{"TableName": "retained", "BillingMode": "PAY_PER_REQUEST", "AttributeDefinitions": []any{map[string]any{"AttributeName": "id", "AttributeType": "S"}}, "KeySchema": []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}}})
			key := dynamodb.TableKey{Scope: dynamodb.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, Name: "retained"}
			table := dynamodb.TableRecord{Key: key, Owner: dynamodb.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, DatabaseID: "retained-database", PhysicalName: "retained-physical", Data: ddbapi.TableDescription{TableName: new(ddbapi.TableName(key.Name)), TableArn: new(ddbapi.String(key.ARN())), TableId: new(ddbapi.TableId("original")), TableStatus: new(ddbapi.TableStatusACTIVE), BillingModeSummary: &ddbapi.BillingModeSummary{BillingMode: new(ddbapi.BillingModePAY_PER_REQUEST)}, KeySchema: ddbapi.KeySchema{{AttributeName: new(ddbapi.KeySchemaAttributeName("id")), KeyType: new(ddbapi.KeyTypeHASH)}}, AttributeDefinitions: ddbapi.AttributeDefinitions{{AttributeName: new(ddbapi.KeySchemaAttributeName("id")), AttributeType: new(ddbapi.ScalarAttributeTypeS)}}}, TTL: ddbapi.TimeToLiveDescription{TimeToLiveStatus: new(ddbapi.TimeToLiveStatusDISABLED)}}
			if err := repo.Update(ctx, func(tx dynamodb.Transaction) error { return tx.PutTable(table) }); err != nil {
				t.Fatal(err)
			}
			var service *dynamodb.Service
			var commands StepFunctionsCommands
			assemble := func() {
				service = dynamodb.New(dynamodb.Config{Repository: repo, Clock: manual})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"dynamodb": service})
			}
			assemble()
			reopen := func() {
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				if db != nil {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					open()
				}
				assemble()
			}
			t.Cleanup(func() {
				_ = service.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			reopen()
			h := cfnDynamoDBTable{commands}
			got, err := h.RecoverCreation(ctx, r)
			if err != nil || got.PhysicalID != key.Name {
				t.Fatalf("retained claim recovery = %#v, %v", got, err)
			}
			global := r
			global.Type = "AWS::DynamoDB::GlobalTable"
			global.Properties = cloudformation.Properties{"TableName": key.Name, "BillingMode": "PAY_PER_REQUEST", "AttributeDefinitions": r.Properties["AttributeDefinitions"], "KeySchema": r.Properties["KeySchema"], "Replicas": []any{map[string]any{"Region": scope.Region}}}
			gh := cfnDynamoDBGlobalTable{commands}
			if got, err := gh.RecoverCreation(ctx, global); err != nil || got.PhysicalID != key.Name {
				t.Fatalf("retained global claim recovery = %#v, %v", got, err)
			}
			// Replace the retained native row, never copying its private authority.
			table.Owner = dynamodb.ResourceOwner{}
			table.PhysicalName, table.Data.TableId = "foreign-physical", new(ddbapi.TableId("foreign"))
			if err := repo.Update(ctx, func(tx dynamodb.Transaction) error {
				if err := tx.DeleteTable(key); err != nil {
					return err
				}
				return tx.PutTable(table)
			}); err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(ctx, commands, "dynamodb", "TagResource", map[string]any{"ResourceArn": key.ARN(), "Tags": cfnDDBTagInput(cfnComputeOwnedTags(r))}); err != nil {
				t.Fatal(err)
			}
			reopen()
			h = cfnDynamoDBTable{commands}
			for _, recover := range []func() (cloudformation.ResourceResult, error){func() (cloudformation.ResourceResult, error) { return h.Create(ctx, r) }, func() (cloudformation.ResourceResult, error) { return h.RecoverCreation(ctx, r) }} {
				got, err := recover()
				if err == nil || got.PhysicalID != "" {
					t.Fatalf("counterfeit table adopted = %#v, %v", got, err)
				}
			}
			r.PhysicalID = key.Name
			if err := h.Delete(ctx, r); err == nil {
				t.Fatal("counterfeit table deletion admitted")
			}
			if got, err := h.Update(ctx, r); err == nil || got.PhysicalID != "" {
				t.Fatalf("counterfeit table update admitted = %#v, %v", got, err)
			}
			gh = cfnDynamoDBGlobalTable{commands}
			global.PhysicalID = key.Name
			if got, err := gh.Create(ctx, global); err == nil || got.PhysicalID != "" {
				t.Fatalf("counterfeit global table adopted = %#v, %v", got, err)
			}
			if got, err := gh.RecoverCreation(ctx, global); err == nil || got.PhysicalID != "" {
				t.Fatalf("counterfeit global recovery adopted = %#v, %v", got, err)
			}
			if err := gh.Delete(ctx, global); err == nil {
				t.Fatal("counterfeit global table deletion admitted")
			}
			if got, err := gh.Update(ctx, global); err == nil || got.PhysicalID != "" {
				t.Fatalf("counterfeit global update admitted = %#v, %v", got, err)
			}
			if _, err := cfnComputeCall[ddbapi.DescribeTableOutput](ctx, commands, "dynamodb", "DescribeTable", map[string]any{"TableName": key.Name}); err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(ctx, commands, "dynamodb", "TagResource", map[string]any{"ResourceArn": key.ARN(), "Tags": []map[string]string{{"Key": "customer", "Value": "native"}}}); err != nil {
				t.Fatal(err)
			}
			// A stale trusted context is fenced inside the native mutation transaction.
			err = cfnComputeRun(cfnDDBOwnerContext(ctx, r, false), commands, "dynamodb", "UntagResource", map[string]any{"ResourceArn": key.ARN(), "TagKeys": []string{"customer"}})
			cfnDataRequireCode(t, err, "AccessDeniedException")
			tags, err := cfnDDBTags(ctx, commands, key.ARN())
			if err != nil || tags["customer"] != "native" {
				t.Fatalf("foreign native mutation lost = %#v, %v", tags, err)
			}
		})
	}
}

func TestKinesisRetainedPrivateOwnersRejectCounterfeitIncarnations(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			metadata, scope := cfnDataTestContext()
			ctx := awsctx.WithMetadata(t.Context(), metadata)
			manual := clock.NewManual(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
			var repo kinesis.Repository = kinesis.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "streams.sqlite")
			open := func() {
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = kinesisstore.New(db)
				}
			}
			open()
			key := kinesis.StreamKey{Scope: kinesis.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, Name: "retained"}
			sr := cfnDataTestRequest(scope, "AWS::Kinesis::Stream", "Stream", cloudformation.Properties{"Name": key.Name, "StreamModeDetails": map[string]any{"StreamMode": "ON_DEMAND"}, "RetentionPeriodHours": 720})
			cr := cfnDataTestRequest(scope, "AWS::Kinesis::StreamConsumer", "Consumer", cloudformation.Properties{"StreamARN": key.ARN(), "ConsumerName": "reader"})
			ck := kinesis.ConsumerKey{Stream: key, Name: "reader", CreatedAt: manual.Now().Unix()}
			stream := kinesis.StreamRecord{Key: key, Owner: kinesis.ResourceOwner{StackID: sr.StackID, LogicalID: sr.LogicalID, Token: sr.Token}, EngineID: "original-engine", Data: kinesisapi.StreamDescriptionSummary{StreamName: new(kinesisapi.StreamName(key.Name)), StreamARN: new(kinesisapi.StreamARN(key.ARN())), StreamStatus: new(kinesisapi.StreamStatusACTIVE), StreamModeDetails: &kinesisapi.StreamModeDetails{StreamMode: new(kinesisapi.StreamModeON_DEMAND)}, RetentionPeriodHours: new(kinesisapi.RetentionPeriodHours(720)), OpenShardCount: new(kinesisapi.ShardCountObject(4)), MaxRecordSizeInKiB: new(kinesisapi.MaxRecordSizeInKiB(1024)), EncryptionType: new(kinesisapi.EncryptionTypeNONE)}}
			consumer := kinesis.ConsumerRecord{Key: ck, Owner: kinesis.ResourceOwner{StackID: cr.StackID, LogicalID: cr.LogicalID, Token: cr.Token}, Data: kinesisapi.ConsumerDescription{ConsumerName: new(kinesisapi.ConsumerName(ck.Name)), ConsumerARN: new(kinesisapi.ConsumerARN(ck.ARN())), StreamARN: new(kinesisapi.StreamARN(key.ARN())), ConsumerStatus: new(kinesisapi.ConsumerStatusACTIVE)}}
			if err := repo.Update(ctx, func(tx kinesis.Transaction) error {
				if err := tx.PutStream(stream); err != nil {
					return err
				}
				return tx.PutConsumer(consumer)
			}); err != nil {
				t.Fatal(err)
			}
			var service *kinesis.Service
			var commands StepFunctionsCommands
			assemble := func() {
				service = kinesis.New(kinesis.Config{Repository: repo, Clock: manual})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kinesis": service})
			}
			assemble()
			reopen := func() {
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				if db != nil {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					open()
				}
				assemble()
			}
			t.Cleanup(func() {
				_ = service.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			reopen()
			sh, ch := cfnKinesisStream{commands}, cfnKinesisConsumer{commands}
			if got, err := sh.RecoverCreation(ctx, sr); err != nil || got.PhysicalID != key.Name {
				t.Fatalf("retained stream recovery = %#v, %v", got, err)
			}
			if got, err := ch.RecoverCreation(ctx, cr); err != nil || got.PhysicalID != ck.ARN() {
				t.Fatalf("retained consumer recovery = %#v, %v", got, err)
			}
			stream.Owner, consumer.Owner = kinesis.ResourceOwner{}, kinesis.ResourceOwner{}
			stream.EngineID = "foreign-engine"
			if err := repo.Update(ctx, func(tx kinesis.Transaction) error {
				if err := tx.DeleteStream(key); err != nil {
					return err
				}
				if err := tx.PutStream(stream); err != nil {
					return err
				}
				return tx.PutConsumer(consumer)
			}); err != nil {
				t.Fatal(err)
			}
			for arn, r := range map[string]cloudformation.ResourceRequest{key.ARN(): sr, ck.ARN(): cr} {
				if err := manual.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
				if err := cfnComputeRun(ctx, commands, "kinesis", "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeOwnedTags(r)}); err != nil {
					t.Fatal(err)
				}
			}
			reopen()
			sh, ch = cfnKinesisStream{commands}, cfnKinesisConsumer{commands}
			sr.PhysicalID, cr.PhysicalID = key.Name, ck.ARN()
			for typ, r := range map[string]cloudformation.ResourceRequest{"stream": sr, "consumer": cr} {
				var h cloudformation.ResourceHandler = sh
				var recoverer cloudformation.ResourceCreationRecoverer = sh
				if typ == "consumer" {
					h, recoverer = ch, ch
				}
				if err := manual.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
				if got, err := h.Create(ctx, r); err == nil || got.PhysicalID != "" {
					t.Fatalf("counterfeit %s create = %#v, %v", typ, got, err)
				}
				if err := manual.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
				if got, err := recoverer.RecoverCreation(ctx, r); err == nil || got.PhysicalID != "" {
					t.Fatalf("counterfeit %s recovery = %#v, %v", typ, got, err)
				}
				if err := h.Delete(ctx, r); err == nil {
					t.Fatalf("counterfeit %s deletion admitted", typ)
				}
				if got, err := h.Update(ctx, r); err == nil || got.PhysicalID != "" {
					t.Fatalf("counterfeit %s update = %#v, %v", typ, got, err)
				}
			}
			if err := manual.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := cfnComputeCall[kinesisapi.DescribeStreamSummaryOutput](ctx, commands, "kinesis", "DescribeStreamSummary", map[string]any{"StreamName": key.Name}); err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(ctx, commands, "kinesis", "TagResource", map[string]any{"ResourceARN": key.ARN(), "Tags": map[string]string{"customer": "native"}}); err != nil {
				t.Fatal(err)
			}
			if err := manual.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			err := cfnComputeRun(cfnKinesisOwnerContext(ctx, sr, "stream", false), commands, "kinesis", "UntagResource", map[string]any{"ResourceARN": key.ARN(), "TagKeys": []string{"customer"}})
			cfnDataRequireCode(t, err, "AccessDeniedException")
			tags, err := cfnKinesisTags(ctx, commands, key.ARN())
			if err != nil || tags["customer"] != "native" {
				t.Fatalf("foreign native mutation lost = %#v, %v", tags, err)
			}
		})
	}
}
