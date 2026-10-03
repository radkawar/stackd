package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
)

type createIdentityCall struct {
	Label      string          `json:"label"`
	Operation  string          `json:"operation"`
	Parameters json.RawMessage `json:"parameters"`
	Code       string          `json:"code"`
	HTTPStatus int             `json:"http_status"`
	Output     json.RawMessage `json:"output"`
}

// Capture the HTTP status without reading or copying the SDK response body.
// Modeled SDK errors supply ErrorAttribute below.
type createIdentityTransport struct {
	status int
}

func (t *createIdentityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	t.status = response.StatusCode
	return response, nil
}

type createIdentityInventory struct {
	Brokers        map[string]types.BrokerSummary
	Configurations map[string]types.Configuration
}

func createIdentityResources(ctx context.Context, c *mq.Client) createIdentityInventory {
	inventory := createIdentityInventory{Brokers: map[string]types.BrokerSummary{}, Configurations: map[string]types.Configuration{}}
	for token := (*string)(nil); ; {
		out, err := c.ListBrokers(ctx, &mq.ListBrokersInput{NextToken: token, MaxResults: aws.Int32(100)})
		must(err)
		for _, broker := range out.BrokerSummaries {
			inventory.Brokers[aws.ToString(broker.BrokerId)] = broker
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	for token := (*string)(nil); ; {
		out, err := c.ListConfigurations(ctx, &mq.ListConfigurationsInput{NextToken: token, MaxResults: aws.Int32(100)})
		must(err)
		for _, configuration := range out.Configurations {
			inventory.Configurations[aws.ToString(configuration.Id)] = configuration
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	return inventory
}

type createIdentityState struct {
	Broker    *mq.DescribeBrokerOutput
	User      *mq.DescribeUserOutput
	Inventory createIdentityInventory
}

func createIdentitySnapshot(ctx context.Context, c *mq.Client, id, username string) createIdentityState {
	broker, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
	must(err)
	user, err := c.DescribeUser(ctx, &mq.DescribeUserInput{BrokerId: &id, Username: &username})
	must(err)
	// Request IDs and response timing are not retained broker state.
	broker.ResultMetadata = middleware.Metadata{}
	user.ResultMetadata = middleware.Metadata{}
	return createIdentityState{Broker: broker, User: user, Inventory: createIdentityResources(ctx, c)}
}

func createIdentityCases() []createIdentityCall {
	raw, err := os.ReadFile(filepath.Join("testdata", "aws", "mq", "create_identity.json"))
	must(err)
	var fixture struct {
		Complete        bool                 `json:"complete"`
		CleanupVerified bool                 `json:"cleanup_verified"`
		Calls           []createIdentityCall `json:"calls"`
	}
	must(json.Unmarshal(raw, &fixture))
	if !fixture.Complete || !fixture.CleanupVerified {
		panic("create-identity requires a completed, cleanup-verified native fixture; run from the repository root")
	}
	labels := []string{
		"create", "replay-unchanged", "replay-changed-password", "replay-changed-console",
		"replay-changed-tags", "replay-changed-window", "replay-changed-instance",
		"replay-explicit-default-auth", "replay-omitted-token", "replay-empty-token", "replay-different-token",
		"mutate-tags", "mutate-window", "mutate-password", "after-mutation",
		"replay-original-after-mutation", "replay-current-values-after-mutation",
	}
	wanted := make(map[string]bool, len(labels))
	for _, label := range labels {
		wanted[label] = true
	}
	var calls []createIdentityCall
	for _, call := range fixture.Calls {
		if !wanted[call.Label] {
			continue
		}
		if len(calls) >= len(labels) || call.Label != labels[len(calls)] || call.Code == "" || call.HTTPStatus == 0 {
			panic("native create-identity fixture has incomplete, duplicate or out-of-order cases")
		}
		calls = append(calls, call)
	}
	if len(calls) != len(labels) {
		panic("native create-identity fixture omits required replay or mutation cases")
	}
	return calls
}

func createIdentityLifecycle(ctx context.Context, cloud *controller) {
	calls := createIdentityCases()
	file, err := os.OpenFile(filepath.Join(cloud.dir, "create-identity-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"at": time.Now().UTC(), "stage": stage, "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ create identity:", stage)
	}
	transport := &createIdentityTransport{}
	c := mq.NewFromConfig(config("us-east-1", "123456789012"), func(o *mq.Options) {
		o.BaseEndpoint = &cloud.endpoint
		o.HTTPClient = &http.Client{Transport: transport}
	})
	baseline := createIdentityResources(ctx, c)
	ownedName := "identity-" + strings.TrimPrefix(filepath.Base(cloud.dir), "stackd-mq-standalone-")
	ownedBrokers, ownedConfigurations := map[string]bool{}, map[string]bool{}
	completed := false
	defer func() {
		failure := recover()
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		var cleanupErrors []string
		attempt := func(stage string, action func()) {
			defer func() {
				if err := recover(); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Sprintf("%s: %v", stage, err))
				}
			}()
			action()
		}
		attempt("restart controller for cleanup", func() {
			if cloud.cmd == nil {
				cloud.start(cleanup)
			}
		})
		attempt("discover exact-owned resources", func() {
			inventory := createIdentityResources(cleanup, c)
			for id, broker := range inventory.Brokers {
				if aws.ToString(broker.BrokerName) == ownedName {
					if _, existed := baseline.Brokers[id]; !existed {
						ownedBrokers[id] = true
					}
				}
			}
			// This controller has a private, fresh SQLite database and this mode is
			// its only writer. Retain exact IDs, including accidental replay-created
			// configurations, rather than deleting by a global name prefix.
			for id := range inventory.Configurations {
				if _, existed := baseline.Configurations[id]; !existed {
					ownedConfigurations[id] = true
				}
			}
			record("exact-owned cleanup inventory", map[string]any{"brokers": ownedBrokers, "configurations": ownedConfigurations})
		})
		for id := range ownedBrokers {
			attempt("delete broker "+id, func() { engineVersionDeleteBroker(cleanup, c, id, record) })
		}
		for id := range ownedConfigurations {
			attempt("delete configuration "+id, func() {
				_, err := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &id})
				must(err)
				_, err = c.DescribeConfiguration(cleanup, &mq.DescribeConfigurationInput{ConfigurationId: &id})
				code(err, "NotFoundException")
				record("exact-owned configuration absent", id)
			})
		}
		attempt("verify cleanup inventory", func() {
			remaining := createIdentityResources(cleanup, c)
			if !reflect.DeepEqual(remaining, baseline) {
				panic("cleanup did not restore the original broker/configuration inventory")
			}
			record("owned cleanup verified", remaining)
		})
		if len(cleanupErrors) != 0 {
			record("cleanup failures", cleanupErrors)
			panic(fmt.Sprintf("create-identity failure: %v; cleanup: %s", failure, strings.Join(cleanupErrors, "; ")))
		}
		if failure != nil {
			panic(failure)
		}
		if completed {
			fmt.Println("ActiveMQ native-calibrated signed replay + immutable broker/container/volume identity + persistent JMS + SQLite restart + pending credentials + exact-owned cleanup: PASS")
		}
	}()

	var original mq.CreateBrokerInput
	must(json.Unmarshal(calls[0].Parameters, &original))
	nativeName, nativeToken := aws.ToString(original.BrokerName), aws.ToString(original.CreatorRequestId)
	if nativeName == "" || nativeToken == "" || len(original.Users) != 1 {
		panic("native identity fixture lacks its single-user broker ownership")
	}
	username := aws.ToString(original.Users[0].Username)
	const originalPassword = "identity-original-password-123"
	const changedPassword = "identity-changed-password-456"
	remapTags := func(tags map[string]string) {
		for key, value := range tags {
			if value == nativeName {
				tags[key] = ownedName
			}
		}
	}
	adaptCreate := func(call createIdentityCall) *mq.CreateBrokerInput {
		var input mq.CreateBrokerInput
		must(json.Unmarshal(call.Parameters, &input))
		if aws.ToString(input.BrokerName) != nativeName || input.EngineType != types.EngineTypeActivemq || len(input.Users) != 1 {
			panic("native replay changed ownership or the admitted engine/user shape")
		}
		input.BrokerName = &ownedName
		if input.CreatorRequestId != nil {
			switch *input.CreatorRequestId {
			case nativeToken:
				input.CreatorRequestId = &ownedName
			case nativeToken + "-different":
				input.CreatorRequestId = aws.String(ownedName + "-different")
			case "":
			default:
				panic("unrecognized native creator token mutation")
			}
		}
		input.EngineVersion = aws.String("5.18")
		input.PubliclyAccessible = aws.Bool(true)
		input.AutoMinorVersionUpgrade = aws.Bool(false)
		input.SubnetIds, input.SecurityGroups = nil, nil
		input.Users[0].Password = aws.String(originalPassword)
		if call.Label == "replay-changed-password" || call.Label == "replay-current-values-after-mutation" {
			input.Users[0].Password = aws.String(changedPassword)
		}
		remapTags(input.Tags)
		return &input
	}
	record("native fixture adaptation", map[string]any{
		"fixture": "testdata/aws/mq/create_identity.json", "owned_name": ownedName,
		"engine_version": "5.18", "publicly_accessible": true, "auto_minor_version_upgrade": false,
		"subnet_ids": []string{}, "security_groups": []string{}, "passwords": "distinct reconstructed local secrets, not fixture redactions",
	})
	check := func(stage string, call createIdentityCall, output any, err error) {
		actualCode := "Success"
		message := ""
		if err != nil {
			actualCode, message = "NonAPIError", err.Error()
			var api smithy.APIError
			if errors.As(err, &api) {
				actualCode = api.ErrorCode()
			}
		}
		var attribute *string
		if err != nil {
			var bad *types.BadRequestException
			var conflict *types.ConflictException
			switch {
			case errors.As(err, &bad):
				attribute = bad.ErrorAttribute
			case errors.As(err, &conflict):
				attribute = conflict.ErrorAttribute
			}
		}
		var expected struct{ ErrorAttribute *string }
		must(json.Unmarshal(call.Output, &expected))
		record(stage, map[string]any{
			"native_label": call.Label, "operation": call.Operation, "native_parameters": call.Parameters,
			"expected": map[string]any{"code": call.Code, "http_status": call.HTTPStatus, "error_attribute": expected.ErrorAttribute},
			"actual":   map[string]any{"code": actualCode, "http_status": transport.status, "error_attribute": attribute, "message": message, "output": output},
		})
		if actualCode != call.Code || transport.status != call.HTTPStatus || !reflect.DeepEqual(attribute, expected.ErrorAttribute) {
			panic(fmt.Sprintf("%s differs from native: code=%s HTTP=%d ErrorAttribute=%v; want %s HTTP=%d ErrorAttribute=%v", stage, actualCode, transport.status, attribute, call.Code, call.HTTPStatus, expected.ErrorAttribute))
		}
	}
	id, arn := "", ""
	runCreate := func(stage string, call createIdentityCall) {
		if call.Operation != "CreateBroker" {
			panic("native replay case is not CreateBroker")
		}
		input := adaptCreate(call)
		transport.status = 0
		out, err := c.CreateBroker(ctx, input)
		if err == nil && out != nil {
			returnedID := aws.ToString(out.BrokerId)
			if returnedID != "" {
				if _, existed := baseline.Brokers[returnedID]; !existed {
					ownedBrokers[returnedID] = true
				}
			}
		}
		check(stage, call, out, err)
		if err == nil {
			if out == nil || aws.ToString(out.BrokerId) == "" || aws.ToString(out.BrokerArn) == "" {
				panic("successful CreateBroker omitted broker identity")
			}
			if id == "" {
				id, arn = *out.BrokerId, *out.BrokerArn
			} else if *out.BrokerId != id || *out.BrokerArn != arn {
				panic("CreateBroker replay returned a different broker ID or ARN")
			}
		}
	}
	runCreate("create", calls[0])
	current := running(ctx, c, id)
	if current.Configurations == nil || current.Configurations.Current == nil {
		panic("created ActiveMQ broker omitted its automatic configuration")
	}
	cid := aws.ToString(current.Configurations.Current.Id)
	if _, existed := baseline.Configurations[cid]; existed || cid == "" {
		panic("new ActiveMQ broker did not receive a new owned configuration")
	}
	ownedConfigurations[cid] = true
	initial := createIdentitySnapshot(ctx, c, id, username)
	if len(initial.Inventory.Brokers) != len(baseline.Brokers)+1 || len(initial.Inventory.Configurations) != len(baseline.Configurations)+1 {
		panic("initial CreateBroker did not create exactly one broker and one configuration")
	}
	address := current.BrokerInstances[0].Endpoints[0]
	native := engineVersionNative(ctx, id, arn)
	payload := base64.StdEncoding.EncodeToString([]byte("persistent-create-identity-" + id + "\x00retained-through-replays-and-restart"))
	must(jms(ctx, cloud, address, username, originalPassword, "publish-bytes", payload))
	record("persistent JMS bytes published before replay and mutation", map[string]any{"broker": initial, "native": native, "payload_base64": payload})
	credentials := func(stage, accepted, rejected string) {
		must(jms(ctx, cloud, address, username, accepted, "connect", ""))
		if err := jms(ctx, cloud, address, username, rejected, "connect", ""); err == nil {
			panic(stage + ": unintended password authenticated against the actual broker")
		} else if !strings.Contains(err.Error(), "JMSSecurityException") && !strings.Contains(err.Error(), "SecurityException") {
			panic(fmt.Sprintf("%s: password probe failed without a native security exception: %v", stage, err))
		}
		record(stage, map[string]any{"username": username, "accepted_expected_credential": true, "rejected_other_credential": true})
	}
	replay := func(stage string, call createIdentityCall) {
		before := createIdentitySnapshot(ctx, c, id, username)
		runCreate(stage, call)
		after := createIdentitySnapshot(ctx, c, id, username)
		if !reflect.DeepEqual(before, after) {
			record(stage+" unexpected state change", map[string]any{"before": before, "after": after})
			panic(stage + ": replay changed broker/user state or broker/configuration inventory")
		}
		record(stage+" leaves broker user and inventory unchanged", after)
	}
	for _, call := range calls[1:] {
		if call.Operation == "CreateBroker" {
			replay(call.Label, call)
			continue
		}
		if call.Label == "mutate-tags" {
			credentials("replays did not apply changed credentials", originalPassword, changedPassword)
		}
		transport.status = 0
		switch call.Operation {
		case "CreateTags":
			var input mq.CreateTagsInput
			must(json.Unmarshal(call.Parameters, &input))
			input.ResourceArn = &arn
			remapTags(input.Tags)
			out, err := c.CreateTags(ctx, &input)
			check(call.Label, call, out, err)
		case "UpdateBroker":
			var input mq.UpdateBrokerInput
			must(json.Unmarshal(call.Parameters, &input))
			input.BrokerId = &id
			out, err := c.UpdateBroker(ctx, &input)
			check(call.Label, call, out, err)
		case "UpdateUser":
			var input mq.UpdateUserInput
			must(json.Unmarshal(call.Parameters, &input))
			input.BrokerId, input.Password = &id, aws.String(changedPassword)
			out, err := c.UpdateUser(ctx, &input)
			check(call.Label, call, out, err)
		case "DescribeBroker":
			out, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
			check(call.Label, call, out, err)
			must(err)
			var expected struct {
				Tags                       map[string]string
				MaintenanceWindowStartTime *types.WeeklyStartTime
				Users                      []types.UserSummary
			}
			must(json.Unmarshal(call.Output, &expected))
			remapTags(expected.Tags)
			if !reflect.DeepEqual(out.Tags, expected.Tags) || !reflect.DeepEqual(out.MaintenanceWindowStartTime, expected.MaintenanceWindowStartTime) || !reflect.DeepEqual(out.Users, expected.Users) {
				panic("intentional tag/window/user mutations differ from native after-mutation state")
			}
			if out.EngineType != types.EngineType("ActiveMQ") {
				panic(fmt.Sprintf("DescribeBroker EngineType = %q, native = ActiveMQ", out.EngineType))
			}
			inventory := createIdentityResources(ctx, c)
			if inventory.Brokers[id].EngineType != types.EngineType("ActiveMQ") {
				panic("ListBrokers did not retain native ActiveMQ spelling")
			}
			engines, err := c.DescribeBrokerEngineTypes(ctx, &mq.DescribeBrokerEngineTypesInput{EngineType: aws.String("ACTIVEMQ")})
			must(err)
			if len(engines.BrokerEngineTypes) != 1 || engines.BrokerEngineTypes[0].EngineType != types.EngineTypeActivemq {
				panic("broker response spelling changed catalog enum")
			}
			record("native ActiveMQ broker labels and uppercase catalog enum", map[string]any{"broker": out.EngineType, "listed": inventory.Brokers[id].EngineType, "catalog": engines.BrokerEngineTypes[0].EngineType})
		default:
			panic("unsupported operation in native create-identity cases: " + call.Operation)
		}
	}
	credentials("original credential remains active while intentional password update is pending", originalPassword, changedPassword)
	beforeRestart := createIdentitySnapshot(ctx, c, id, username)
	beforeNative := engineVersionNative(ctx, id, arn)
	if !reflect.DeepEqual(native, beforeNative) {
		panic("replay or pending mutation replaced/restarted the native broker or its journal volume")
	}
	cloud.stop()
	cloud.start(ctx)
	running(ctx, c, id)
	afterRestart := createIdentitySnapshot(ctx, c, id, username)
	afterNative := engineVersionNative(ctx, id, arn)
	if !reflect.DeepEqual(beforeRestart, afterRestart) || !reflect.DeepEqual(beforeNative, afterNative) {
		record("unexpected retained restart change", map[string]any{"before": beforeRestart, "after": afterRestart, "native_before": beforeNative, "native_after": afterNative})
		panic("SQLite controller restart changed broker state, inventory or native identity")
	}
	record("SQLite restart retained broker container volume and settings", map[string]any{"broker": afterRestart, "native": afterNative})
	for _, call := range calls[len(calls)-2:] {
		replay("after-restart "+call.Label, call)
	}
	credentials("controller restart and replays preserve active and pending credentials", originalPassword, changedPassword)
	must(jms(ctx, cloud, address, username, originalPassword, "consume-bytes", payload))
	must(jms(ctx, cloud, address, username, originalPassword, "expect-empty", "500"))
	record("exact persistent JMS bytes consumed after replay mutation and SQLite restart", map[string]any{"payload_base64": payload, "native": afterNative})

	// Password values are intentionally absent from DescribeUser. Apply the
	// explicit mutation to prove replay did not silently overwrite pending secret
	// material while leaving the public pending-change summary unchanged.
	current = reboot(ctx, c, id)
	afterReboot := engineVersionNative(ctx, id, arn)
	if afterReboot.ContainerID != native.ContainerID || afterReboot.VolumeName != native.VolumeName || afterReboot.StartedAt == afterNative.StartedAt || current.BrokerInstances[0].Endpoints[0] != address {
		panic("applying the explicit password update did not preserve broker/container/volume identity")
	}
	credentials("native reboot applies only the explicit pending password mutation", changedPassword, originalPassword)
	inventory := createIdentityResources(ctx, c)
	if !reflect.DeepEqual(inventory, beforeRestart.Inventory) {
		panic("applying pending credentials changed broker/configuration inventory")
	}
	record("intentional pending password survives replay and restart", map[string]any{"broker": current, "native": afterReboot, "inventory": inventory})
	completed = true
}
