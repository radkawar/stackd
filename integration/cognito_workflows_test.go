package stackd_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

func cognitoWorkflowClient(c cloudClients, region, key, secret string) *cognitoidentityprovider.Client {
	return cognitoidentityprovider.New(cognitoidentityprovider.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestCognitoWorkflowAuthorizationObservation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
			var cloud *stackd.Stack
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
			objects := s3NativeLoad(t, "s3", "owned_object_delivery")
			trailNativeProvision(t, clients, controls, objects, false)
			queueURL := trailNativeQueue(t, clients)
			if _, err := eventDeliveryClient(clients, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabled,
				EventPattern: aws.String(`{"source":["aws.cognito-idp"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["cognito-idp.amazonaws.com"],"eventName":["CreateUserPool","CreateGroup"]}}`),
			}); err != nil {
				t.Fatal(err)
			}
			trails := trailNativeClient(clients)
			selectManagement := func(readWrite trailtypes.ReadWriteType) {
				t.Helper()
				if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{
					TrailName:      aws.String(controls.Identity["trail_name"]),
					EventSelectors: []trailtypes.EventSelector{{IncludeManagementEvents: aws.Bool(true), ReadWriteType: readWrite}},
				}); err != nil {
					t.Fatal(err)
				}
			}
			selectManagement(trailtypes.ReadWriteTypeReadOnly)
			if _, err := trails.StartLogging(t.Context(), &cloudtrail.StartLoggingInput{Name: aws.String(controls.Identity["trail_name"])}); err != nil {
				t.Fatal(err)
			}
			root := cognitoWorkflowClient(clients, "us-east-1", eventDeliveryAccount, "test")
			if _, err := root.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("unselected-write"), UserPoolTier: cognitotypes.UserPoolTierTypeLite}); err != nil {
				t.Fatal(err)
			}
			if messages := snsAdmissionReceive(t, cloud, clients.sqs(eventDeliveryAccount, "test", ""), queueURL); len(messages) != 0 {
				t.Fatalf("read-only trail admitted Cognito write: %+v", messages)
			}
			selectManagement(trailtypes.ReadWriteTypeWriteOnly)

			actorARN, key, secret := clients.user(t, eventDeliveryAccount, "cognito-manager")
			actor := cognitoWorkflowClient(clients, "us-east-1", key, secret)
			denied, err := actor.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("denied-pool"), UserPoolTier: cognitotypes.UserPoolTierTypeLite})
			assertAPIError(t, err, "AccessDeniedException")
			deniedID := nativeAuditRequestID(t, denied, err)
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "cognito-manager", allow(`"cognito-idp:CreateUserPool"`, "*"))
			created, err := actor.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("allowed-pool"), UserPoolTier: cognitotypes.UserPoolTierTypeLite})
			if err != nil {
				t.Fatal(err)
			}
			createdID := nativeAuditRequestID(t, created, nil)
			groupInput := &cognitoidentityprovider.CreateGroupInput{UserPoolId: created.UserPool.Id, GroupName: aws.String("application-readers")}
			deniedGroup, err := actor.CreateGroup(t.Context(), groupInput)
			assertAPIError(t, err, "AccessDeniedException")
			deniedGroupID := nativeAuditRequestID(t, deniedGroup, err)
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "cognito-manager", allow(`"cognito-idp:CreateGroup"`, aws.ToString(created.UserPool.Arn)))
			createdGroup, err := actor.CreateGroup(t.Context(), groupInput)
			if err != nil {
				t.Fatal(err)
			}
			createdGroupID := nativeAuditRequestID(t, createdGroup, nil)
			listed, err := root.ListUserPools(t.Context(), &cognitoidentityprovider.ListUserPoolsInput{MaxResults: aws.Int32(60)})
			if err != nil {
				t.Fatal(err)
			}
			if len(listed.UserPools) != 2 {
				t.Fatalf("denied creation changed pool inventory: %+v", listed.UserPools)
			}
			for _, pool := range listed.UserPools {
				if aws.ToString(pool.Name) != "unselected-write" && aws.ToString(pool.Id) != aws.ToString(created.UserPool.Id) {
					t.Fatalf("denied creation left a pool: %+v", pool)
				}
			}

			// Retain the configured rule, queue policy, trail and admitted deliveries.
			clients = reopen()
			queues := clients.sqs(eventDeliveryAccount, "test", "")
			queue, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("native-cloudtrail")})
			if err != nil {
				t.Fatal(err)
			}
			type expectedCall struct{ operation, poolName, groupName string }
			want := map[string]expectedCall{
				deniedID:       {"CreateUserPool", "", ""},
				createdID:      {"CreateUserPool", "allowed-pool", ""},
				deniedGroupID:  {"CreateGroup", "", ""},
				createdGroupID: {"CreateGroup", "", "application-readers"},
			}
			// The configured standard queue is at-least-once. Validate every copy,
			// but require coverage by request ID rather than exactly-once delivery.
			seen := make(map[string]bool, len(want))
			for _, message := range snsAdmissionReceive(t, cloud, queues, queue.QueueUrl) {
				var event struct {
					Source, Account, Region string
					DetailType              string `json:"detail-type"`
					Detail                  struct {
						RequestID, EventSource, EventName, RecipientAccountID, EventCategory, ErrorCode string
						ReadOnly, ManagementEvent                                                       bool
						UserIdentity                                                                    struct{ ARN string }
						RequestParameters                                                               *struct{ PoolName, GroupName string }
					}
				}
				awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &event)
				detail := event.Detail
				call, selected := want[detail.RequestID]
				if !selected || event.Source != "aws.cognito-idp" || event.Account != eventDeliveryAccount || event.Region != "us-east-1" || event.DetailType != "AWS API Call via CloudTrail" {
					t.Fatalf("unexpected Cognito delivery: %+v", event)
				}
				if detail.EventSource != "cognito-idp.amazonaws.com" || detail.EventName != call.operation || detail.RecipientAccountID != eventDeliveryAccount || detail.EventCategory != "Management" || !detail.ManagementEvent || detail.ReadOnly || detail.UserIdentity.ARN != actorARN {
					t.Fatalf("Cognito delivery lost request scope or actor: %+v", event)
				}
				if detail.RequestID == deniedID || detail.RequestID == deniedGroupID {
					if detail.ErrorCode != "AccessDenied" || detail.RequestParameters != nil {
						t.Fatalf("Cognito IAM denial exposed request parameters or lost its outcome: %+v", event)
					}
				} else if detail.ErrorCode != "" || detail.RequestParameters == nil || detail.RequestParameters.PoolName != call.poolName || detail.RequestParameters.GroupName != call.groupName {
					t.Fatalf("Cognito delivery lost accepted request parameters: %+v", event)
				}
				seen[detail.RequestID] = true
			}
			for requestID, call := range want {
				if !seen[requestID] {
					t.Fatalf("configured CloudTrail/EventBridge/SQS path lost Cognito call %s: %+v", requestID, call)
				}
			}
		})
	}
}

func TestCognitoWorkflowResourceIsolation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			root := cognitoWorkflowClient(clients, "us-east-1", eventDeliveryAccount, "test")
			owned, err := root.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("owned-application"), UserPoolTier: cognitotypes.UserPoolTierTypeLite})
			if err != nil {
				t.Fatal(err)
			}
			sibling, err := root.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("sibling-application"), UserPoolTier: cognitotypes.UserPoolTierTypeLite})
			if err != nil {
				t.Fatal(err)
			}
			_, key, secret := clients.user(t, eventDeliveryAccount, "pool-reader")
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "pool-reader", allow(`["cognito-idp:DescribeUserPool","cognito-idp:CreateGroup","cognito-idp:GetGroup"]`, aws.ToString(owned.UserPool.Arn)))
			clients = reopen()
			root = cognitoWorkflowClient(clients, "us-east-1", eventDeliveryAccount, "test")
			actor := cognitoWorkflowClient(clients, "us-east-1", key, secret)
			described, err := actor.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: owned.UserPool.Id})
			if err != nil || aws.ToString(described.UserPool.Id) != aws.ToString(owned.UserPool.Id) {
				t.Fatalf("retained resource-scoped permission did not allow owned pool: %+v, %v", described, err)
			}
			_, err = actor.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: sibling.UserPool.Id})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = actor.DeleteUserPool(t.Context(), &cognitoidentityprovider.DeleteUserPoolInput{UserPoolId: owned.UserPool.Id})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := actor.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: owned.UserPool.Id}); err != nil {
				t.Fatalf("denied deletion changed owned pool: %v", err)
			}
			groupInput := &cognitoidentityprovider.CreateGroupInput{UserPoolId: owned.UserPool.Id, GroupName: aws.String("readers")}
			if _, err := actor.CreateGroup(t.Context(), groupInput); err != nil {
				t.Fatal(err)
			}
			_, err = actor.CreateGroup(t.Context(), &cognitoidentityprovider.CreateGroupInput{UserPoolId: sibling.UserPool.Id, GroupName: groupInput.GroupName})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = root.GetGroup(t.Context(), &cognitoidentityprovider.GetGroupInput{UserPoolId: sibling.UserPool.Id, GroupName: groupInput.GroupName})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = actor.DeleteGroup(t.Context(), &cognitoidentityprovider.DeleteGroupInput{UserPoolId: owned.UserPool.Id, GroupName: groupInput.GroupName})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := actor.GetGroup(t.Context(), &cognitoidentityprovider.GetGroupInput{UserPoolId: owned.UserPool.Id, GroupName: groupInput.GroupName}); err != nil {
				t.Fatalf("denied group deletion changed membership owner: %v", err)
			}
			for _, scope := range []struct{ account, region string }{{"222222222222", "us-east-1"}, {eventDeliveryAccount, "us-west-2"}} {
				other := cognitoWorkflowClient(clients, scope.region, scope.account, "test")
				_, err := other.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: owned.UserPool.Id})
				assertAPIError(t, err, "ResourceNotFoundException")
				_, err = other.GetGroup(t.Context(), &cognitoidentityprovider.GetGroupInput{UserPoolId: owned.UserPool.Id, GroupName: groupInput.GroupName})
				assertAPIError(t, err, "ResourceNotFoundException")
				created, err := other.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("owned-application"), UserPoolTier: cognitotypes.UserPoolTierTypeLite})
				if err != nil {
					t.Fatal(err)
				}
				listed, err := other.ListUserPools(t.Context(), &cognitoidentityprovider.ListUserPoolsInput{MaxResults: aws.Int32(60)})
				if err != nil || len(listed.UserPools) != 1 || aws.ToString(listed.UserPools[0].Id) != aws.ToString(created.UserPool.Id) {
					t.Fatalf("pool inventory crossed account/region scope %+v: %+v, %v", scope, listed, err)
				}
				root = cognitoWorkflowClient(clients, "us-east-1", eventDeliveryAccount, "test")
				_, err = root.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: created.UserPool.Id})
				assertAPIError(t, err, "ResourceNotFoundException")
			}
		})
	}
}

func TestCognitoWorkflowTokenExpiry(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source})
			root := cognitoWorkflowClient(clients, "us-east-1", eventDeliveryAccount, "test")
			pool, err := root.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("expiry-application"), UserPoolTier: cognitotypes.UserPoolTierTypeLite})
			if err != nil {
				t.Fatal(err)
			}
			app, err := root.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{
				UserPoolId: pool.UserPool.Id, ClientName: aws.String("expiry-client"),
				ExplicitAuthFlows:   []cognitotypes.ExplicitAuthFlowsType{cognitotypes.ExplicitAuthFlowsTypeAllowUserPasswordAuth, cognitotypes.ExplicitAuthFlowsTypeAllowRefreshTokenAuth},
				AccessTokenValidity: aws.Int32(300), IdTokenValidity: aws.Int32(300), RefreshTokenValidity: 3600,
				TokenValidityUnits: &cognitotypes.TokenValidityUnitsType{AccessToken: cognitotypes.TimeUnitsTypeSeconds, IdToken: cognitotypes.TimeUnitsTypeSeconds, RefreshToken: cognitotypes.TimeUnitsTypeSeconds},
			})
			if err != nil {
				t.Fatal(err)
			}
			const username, password = "expiry-user", "OwnedPassword1!"
			if _, err := root.AdminCreateUser(t.Context(), &cognitoidentityprovider.AdminCreateUserInput{UserPoolId: pool.UserPool.Id, Username: aws.String(username), TemporaryPassword: aws.String(password), MessageAction: cognitotypes.MessageActionTypeSuppress}); err != nil {
				t.Fatal(err)
			}
			if _, err := root.AdminSetUserPassword(t.Context(), &cognitoidentityprovider.AdminSetUserPasswordInput{UserPoolId: pool.UserPool.Id, Username: aws.String(username), Password: aws.String(password), Permanent: true}); err != nil {
				t.Fatal(err)
			}
			publicOptions := root.Options()
			publicOptions.Credentials = aws.AnonymousCredentials{}
			public := cognitoidentityprovider.New(publicOptions)
			login, err := public.InitiateAuth(t.Context(), &cognitoidentityprovider.InitiateAuthInput{ClientId: app.UserPoolClient.ClientId, AuthFlow: cognitotypes.AuthFlowTypeUserPasswordAuth, AuthParameters: map[string]string{"USERNAME": username, "PASSWORD": password}})
			if err != nil || login.AuthenticationResult == nil {
				t.Fatalf("public password login: %+v, %v", login, err)
			}
			access, refresh := login.AuthenticationResult.AccessToken, aws.ToString(login.AuthenticationResult.RefreshToken)
			checkUser := func(token *string) {
				t.Helper()
				user, err := public.GetUser(t.Context(), &cognitoidentityprovider.GetUserInput{AccessToken: token})
				if err != nil || aws.ToString(user.Username) != username {
					t.Fatalf("unexpired access token rejected or changed identity: %+v, %v", user, err)
				}
			}
			refreshInput := &cognitoidentityprovider.InitiateAuthInput{ClientId: app.UserPoolClient.ClientId, AuthFlow: cognitotypes.AuthFlowTypeRefreshTokenAuth, AuthParameters: map[string]string{"REFRESH_TOKEN": refresh}}
			checkUser(access)
			advanceClock(t, source, 299*time.Second)
			checkUser(access)
			advanceClock(t, source, time.Second)
			_, err = public.GetUser(t.Context(), &cognitoidentityprovider.GetUserInput{AccessToken: access})
			assertAPIError(t, err, "NotAuthorizedException")
			refreshed, err := public.InitiateAuth(t.Context(), refreshInput)
			if err != nil || refreshed.AuthenticationResult == nil {
				t.Fatalf("access expiry incorrectly expired refresh token: %+v, %v", refreshed, err)
			}
			checkUser(refreshed.AuthenticationResult.AccessToken)

			// Restart does not reset expiry, and refreshing does not extend the family.
			clients = reopen()
			publicOptions.BaseEndpoint, publicOptions.HTTPClient = aws.String(clients.server.URL), clients.server.Client()
			public = cognitoidentityprovider.New(publicOptions)
			advanceClock(t, source, 3299*time.Second)
			refreshed, err = public.InitiateAuth(t.Context(), refreshInput)
			if err != nil || refreshed.AuthenticationResult == nil {
				t.Fatalf("refresh token expired before configured deadline: %+v, %v", refreshed, err)
			}
			checkUser(refreshed.AuthenticationResult.AccessToken)
			advanceClock(t, source, time.Second)
			_, err = public.InitiateAuth(t.Context(), refreshInput)
			assertAPIError(t, err, "NotAuthorizedException")
			checkUser(refreshed.AuthenticationResult.AccessToken)
		})
	}
}
