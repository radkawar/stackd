package stackd_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd"
	"stackd/storage"
)

// Customer Python runs through the native Runtime API, on both typed storage
// backends. Permission revocation and source-pool mismatch must be evaluated by
// the current Lambda resource policy, not a Cognito-side cached authorization.
func TestCognitoClassicTriggersNativeLambda(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise real native Lambda triggers")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "cognito-triggers.sqlite"))
			}
			_, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, AccountID: cognitoGuardAccount}, nil)
			clients := cloudClients{server}
			identity := clients.iam("test", "test", "")
			idp := cognitoWorkflowClient(clients, "us-east-1", cognitoGuardAccount, "test")
			functions := lambda.New(lambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("cognito-classic-native"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			source := `def handler(event, context):
    assert event['version'] == '1'
    assert event['region'] == 'us-east-1'
    assert event['userPoolId'].startswith('us-east-1_')
    assert event['callerContext']['clientId']
    trigger = event['triggerSource']
    if trigger == 'PreSignUp_SignUp':
        assert event['request']['validationData']['invite'] == 'valid'
        event['response']['autoConfirmUser'] = True
        event['response']['autoVerifyEmail'] = True
    elif trigger == 'PreAuthentication_Authentication':
        if event['request'].get('validationData', {}).get('risk') == 'blocked':
            raise Exception('native policy denial')
    elif trigger == 'PostConfirmation_ConfirmSignUp':
        assert event['request']['userAttributes']['email_verified'] == 'true'
        assert event['request']['userAttributes']['sub']
    else:
        raise Exception('unexpected trigger source')
    return event
`
			created, err := functions.CreateFunction(t.Context(), &lambda.CreateFunctionInput{FunctionName: aws.String("cognito-classic-hook"), Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"), Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureX8664}, Timeout: aws.Int32(5), Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"handler.py": source})}})
			if err != nil {
				t.Fatal(err)
			}
			if err := lambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: created.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			pool, err := idp.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("native-classic"), UsernameAttributes: []idptypes.UsernameAttributeType{idptypes.UsernameAttributeTypeEmail}, LambdaConfig: &idptypes.LambdaConfigType{PreSignUp: created.FunctionArn, PreAuthentication: created.FunctionArn, PostConfirmation: created.FunctionArn}})
			if err != nil {
				t.Fatal(err)
			}
			client, err := idp.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientName: aws.String("native-client"), ExplicitAuthFlows: []idptypes.ExplicitAuthFlowsType{idptypes.ExplicitAuthFlowsTypeAllowUserPasswordAuth}})
			if err != nil {
				t.Fatal(err)
			}
			signup := &cognitoidentityprovider.SignUpInput{ClientId: client.UserPoolClient.ClientId, Username: aws.String("native@example.invalid"), Password: aws.String("Password123!"), ValidationData: []idptypes.AttributeType{{Name: aws.String("invite"), Value: aws.String("valid")}}}
			_, err = idp.SignUp(t.Context(), signup)
			assertAPIError(t, err, "UnexpectedLambdaException")
			_, err = idp.AdminGetUser(t.Context(), &cognitoidentityprovider.AdminGetUserInput{UserPoolId: pool.UserPool.Id, Username: signup.Username})
			assertAPIError(t, err, "UserNotFoundException")
			_, err = functions.AddPermission(t.Context(), &lambda.AddPermissionInput{FunctionName: created.FunctionArn, StatementId: aws.String("cognito-pool"), Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("cognito-idp.amazonaws.com"), SourceArn: pool.UserPool.Arn, SourceAccount: aws.String(cognitoGuardAccount)})
			if err != nil {
				t.Fatal(err)
			}
			registered, err := idp.SignUp(t.Context(), signup)
			if err != nil || !registered.UserConfirmed {
				t.Fatalf("native signup=%v err=%v", registered, err)
			}
			auth := &cognitoidentityprovider.InitiateAuthInput{ClientId: client.UserPoolClient.ClientId, AuthFlow: idptypes.AuthFlowTypeUserPasswordAuth, AuthParameters: map[string]string{"USERNAME": aws.ToString(signup.Username), "PASSWORD": aws.ToString(signup.Password)}, ClientMetadata: map[string]string{"risk": "blocked"}}
			_, err = idp.InitiateAuth(t.Context(), auth)
			assertAPIError(t, err, "UserLambdaValidationException")
			auth.ClientMetadata = map[string]string{"risk": "allowed"}
			authenticated, err := idp.InitiateAuth(t.Context(), auth)
			if err != nil || authenticated.AuthenticationResult == nil || aws.ToString(authenticated.AuthenticationResult.AccessToken) == "" {
				t.Fatalf("native allowed auth=%v err=%v", authenticated, err)
			}
			other, err := idp.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("other-source-pool"), LambdaConfig: &idptypes.LambdaConfigType{PreSignUp: created.FunctionArn}})
			if err != nil {
				t.Fatal(err)
			}
			otherClient, err := idp.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: other.UserPool.Id, ClientName: aws.String("other-source-client")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = idp.SignUp(t.Context(), &cognitoidentityprovider.SignUpInput{ClientId: otherClient.UserPoolClient.ClientId, Username: aws.String("source-mismatch"), Password: signup.Password})
			assertAPIError(t, err, "UnexpectedLambdaException")
			_, err = functions.RemovePermission(t.Context(), &lambda.RemovePermissionInput{FunctionName: created.FunctionArn, StatementId: aws.String("cognito-pool")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = idp.InitiateAuth(t.Context(), auth)
			assertAPIError(t, err, "UnexpectedLambdaException")
		})
	}
}
