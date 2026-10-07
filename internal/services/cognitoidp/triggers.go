package cognitoidp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awswire"
)

// TriggerInvoker executes customer code synchronously through the native Lambda
// service, using the pool's service principal and current function resource policy.
// It must never be called with a repository transaction context.
type TriggerInvoker interface {
	InvokeTrigger(context.Context, PoolKey, string, []byte) ([]byte, error)
}

type triggerEvent struct {
	Version       string         `json:"version"`
	TriggerSource string         `json:"triggerSource"`
	Region        string         `json:"region"`
	UserPoolID    string         `json:"userPoolId"`
	UserName      string         `json:"userName"`
	CallerContext triggerCaller  `json:"callerContext"`
	Request       triggerRequest `json:"request"`
	Response      any            `json:"response"`
}
type triggerCaller struct {
	AWSSDKVersion string `json:"awsSdkVersion"`
	ClientID      string `json:"clientId"`
}
type triggerRequest struct {
	UserAttributes map[string]string `json:"userAttributes"`
	ValidationData map[string]string `json:"validationData,omitempty"`
	ClientMetadata map[string]string `json:"clientMetadata,omitempty"`
	UserNotFound   *bool             `json:"userNotFound,omitempty"`
}
type preSignUpResponse struct {
	AutoConfirmUser bool `json:"autoConfirmUser"`
	AutoVerifyEmail bool `json:"autoVerifyEmail"`
	AutoVerifyPhone bool `json:"autoVerifyPhone"`
}
type triggerCall struct {
	pool   PoolRecord
	client ClientRecord
	arn    string
	event  triggerEvent
}
type triggerCommandKey struct{}
type triggerCommand struct {
	authenticate    bool
	probing         bool
	pre             *triggerCall
	approved        bool
	signUp          preSignUpResponse
	initialUser     *UserRecord
	initialUsername string
	post            []triggerCall
	validationData  map[string]string
	clientMetadata  map[string]string
}

var errTriggerProbe = errors.New("cognito trigger preflight completed")

func validateLambdaConfig(config *api.LambdaConfigType, tier string) error {
	if config == nil {
		return nil
	}
	// TODO: Comeback implement the other Lambda triggers before admitting their
	// configuration; these four triggers are not the entire Cognito lifecycle.
	unsupported := *config
	unsupported.PreSignUp, unsupported.PreAuthentication, unsupported.PostConfirmation, unsupported.InboundFederation = nil, nil, nil, nil
	if unsupported != (api.LambdaConfigType{}) {
		return failure("InvalidParameterException", "Only PreSignUp, PreAuthentication, PostConfirmation and InboundFederation Lambda triggers are supported.")
	}
	functions := []*api.ArnType{config.PreSignUp, config.PreAuthentication, config.PostConfirmation}
	if config.InboundFederation != nil {
		if tier == "LITE" || value(config.InboundFederation.LambdaVersion) != "V1_0" || config.InboundFederation.LambdaArn == nil {
			return failure("InvalidParameterException", "InboundFederation requires the ESSENTIALS tier and LambdaVersion V1_0.")
		}
		functions = append(functions, config.InboundFederation.LambdaArn)
	}
	for _, function := range functions {
		if function == nil {
			continue
		}
		a, err := arn.Parse(value(function))
		parts := strings.Split(a.Resource, ":")
		if err != nil || a.Partition == "" || a.Service != "lambda" || a.Region == "" || len(a.AccountID) != 12 || len(parts) < 2 || len(parts) > 3 || parts[0] != "function" || parts[1] == "" || (len(parts) == 3 && (parts[2] == "" || parts[2] == "$LATEST")) {
			return failure("InvalidParameterException", "Lambda triggers require a Lambda function ARN, optionally qualified by a version or alias.")
		}
	}
	return nil
}

func triggerAttributes(user UserRecord, signingUp bool) map[string]string {
	attributes := make(map[string]string, len(user.Data.Attributes))
	for _, attribute := range user.Data.Attributes {
		name := value(attribute.Name)
		if signingUp && name == "sub" {
			continue
		}
		attributes[name] = value(attribute.Value)
	}
	return attributes
}
func newTriggerEvent(pool PoolRecord, source, clientID, username string, attributes, validation, metadata map[string]string, response any) triggerEvent {
	if clientID == "" {
		clientID = "CLIENT_ID_NOT_APPLICABLE"
	}
	return triggerEvent{Version: "1", TriggerSource: source, Region: pool.Key.Region, UserPoolID: pool.Key.ID, UserName: username, CallerContext: triggerCaller{AWSSDKVersion: "aws-sdk-unknown-unknown", ClientID: clientID}, Request: triggerRequest{UserAttributes: attributes, ValidationData: validation, ClientMetadata: metadata}, Response: response}
}
func (s *Service) invokeTrigger(ctx context.Context, pool PoolRecord, functionARN string, event any) ([]byte, error) {
	if s.triggerInvoker == nil {
		return nil, failure("UnexpectedLambdaException", "Lambda trigger execution is not configured.")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := s.triggerInvoker.InvokeTrigger(ctx, pool.Key, functionARN, payload)
	if err != nil {
		var rejected *awswire.Error
		if errors.As(err, &rejected) {
			return nil, rejected
		}
		return nil, failure("UnexpectedLambdaException", "Cognito Lambda trigger invocation failed: "+err.Error())
	}
	// Classic triggers must return the event, not a null/scalar or HTTP envelope.
	if original, ok := event.(triggerEvent); ok {
		var returned struct {
			Version       string          `json:"version"`
			TriggerSource string          `json:"triggerSource"`
			Region        string          `json:"region"`
			UserPoolID    string          `json:"userPoolId"`
			UserName      string          `json:"userName"`
			Response      json.RawMessage `json:"response"`
		}
		if json.Unmarshal(response, &returned) != nil || returned.Version != original.Version || returned.TriggerSource != original.TriggerSource || returned.Region != original.Region || returned.UserPoolID != original.UserPoolID || returned.UserName != original.UserName || len(returned.Response) == 0 || returned.Response[0] != '{' {
			return nil, failure("InvalidLambdaResponseException", "Lambda trigger returned an invalid Cognito event.")
		}
	}
	return response, nil
}
func decodePreSignUpResponse(payload []byte) (preSignUpResponse, error) {
	var returned struct {
		Response preSignUpResponse `json:"response"`
	}
	if err := json.Unmarshal(payload, &returned); err != nil {
		return preSignUpResponse{}, failure("InvalidLambdaResponseException", "Invalid PreSignUp response flags.")
	}
	return returned.Response, nil
}
func (s *Service) invokePreSignUp(ctx context.Context, pool PoolRecord, source, clientID, username string, attributes, validationData, clientMetadata map[string]string) (preSignUpResponse, error) {
	if pool.Data.LambdaConfig == nil || pool.Data.LambdaConfig.PreSignUp == nil {
		return preSignUpResponse{}, nil
	}
	event := newTriggerEvent(pool, source, clientID, username, attributes, validationData, clientMetadata, preSignUpResponse{})
	payload, err := s.invokeTrigger(ctx, pool, value(pool.Data.LambdaConfig.PreSignUp), event)
	if err != nil {
		return preSignUpResponse{}, err
	}
	return decodePreSignUpResponse(payload)
}

func commandTriggerInput(input any, prepared *triggerCommand) (poolID, clientID, trigger string, relevant bool) {
	trigger = "PreAuthentication"
	switch in := input.(type) {
	case *api.SignUpInput:
		clientID, trigger = value(in.ClientId), "PreSignUp"
		prepared.clientMetadata = stringMap(in.ClientMetadata)
		prepared.validationData = attributeMap(in.ValidationData)
	case *api.AdminCreateUserInput:
		poolID, trigger = value(in.UserPoolId), "PreSignUp"
		if value(in.MessageAction) == "RESEND" {
			return "", "", "", false
		}
		prepared.clientMetadata = stringMap(in.ClientMetadata)
		prepared.validationData = attributeMap(in.ValidationData)
	case *api.InitiateAuthInput:
		if value(in.AuthFlow) != "USER_PASSWORD_AUTH" && value(in.AuthFlow) != "USER_SRP_AUTH" {
			return "", "", "", false
		}
		clientID = value(in.ClientId)
		prepared.validationData = stringMap(in.ClientMetadata)
	case *api.AdminInitiateAuthInput:
		if value(in.AuthFlow) != "ADMIN_USER_PASSWORD_AUTH" && value(in.AuthFlow) != "ADMIN_NO_SRP_AUTH" && value(in.AuthFlow) != "USER_SRP_AUTH" {
			return "", "", "", false
		}
		poolID, clientID = value(in.UserPoolId), value(in.ClientId)
		prepared.validationData = stringMap(in.ClientMetadata)
	default:
		return "", "", "", false
	}
	prepared.authenticate = trigger == "PreAuthentication"
	return poolID, clientID, trigger, true
}
func stringMap(input api.ClientMetadataType) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[string(key)] = string(value)
	}
	return out
}
func attributeMap(input api.AttributeListType) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for _, attribute := range input {
		out[value(attribute.Name)] = value(attribute.Value)
	}
	return out
}
func prepareCommandTriggers[I, O any](s *Service, ctx context.Context, in *I, fn func(Transaction, *I) (*O, error), prepared *triggerCommand) error {
	poolID, clientID, trigger, relevant := commandTriggerInput(in, prepared)
	if !relevant {
		return nil
	}
	configured := false
	// This lookup is not authorization: the probe below repeats the full command
	// validation, and the committing transaction revalidates it a third time.
	err := s.repository.View(ctx, func(r Reader) error {
		var pool PoolRecord
		var err error
		if poolID != "" {
			pool, err = r.Pool(PoolKey{Scope: scopeFor(ctx), ID: poolID})
		} else {
			client, clientErr := publicClient(r, clientID)
			if clientErr != nil {
				return nil
			}
			pool, err = r.Pool(client.Key.PoolKey)
		}
		if err != nil || pool.Data.LambdaConfig == nil {
			return nil
		}
		if trigger == "PreSignUp" {
			configured = pool.Data.LambdaConfig.PreSignUp != nil
		} else {
			configured = pool.Data.LambdaConfig.PreAuthentication != nil
		}
		return nil
	})
	if err != nil || !configured {
		return err
	}
	prepared.probing = true
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := fn(tx, in)
		if err != nil {
			return err
		}
		return errTriggerProbe
	})
	prepared.probing = false
	prepared.post = nil
	if !errors.Is(err, errTriggerProbe) {
		return err
	}
	if prepared.pre == nil {
		return nil
	}
	payload, err := s.invokeTrigger(ctx, prepared.pre.pool, prepared.pre.arn, prepared.pre.event)
	if err != nil {
		return err
	}
	if trigger == "PreSignUp" {
		prepared.signUp, err = decodePreSignUpResponse(payload)
		if err != nil {
			return err
		}
	}
	prepared.approved = true
	return nil
}
func (s *Service) preAuthentication(tx Transaction, pool PoolRecord, client ClientRecord, user UserRecord) error {
	if pool.Data.LambdaConfig == nil || pool.Data.LambdaConfig.PreAuthentication == nil {
		return nil
	}
	prepared, _ := tx.Context().Value(triggerCommandKey{}).(*triggerCommand)
	if prepared != nil && !prepared.authenticate {
		return nil
	}
	event := newTriggerEvent(pool, "PreAuthentication_Authentication", client.Key.ID, user.Key.Username, triggerAttributes(user, false), commandValidation(prepared), nil, struct{}{})
	if value(client.Data.PreventUserExistenceErrors) == "ENABLED" {
		event.Request.UserNotFound = ptr(false)
	}
	return s.prepareTrigger(tx, triggerCall{pool: pool, client: client, arn: value(pool.Data.LambdaConfig.PreAuthentication), event: event})
}
func (s *Service) preAuthenticationMissing(tx Transaction, pool PoolRecord, client ClientRecord, username string) error {
	if pool.Data.LambdaConfig == nil || pool.Data.LambdaConfig.PreAuthentication == nil {
		return nil
	}
	prepared, _ := tx.Context().Value(triggerCommandKey{}).(*triggerCommand)
	event := newTriggerEvent(pool, "PreAuthentication_Authentication", client.Key.ID, canonicalUsername(pool, username), map[string]string{}, commandValidation(prepared), nil, struct{}{})
	event.Request.UserNotFound = ptr(true)
	return s.prepareTrigger(tx, triggerCall{pool: pool, client: client, arn: value(pool.Data.LambdaConfig.PreAuthentication), event: event})
}
func commandValidation(prepared *triggerCommand) map[string]string {
	if prepared == nil {
		return nil
	}
	return prepared.validationData
}
func (s *Service) prepareTrigger(tx Transaction, call triggerCall) error {
	prepared, _ := tx.Context().Value(triggerCommandKey{}).(*triggerCommand)
	if prepared == nil {
		return failure("UnexpectedLambdaException", "Lambda trigger preflight is required.")
	}
	if prepared.probing {
		prepared.pre = &call
		return errTriggerProbe
	}
	if !prepared.approved || prepared.pre == nil || !reflect.DeepEqual(prepared.pre.pool, call.pool) || !reflect.DeepEqual(prepared.pre.client, call.client) || !reflect.DeepEqual(prepared.pre.event, call.event) || prepared.pre.arn != call.arn {
		return failure("NotAuthorizedException", "User pool, client or user changed during Lambda trigger execution. Retry the request.")
	}
	return nil
}

// Keep the randomly assigned sub/username stable between preflight and commit,
// without accepting any attribute edits or account writes from the probe.
func (s *Service) initializeSignUpUser(tx Transaction, pool PoolRecord, username string) (UserRecord, error) {
	prepared, _ := tx.Context().Value(triggerCommandKey{}).(*triggerCommand)
	if prepared != nil && prepared.approved && prepared.initialUser != nil && prepared.initialUsername == username && prepared.initialUser.Key.PoolKey == pool.Key {
		return copyUserRecord(*prepared.initialUser), nil
	}
	user, err := initializeUser(pool, username)
	if err == nil && prepared != nil && prepared.probing {
		initial := copyUserRecord(user)
		prepared.initialUser, prepared.initialUsername = &initial, username
	}
	return user, err
}
func (s *Service) preSignUp(tx Transaction, pool PoolRecord, client ClientRecord, user *UserRecord, admin bool) error {
	if pool.Data.LambdaConfig == nil || pool.Data.LambdaConfig.PreSignUp == nil {
		return nil
	}
	prepared, _ := tx.Context().Value(triggerCommandKey{}).(*triggerCommand)
	source := "PreSignUp_SignUp"
	if admin {
		source = "PreSignUp_AdminCreateUser"
	}
	var validation, metadata map[string]string
	if prepared != nil {
		validation, metadata = prepared.validationData, prepared.clientMetadata
	}
	call := triggerCall{pool: pool, client: client, arn: value(pool.Data.LambdaConfig.PreSignUp), event: newTriggerEvent(pool, source, client.Key.ID, user.Key.Username, triggerAttributes(*user, true), validation, metadata, preSignUpResponse{})}
	if err := s.prepareTrigger(tx, call); err != nil {
		return err
	}
	// AdminCreateUser ignores all three response flags, as documented by AWS.
	if !admin {
		if prepared.signUp.AutoConfirmUser {
			user.Data.UserStatus = str[api.UserStatusType]("CONFIRMED")
		}
		if prepared.signUp.AutoVerifyEmail {
			if userAttribute(*user, "email") == "" {
				return failure("InvalidParameterException", "AutoVerifyEmail requires an email attribute.")
			}
			putUserAttribute(user, "email_verified", "true")
		}
		if prepared.signUp.AutoVerifyPhone {
			if userAttribute(*user, "phone_number") == "" {
				return failure("InvalidParameterException", "AutoVerifyPhone requires a phone_number attribute.")
			}
			putUserAttribute(user, "phone_number_verified", "true")
		}
	}
	return nil
}
func (s *Service) postConfirmation(tx Transaction, pool PoolRecord, clientID string, user UserRecord, source string, metadata api.ClientMetadataType) {
	if pool.Data.LambdaConfig == nil || pool.Data.LambdaConfig.PostConfirmation == nil {
		return
	}
	prepared, _ := tx.Context().Value(triggerCommandKey{}).(*triggerCommand)
	if prepared == nil || prepared.probing {
		return
	}
	prepared.post = append(prepared.post, triggerCall{pool: pool, arn: value(pool.Data.LambdaConfig.PostConfirmation), event: newTriggerEvent(pool, source, clientID, user.Key.Username, triggerAttributes(user, false), nil, stringMap(metadata), struct{}{})})
}
