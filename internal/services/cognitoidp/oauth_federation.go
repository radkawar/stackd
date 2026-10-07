package cognitoidp

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	api "stackd/internal/awsapi/cognitoidp"
)

// inboundFederationEvent is the documented V1_0 InboundFederation trigger
// request: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-inbound-federation.html
type inboundFederationEvent struct {
	Version       string `json:"version"`
	TriggerSource string `json:"triggerSource"`
	Region        string `json:"region"`
	UserPoolID    string `json:"userPoolId"`
	UserName      string `json:"userName"`
	CallerContext struct {
		AWSSDKVersion string `json:"awsSdkVersion"`
		ClientID      string `json:"clientId"`
	} `json:"callerContext"`
	Request struct {
		ProviderName string `json:"providerName"`
		ProviderType string `json:"providerType"`
		Attributes   struct {
			TokenResponse map[string]string `json:"tokenResponse"`
			IDToken       map[string]string `json:"idToken"`
			UserInfo      map[string]string `json:"userInfo"`
		} `json:"attributes"`
	} `json:"request"`
	Response struct {
		UserAttributesToMap map[string]string `json:"userAttributesToMap"`
	} `json:"response"`
}

// inboundFederation returns the identity provider attributes that feed the
// provider's AttributeMapping. With a V1_0 InboundFederation trigger, a
// nonempty response.userAttributesToMap replaces the provider attributes:
// omitted attributes are dropped. An empty map keeps the original attributes.
func (s *Service) inboundFederation(ctx context.Context, pool PoolRecord, client ClientRecord, provider ProviderRecord, username string, identity upstreamIdentity) (map[string]string, error) {
	source := identity.attributes()
	config := pool.Data.LambdaConfig
	if config == nil || config.InboundFederation == nil || value(config.InboundFederation.LambdaArn) == "" {
		return source, nil
	}
	if version := value(config.InboundFederation.LambdaVersion); version != "V1_0" {
		return nil, failure("InvalidLambdaResponseException", "Unsupported InboundFederation Lambda version "+version+".")
	}
	var event inboundFederationEvent
	event.Version = "1"
	event.TriggerSource = "InboundFederation_ExternalProvider"
	event.Region = pool.Key.Region
	event.UserPoolID = pool.Key.ID
	event.UserName = username
	event.CallerContext.AWSSDKVersion = "aws-sdk-unknown-unknown"
	event.CallerContext.ClientID = client.Key.ID
	event.Request.ProviderName = provider.Key.Name
	event.Request.ProviderType = value(provider.Data.ProviderType)
	event.Request.Attributes.TokenResponse = identity.TokenResponse
	event.Request.Attributes.IDToken = identity.IDToken
	event.Request.Attributes.UserInfo = identity.UserInfo
	event.Response.UserAttributesToMap = map[string]string{}
	out, err := s.invokeTrigger(ctx, pool, value(config.InboundFederation.LambdaArn), event)
	if err != nil {
		return nil, err
	}
	var response struct {
		TriggerSource string `json:"triggerSource"`
		UserPoolID    string `json:"userPoolId"`
		UserName      string `json:"userName"`
		Response      *struct {
			UserAttributesToMap map[string]string `json:"userAttributesToMap"`
		} `json:"response"`
	}
	// The function must return the whole event with a string-to-string map.
	if err := json.Unmarshal(out, &response); err != nil || response.Response == nil || response.TriggerSource != event.TriggerSource || response.UserPoolID != event.UserPoolID || response.UserName != event.UserName {
		return nil, failure("InvalidLambdaResponseException", "Invalid InboundFederation Lambda response: return the event with response.userAttributesToMap mapping strings to strings.")
	}
	if len(response.Response.UserAttributesToMap) == 0 {
		return source, nil
	}
	return response.Response.UserAttributesToMap, nil
}

// federatedAttributes applies AttributeMapping (user pool attribute ->
// provider attribute) to the provider attributes, in deterministic order.
func federatedAttributes(pool PoolRecord, provider ProviderRecord, source map[string]string) api.AttributeListType {
	names := make([]string, 0, len(provider.Data.AttributeMapping))
	for name := range provider.Data.AttributeMapping {
		if name != "username" && schemaAttribute(pool, string(name)) != nil {
			names = append(names, string(name))
		}
	}
	slices.Sort(names)
	out := make(api.AttributeListType, 0, len(names))
	for _, name := range names {
		if v, ok := source[string(provider.Data.AttributeMapping[api.AttributeMappingKeyType(name)])]; ok {
			out = append(out, api.AttributeType{Name: str[api.AttributeNameType](name), Value: str[api.AttributeValueType](v)})
		}
	}
	return out
}

func attributeValues(attributes api.AttributeListType) map[string]string {
	out := make(map[string]string, len(attributes))
	for _, a := range attributes {
		out[value(a.Name)] = value(a.Value)
	}
	return out
}

// putFederatedUser creates the EXTERNAL_PROVIDER user on first sign-in or
// refreshes its mapped attributes on later sign-ins. signup is the
// PreSignUp_ExternalProvider response obtained outside the transaction; it is
// nil when the user already existed then, so a user deleted meanwhile is not
// recreated without that trigger.
func (s *Service) putFederatedUser(tx Transaction, pool PoolRecord, provider ProviderRecord, username, subject string, attributes api.AttributeListType, signup *preSignUpResponse) (UserRecord, error) {
	now := s.clock.Now()
	user, err := tx.User(UserKey{PoolKey: pool.Key, Username: username})
	switch {
	case err == nil:
		if value(user.Data.UserStatus) != "EXTERNAL_PROVIDER" {
			return UserRecord{}, oauthReject("invalid_request", "A user with the federated username already exists.")
		}
		if err := userEnabled(user); err != nil {
			return UserRecord{}, err
		}
		changed := make(api.AttributeListType, 0, len(attributes))
		for _, a := range attributes {
			schema := schemaAttribute(pool, value(a.Name))
			if schema != nil && schema.Mutable != nil && !bool(*schema.Mutable) && userAttribute(user, value(a.Name)) == value(a.Value) {
				continue
			}
			changed = append(changed, a)
		}
		if err := setUserAttributes(pool, &user, changed, nil); err != nil {
			return UserRecord{}, err
		}
		user.Data.UserLastModifiedDate = &now
	case errors.Is(err, ErrNotFound):
		if signup == nil {
			return UserRecord{}, oauthReject("invalid_request", "The federated user changed during sign-in; retry the sign-in.")
		}
		sub, err := usernameUUID()
		if err != nil {
			return UserRecord{}, err
		}
		user = UserRecord{Key: UserKey{PoolKey: pool.Key, Username: username}}
		user.Data.Username = str[api.UsernameType](username)
		putUserAttribute(&user, "sub", sub)
		if err := setUserAttributes(pool, &user, attributes, nil); err != nil {
			return UserRecord{}, err
		}
		if signup.AutoVerifyEmail {
			if userAttribute(user, "email") == "" {
				return UserRecord{}, failure("InvalidParameterException", "PreSignUp autoVerifyEmail requires an email attribute.")
			}
			putUserAttribute(&user, "email_verified", "true")
		}
		if signup.AutoVerifyPhone {
			if userAttribute(user, "phone_number") == "" {
				return UserRecord{}, failure("InvalidParameterException", "PreSignUp autoVerifyPhone requires a phone_number attribute.")
			}
			putUserAttribute(&user, "phone_number_verified", "true")
		}
		identities, err := json.Marshal([]map[string]any{{
			"userId": subject, "providerName": provider.Key.Name, "providerType": value(provider.Data.ProviderType),
			"issuer": nil, "primary": "true", "dateCreated": strconv.FormatInt(now.UnixMilli(), 10),
		}})
		if err != nil {
			return UserRecord{}, err
		}
		putUserAttribute(&user, "identities", string(identities))
		for _, attribute := range pool.Data.SchemaAttributes {
			name := value(attribute.Name)
			if name != "sub" && attribute.Required != nil && bool(*attribute.Required) && userAttribute(user, name) == "" {
				return UserRecord{}, failure("InvalidParameterException", "Missing required attribute "+name+" from the identity provider attribute mapping.")
			}
		}
		user.Data.UserStatus = str[api.UserStatusType]("EXTERNAL_PROVIDER")
		user.Data.Enabled = ptr(api.BooleanType(true))
		user.Data.UserCreateDate = &now
		user.Data.UserLastModifiedDate = &now
	default:
		return UserRecord{}, err
	}
	if err := tx.PutUser(user); err != nil {
		return UserRecord{}, err
	}
	noteUser(tx.Context(), user)
	return user, nil
}
