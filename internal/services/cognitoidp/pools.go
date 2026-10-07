package cognitoidp

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/cognitoidp"
)

func registerControl(s *Service) {
	register(s, "CreateUserPool", s.createUserPool)
	register(s, "DescribeUserPool", s.describeUserPool)
	register(s, "UpdateUserPool", s.updateUserPool)
	register(s, "DeleteUserPool", s.deleteUserPool)
	register(s, "ListUserPools", s.listUserPools)
	register(s, "AddCustomAttributes", s.addCustomAttributes)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "CreateUserPoolClient", s.createUserPoolClient)
	register(s, "DescribeUserPoolClient", s.describeUserPoolClient)
	register(s, "UpdateUserPoolClient", s.updateUserPoolClient)
	register(s, "DeleteUserPoolClient", s.deleteUserPoolClient)
	register(s, "ListUserPoolClients", s.listUserPoolClients)
	register(s, "AdminCreateUser", s.adminCreateUser)
	register(s, "AdminGetUser", s.adminGetUser)
	register(s, "AdminDeleteUser", s.adminDeleteUser)
	register(s, "AdminEnableUser", s.adminEnableUser)
	register(s, "AdminDisableUser", s.adminDisableUser)
	register(s, "AdminSetUserPassword", s.adminSetUserPassword)
	register(s, "AdminConfirmSignUp", s.adminConfirmSignUp)
	register(s, "AdminUpdateUserAttributes", s.adminUpdateUserAttributes)
	register(s, "AdminDeleteUserAttributes", s.adminDeleteUserAttributes)
	register(s, "ListUsers", s.listUsers)
}

func validControlName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) && !strings.ContainsRune("_+=,.@-", r) {
			return false
		}
	}
	return true
}

func (s *Service) createUserPool(tx Transaction, in *api.CreateUserPoolInput) (*api.CreateUserPoolOutput, error) {
	if err := s.authorize(tx, "cognito-idp:CreateUserPool", "*", requestTagConditions(in.UserPoolTags)); err != nil {
		return nil, err
	}
	data, err := poolConfiguration(in)
	if err != nil {
		return nil, err
	}
	data.SchemaAttributes, err = poolSchema(in.Schema)
	if err != nil {
		return nil, err
	}
	id, err := controlID(6)
	if err != nil {
		return nil, err
	}
	key := PoolKey{Scope: scopeFor(tx.Context())}
	key.ID = key.Region + "_" + id
	keys := PoolSigningKeys{}
	keys.Access, err = newSigningKey()
	if err != nil {
		return nil, err
	}
	keys.ID, err = newSigningKey()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	data.Id = str[api.UserPoolIdType](key.ID)
	data.Arn = str[api.ArnType](key.ARN())
	data.CreationDate = &now
	data.LastModifiedDate = &now
	data.EstimatedNumberOfUsers = ptr(api.IntegerType(0))
	pool := PoolRecord{Key: key, Data: data, IssuerURL: poolIssuerURL(key, s.publicEndpoint)}
	if err := applySoftwareTokenPoolIntent(tx.Context(), &pool); err != nil {
		return nil, err
	}
	if err = s.prepareEmail(tx, pool); err != nil {
		return nil, err
	}
	if err = tx.PutPool(pool); err != nil {
		return nil, err
	}
	if err = tx.PutSigningKeys(key, keys); err != nil {
		return nil, err
	}
	notePool(tx.Context(), key)
	return &api.CreateUserPoolOutput{UserPool: &data}, nil
}

// Only configurations with implemented runtime behavior are admitted.
// TODO: Comeback implement SMS, devices, customer-managed pool keys and advanced
// security before admitting their active configurations.
func poolConfiguration(in *api.CreateUserPoolInput) (api.UserPoolType, error) {
	var d api.UserPoolType
	invalid := func(message string) (api.UserPoolType, error) {
		return d, failure("InvalidParameterException", message)
	}
	unsupported := func(message string) (api.UserPoolType, error) {
		return d, failure("InvalidParameterException", message+" is not supported.")
	}
	if !validControlName(value(in.PoolName)) {
		return invalid("Invalid user pool name.")
	}
	if in.DeviceConfiguration != nil {
		return unsupported("Device remembering")
	}
	if err := validateLambdaConfig(in.LambdaConfig, value(in.UserPoolTier)); err != nil {
		return d, err
	}
	if mode := value(in.MfaConfiguration); mode != "" && mode != "OFF" && mode != "OPTIONAL" && mode != "ON" {
		return invalid("Invalid MFA configuration.")
	}
	if in.SmsConfiguration != nil || in.SmsAuthenticationMessage != nil || in.SmsVerificationMessage != nil {
		return unsupported("SMS message delivery configuration")
	}
	if config := in.EmailConfiguration; config != nil {
		mode := value(config.EmailSendingAccount)
		if mode != "" && mode != "COGNITO_DEFAULT" && mode != "DEVELOPER" {
			return invalid("Invalid EmailSendingAccount.")
		}
		if mode != "DEVELOPER" && (config.SourceArn != nil || config.From != nil || config.ConfigurationSet != nil || config.ReplyToEmailAddress != nil) {
			return unsupported("Custom COGNITO_DEFAULT sender authorization")
		}
		if mode == "DEVELOPER" && value(config.SourceArn) == "" {
			return invalid("SourceArn is required with DEVELOPER email.")
		}
	}
	if t := in.AdminCreateUserConfig; t != nil && t.InviteMessageTemplate != nil {
		if t.InviteMessageTemplate.SMSMessage != nil {
			return unsupported("SMS invitation messages")
		}
		if err := emailTemplate(value(t.InviteMessageTemplate.EmailMessage), value(t.InviteMessageTemplate.EmailSubject), true); err != nil {
			return d, err
		}
	}
	verification := &api.VerificationMessageTemplateType{DefaultEmailOption: str[api.DefaultEmailOptionType]("CONFIRM_WITH_CODE")}
	if v := in.VerificationMessageTemplate; v != nil {
		if v.EmailMessageByLink != nil || v.EmailSubjectByLink != nil || (value(v.DefaultEmailOption) != "" && value(v.DefaultEmailOption) != "CONFIRM_WITH_CODE") {
			return unsupported("Link verification messages")
		}
		if v.SmsMessage != nil {
			return unsupported("SMS verification messages")
		}
		verification.EmailMessage, verification.EmailSubject = v.EmailMessage, v.EmailSubject
	}
	// The legacy members are aliases of the template's code-message members.
	for _, alias := range []struct{ legacy, template *string }{
		{(*string)(in.EmailVerificationMessage), (*string)(verification.EmailMessage)},
		{(*string)(in.EmailVerificationSubject), (*string)(verification.EmailSubject)},
	} {
		if alias.legacy != nil && alias.template != nil && *alias.legacy != *alias.template {
			return invalid("EmailVerificationMessage and EmailVerificationSubject must match VerificationMessageTemplate.")
		}
	}
	if verification.EmailMessage == nil && in.EmailVerificationMessage != nil {
		verification.EmailMessage = ptr(api.EmailVerificationMessageType(*in.EmailVerificationMessage))
	}
	if verification.EmailSubject == nil && in.EmailVerificationSubject != nil {
		verification.EmailSubject = ptr(api.EmailVerificationSubjectType(*in.EmailVerificationSubject))
	}
	if verification.EmailMessage != nil || verification.EmailSubject != nil {
		if err := emailTemplate(value(verification.EmailMessage), value(verification.EmailSubject), false); err != nil {
			return d, err
		}
	}
	if in.UserPoolAddOns != nil && (value(in.UserPoolAddOns.AdvancedSecurityMode) != "OFF" || in.UserPoolAddOns.AdvancedSecurityAdditionalFlows != nil) {
		return unsupported("Advanced security")
	}
	if in.IssuerConfiguration != nil && value(in.IssuerConfiguration.Type) != "ORIGINAL" {
		return unsupported("Custom token issuers")
	}
	if in.KeyConfiguration != nil && (value(in.KeyConfiguration.KeyType) != "AWS_OWNED_KEY" || in.KeyConfiguration.KmsKeyArn != nil) {
		return unsupported("Customer-managed encryption keys")
	}
	if in.UserAttributeUpdateSettings != nil && len(in.UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate) > 0 {
		return unsupported("Attribute verification before update")
	}
	for _, attribute := range in.AutoVerifiedAttributes {
		if string(attribute) != "email" {
			return unsupported("Automatic phone verification")
		}
	}
	if len(in.AliasAttributes) > 0 && len(in.UsernameAttributes) > 0 {
		return invalid("AliasAttributes and UsernameAttributes cannot be configured together.")
	}
	seen := map[string]bool{}
	for _, a := range in.AliasAttributes {
		n := string(a)
		if (n != "email" && n != "phone_number" && n != "preferred_username") || seen[n] {
			return invalid("Invalid alias attributes.")
		}
		seen[n] = true
	}
	seen = map[string]bool{}
	for _, a := range in.UsernameAttributes {
		n := string(a)
		if (n != "email" && n != "phone_number") || seen[n] {
			return invalid("Invalid username attributes.")
		}
		seen[n] = true
	}
	if in.UsernameConfiguration != nil && in.UsernameConfiguration.CaseSensitive == nil {
		return invalid("CaseSensitive is required.")
	}
	tier := value(in.UserPoolTier)
	// API_CreateUserPool documents ESSENTIALS as the omitted tier. The native
	// workflow fixture explicitly selected LITE and is not default-tier evidence.
	if tier == "" {
		tier = "ESSENTIALS"
	}
	if tier != "LITE" && tier != "ESSENTIALS" {
		return unsupported("Requested user pool feature plan")
	}
	protection := value(in.DeletionProtection)
	if protection == "" {
		protection = "INACTIVE"
	}
	if protection != "ACTIVE" && protection != "INACTIVE" {
		return invalid("Invalid deletion protection.")
	}
	if err := validatePoolTags(in.UserPoolTags); err != nil {
		return d, err
	}
	policy, err := poolPasswordPolicy(in.Policies, in.AdminCreateUserConfig)
	if err != nil {
		return d, err
	}
	recovery := in.AccountRecoverySetting
	if recovery == nil {
		recovery = &api.AccountRecoverySettingType{RecoveryMechanisms: api.RecoveryMechanismsType{
			{Name: str[api.RecoveryOptionNameType]("verified_email"), Priority: ptr(api.PriorityType(1))},
			{Name: str[api.RecoveryOptionNameType]("verified_phone_number"), Priority: ptr(api.PriorityType(2))},
		}}
	} else {
		seenName := map[string]bool{}
		seenPriority := map[api.PriorityType]bool{}
		if len(recovery.RecoveryMechanisms) == 0 || len(recovery.RecoveryMechanisms) > 2 {
			return invalid("Invalid account recovery settings.")
		}
		for _, r := range recovery.RecoveryMechanisms {
			n := value(r.Name)
			if (n != "verified_email" && n != "verified_phone_number" && n != "admin_only") || r.Priority == nil || *r.Priority < 1 || *r.Priority > 2 || seenName[n] || seenPriority[*r.Priority] || (n == "admin_only" && len(recovery.RecoveryMechanisms) != 1) {
				return invalid("Invalid account recovery settings.")
			}
			seenName[n] = true
			seenPriority[*r.Priority] = true
		}
	}
	admin := &api.AdminCreateUserConfigType{AllowAdminCreateUserOnly: ptr(api.BooleanType(false)), UnusedAccountValidityDays: ptr(api.AdminCreateUserUnusedAccountValidityDaysType(7))}
	if in.AdminCreateUserConfig != nil {
		if in.AdminCreateUserConfig.AllowAdminCreateUserOnly != nil {
			admin.AllowAdminCreateUserOnly = in.AdminCreateUserConfig.AllowAdminCreateUserOnly
		}
		if in.AdminCreateUserConfig.UnusedAccountValidityDays != nil && *in.AdminCreateUserConfig.UnusedAccountValidityDays > 0 {
			admin.UnusedAccountValidityDays = in.AdminCreateUserConfig.UnusedAccountValidityDays
		}
		admin.InviteMessageTemplate = in.AdminCreateUserConfig.InviteMessageTemplate
	}
	d = api.UserPoolType{
		Name: in.PoolName, AliasAttributes: in.AliasAttributes, UsernameAttributes: in.UsernameAttributes, UsernameConfiguration: in.UsernameConfiguration,
		AutoVerifiedAttributes: in.AutoVerifiedAttributes,
		UserPoolTier:           str[api.UserPoolTierType](tier), DeletionProtection: str[api.DeletionProtectionType](protection), Policies: policy,
		AdminCreateUserConfig: admin, AccountRecoverySetting: recovery, LambdaConfig: &api.LambdaConfigType{},
		EmailConfiguration:  &api.EmailConfigurationType{EmailSendingAccount: str[api.EmailSendingAccountType]("COGNITO_DEFAULT")},
		IssuerConfiguration: &api.IssuerConfigurationType{Type: str[api.IssuerType]("ORIGINAL")},
		KeyConfiguration:    &api.KeyConfigurationType{KeyType: str[api.EncryptionKeyType]("AWS_OWNED_KEY")},
		MfaConfiguration:    in.MfaConfiguration, UserPoolTags: in.UserPoolTags, UserPoolAddOns: in.UserPoolAddOns,
		UserAttributeUpdateSettings: &api.UserAttributeUpdateSettingsType{AttributesRequireVerificationBeforeUpdate: api.AttributesRequireVerificationBeforeUpdateType{}},
		VerificationMessageTemplate: verification,
	}
	if d.MfaConfiguration == nil {
		d.MfaConfiguration = str[api.UserPoolMfaType]("OFF")
	}
	if in.LambdaConfig != nil {
		d.LambdaConfig = ptr(api.CloneLambdaConfigType(*in.LambdaConfig))
	}
	if verification.EmailMessage != nil {
		d.EmailVerificationMessage = ptr(api.EmailVerificationMessageType(*verification.EmailMessage))
	}
	if verification.EmailSubject != nil {
		d.EmailVerificationSubject = ptr(api.EmailVerificationSubjectType(*verification.EmailSubject))
	}
	if in.EmailConfiguration != nil {
		d.EmailConfiguration = in.EmailConfiguration
	}
	return d, nil
}

// emailTemplate validates the documented code placeholders. Invitations also
// name the user. Messages are delivered as plain text by the email owner.
func emailTemplate(message, subject string, invite bool) error {
	invalid := func(text string) error { return failure("InvalidParameterException", text) }
	if message != "" {
		if utf8.RuneCountInString(message) < 6 || utf8.RuneCountInString(message) > 20000 || !strings.Contains(message, "{####}") {
			return invalid("Email message must contain {####} and be 6 to 20000 characters.")
		}
		if invite && !strings.Contains(message, "{username}") {
			return invalid("Invitation email message must contain {username} and {####}.")
		}
	}
	if subject != "" && utf8.RuneCountInString(subject) > 140 {
		return invalid("Email subject must be at most 140 characters.")
	}
	return nil
}

func poolPasswordPolicy(in *api.UserPoolPolicyType, admin *api.AdminCreateUserConfigType) (*api.UserPoolPolicyType, error) {
	p := api.PasswordPolicyType{MinimumLength: ptr(api.PasswordPolicyMinLengthType(8)), RequireLowercase: ptr(api.BooleanType(true)), RequireUppercase: ptr(api.BooleanType(true)), RequireNumbers: ptr(api.BooleanType(true)), RequireSymbols: ptr(api.BooleanType(true)), TemporaryPasswordValidityDays: ptr(api.TemporaryPasswordValidityDaysType(7))}
	if admin != nil && admin.UnusedAccountValidityDays != nil {
		if *admin.UnusedAccountValidityDays < 0 || *admin.UnusedAccountValidityDays > 365 {
			return nil, failure("InvalidParameterException", "Invalid unused account validity days.")
		}
		if *admin.UnusedAccountValidityDays > 0 {
			p.TemporaryPasswordValidityDays = ptr(api.TemporaryPasswordValidityDaysType(*admin.UnusedAccountValidityDays))
		}
	}
	if in != nil {
		if in.SignInPolicy != nil && (len(in.SignInPolicy.AllowedFirstAuthFactors) != 1 || in.SignInPolicy.AllowedFirstAuthFactors[0] != "PASSWORD") {
			return nil, failure("InvalidParameterException", "Passwordless authentication is not supported.")
		}
		if x := in.PasswordPolicy; x != nil {
			if x.MinimumLength != nil {
				if *x.MinimumLength < 6 || *x.MinimumLength > 99 {
					return nil, failure("InvalidParameterException", "Invalid minimum password length.")
				}
				p.MinimumLength = x.MinimumLength
			}
			if x.PasswordHistorySize != nil && *x.PasswordHistorySize != 0 {
				return nil, failure("InvalidParameterException", "Password history is not supported.")
			}
			if x.RequireLowercase != nil {
				p.RequireLowercase = x.RequireLowercase
			}
			if x.RequireUppercase != nil {
				p.RequireUppercase = x.RequireUppercase
			}
			if x.RequireNumbers != nil {
				p.RequireNumbers = x.RequireNumbers
			}
			if x.RequireSymbols != nil {
				p.RequireSymbols = x.RequireSymbols
			}
			if x.TemporaryPasswordValidityDays != nil {
				if *x.TemporaryPasswordValidityDays < 0 || *x.TemporaryPasswordValidityDays > 365 {
					return nil, failure("InvalidParameterException", "Invalid temporary password validity days.")
				}
				if *x.TemporaryPasswordValidityDays > 0 {
					p.TemporaryPasswordValidityDays = x.TemporaryPasswordValidityDays
				}
			}
		}
	}
	return &api.UserPoolPolicyType{PasswordPolicy: &p, SignInPolicy: &api.SignInPolicyType{AllowedFirstAuthFactors: api.AllowedFirstAuthFactorsListType{"PASSWORD"}}}, nil
}

func (s *Service) describeUserPool(tx Transaction, in *api.DescribeUserPoolInput) (*api.DescribeUserPoolOutput, error) {
	pool, err := s.adminPool(tx, "DescribeUserPool", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	users, err := tx.Users(pool.Key)
	if err != nil {
		return nil, err
	}
	pool.Data.EstimatedNumberOfUsers = ptr(api.IntegerType(len(users)))
	if pool.Data.UserPoolTags == nil {
		pool.Data.UserPoolTags = api.UserPoolTagsType{}
	}
	// Describe exposes the service-managed federation attribute; Create does not
	// include it in the configurable schema.
	pool.Data.SchemaAttributes = append(pool.Data.SchemaAttributes, api.SchemaAttributeType{
		Name: str[api.CustomAttributeNameType]("identities"), AttributeDataType: str[api.AttributeDataType]("String"),
		DeveloperOnlyAttribute: ptr(api.BooleanType(false)), Mutable: ptr(api.BooleanType(true)),
		Required: ptr(api.BooleanType(false)), StringAttributeConstraints: &api.StringAttributeConstraintsType{},
	})
	return &api.DescribeUserPoolOutput{UserPool: &pool.Data}, nil
}

func (s *Service) updateUserPool(tx Transaction, in *api.UpdateUserPoolInput) (*api.UpdateUserPoolOutput, error) {
	pool, err := s.adminPoolConditions(tx, "UpdateUserPool", value(in.UserPoolId), requestTagConditions(in.UserPoolTags))
	if err != nil {
		return nil, err
	}
	config := api.CreateUserPoolInput{
		PoolName: in.PoolName, AccountRecoverySetting: in.AccountRecoverySetting, AdminCreateUserConfig: in.AdminCreateUserConfig,
		AutoVerifiedAttributes: in.AutoVerifiedAttributes, DeletionProtection: in.DeletionProtection, DeviceConfiguration: in.DeviceConfiguration,
		EmailConfiguration: in.EmailConfiguration, EmailVerificationMessage: in.EmailVerificationMessage, EmailVerificationSubject: in.EmailVerificationSubject,
		IssuerConfiguration: in.IssuerConfiguration, KeyConfiguration: in.KeyConfiguration, LambdaConfig: in.LambdaConfig, MfaConfiguration: in.MfaConfiguration, Policies: in.Policies,
		SmsAuthenticationMessage: in.SmsAuthenticationMessage, SmsConfiguration: in.SmsConfiguration, SmsVerificationMessage: in.SmsVerificationMessage,
		UserAttributeUpdateSettings: in.UserAttributeUpdateSettings, UserPoolAddOns: in.UserPoolAddOns, UserPoolTags: in.UserPoolTags, UserPoolTier: in.UserPoolTier,
		VerificationMessageTemplate: in.VerificationMessageTemplate, AliasAttributes: pool.Data.AliasAttributes, UsernameAttributes: pool.Data.UsernameAttributes, UsernameConfiguration: pool.Data.UsernameConfiguration,
	}
	if config.PoolName == nil {
		config.PoolName = pool.Data.Name
	}
	if config.UserPoolTier == nil {
		config.UserPoolTier = pool.Data.UserPoolTier
	}
	if config.UserPoolTags == nil {
		config.UserPoolTags = pool.Data.UserPoolTags
	}
	data, err := poolConfiguration(&config)
	if err != nil {
		return nil, err
	}
	if value(data.UserPoolTier) == "LITE" && value(pool.Data.UserPoolTier) != "LITE" {
		clients, err := tx.Clients(pool.Key)
		if err != nil {
			return nil, err
		}
		for _, client := range clients {
			if refreshRotationEnabled(client) {
				return nil, failure("TierChangeNotAllowedException", "The following features need to be disabled for the LITE pricing tier configured: Refresh Token Rotation")
			}
		}
	}
	data.Id = pool.Data.Id
	data.Arn = pool.Data.Arn
	data.CreationDate = pool.Data.CreationDate
	data.SchemaAttributes = pool.Data.SchemaAttributes
	now := s.clock.Now()
	data.LastModifiedDate = &now
	pool.Data = data
	if err := applySoftwareTokenPoolIntent(tx.Context(), &pool); err != nil {
		return nil, err
	}
	if err = s.prepareEmail(tx, pool); err != nil {
		return nil, err
	}
	if err = tx.PutPool(pool); err != nil {
		return nil, err
	}
	return &api.UpdateUserPoolOutput{}, nil
}
func (s *Service) deleteUserPool(tx Transaction, in *api.DeleteUserPoolInput) (*api.DeleteUserPoolOutput, error) {
	pool, err := s.adminPool(tx, "DeleteUserPool", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	if value(pool.Data.DeletionProtection) == "ACTIVE" {
		return nil, failure("InvalidParameterException", "User pool deletion protection is active.")
	}
	if value(pool.Data.Domain) != "" {
		return nil, failure("InvalidParameterException", "User pool cannot be deleted. It has a domain configured that should be deleted first.")
	}
	if err = tx.DeletePool(pool.Key); err != nil {
		return nil, err
	}
	return &api.DeleteUserPoolOutput{}, nil
}
func (s *Service) listUserPools(tx Transaction, in *api.ListUserPoolsInput) (*api.ListUserPoolsOutput, error) {
	if err := s.authorize(tx, "cognito-idp:ListUserPools", "*", nil); err != nil {
		return nil, err
	}
	if in.MaxResults == nil || *in.MaxResults < 1 || *in.MaxResults > 60 {
		return nil, failure("InvalidParameterException", "MaxResults must be between 1 and 60.")
	}
	scope := scopeFor(tx.Context())
	binding := "pools:" + scope.Partition + ":" + scope.AccountID + ":" + scope.Region
	cursor, err := pageCursor(value(in.NextToken), binding)
	if err != nil {
		return nil, err
	}
	pools, err := tx.Pools(scope)
	if err != nil {
		return nil, err
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].Key.ID < pools[j].Key.ID })
	out := &api.ListUserPoolsOutput{UserPools: api.UserPoolListType{}}
	for _, p := range pools {
		if p.Key.ID <= cursor {
			continue
		}
		if len(out.UserPools) == int(*in.MaxResults) {
			out.NextToken = str[api.PaginationKeyType](nextPage(binding, value(out.UserPools[len(out.UserPools)-1].Id)))
			break
		}
		d := p.Data
		out.UserPools = append(out.UserPools, api.UserPoolDescriptionType{Id: d.Id, Name: d.Name, CreationDate: d.CreationDate, LastModifiedDate: d.LastModifiedDate, LambdaConfig: d.LambdaConfig})
	}
	return out, nil
}
func (s *Service) addCustomAttributes(tx Transaction, in *api.AddCustomAttributesInput) (*api.AddCustomAttributesOutput, error) {
	pool, err := s.adminPool(tx, "AddCustomAttributes", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	if len(in.CustomAttributes) == 0 {
		return nil, failure("InvalidParameterException", "CustomAttributes must not be empty.")
	}
	for _, a := range in.CustomAttributes {
		a, err = customSchema(a)
		if err != nil {
			return nil, err
		}
		if schemaAttribute(pool, value(a.Name)) != nil {
			return nil, failure("InvalidParameterException", "Attribute already exists in the schema.")
		}
		pool.Data.SchemaAttributes = append(pool.Data.SchemaAttributes, a)
	}
	now := s.clock.Now()
	pool.Data.LastModifiedDate = &now
	if err = tx.PutPool(pool); err != nil {
		return nil, err
	}
	return &api.AddCustomAttributesOutput{}, nil
}
func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	pool, err := s.poolByARN(tx, "ListTagsForResource", value(in.ResourceArn), nil)
	if err != nil {
		return nil, err
	}
	tags := pool.Data.UserPoolTags
	if tags == nil {
		tags = api.UserPoolTagsType{}
	}
	return &api.ListTagsForResourceOutput{Tags: tags}, nil
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	pool, err := s.poolByARN(tx, "TagResource", value(in.ResourceArn), requestTagConditions(in.Tags))
	if err != nil {
		return nil, err
	}
	if err = validatePoolTags(in.Tags); err != nil {
		return nil, err
	}
	if pool.Data.UserPoolTags == nil {
		pool.Data.UserPoolTags = api.UserPoolTagsType{}
	}
	for k, v := range in.Tags {
		pool.Data.UserPoolTags[k] = v
	}
	if err = tx.PutPool(pool); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	var keys []string
	if len(in.TagKeys) > 0 {
		keys = make([]string, len(in.TagKeys))
		for i, k := range in.TagKeys {
			keys[i] = string(k)
		}
	}
	pool, err := s.poolByARN(tx, "UntagResource", value(in.ResourceArn), map[string][]string{"aws:TagKeys": keys})
	if err != nil {
		return nil, err
	}
	for _, k := range in.TagKeys {
		if strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return nil, failure("InvalidParameterException", "Reserved tag key.")
		}
		delete(pool.Data.UserPoolTags, k)
	}
	if err = tx.PutPool(pool); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
