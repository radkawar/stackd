package cognitoidp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/cognitoidp"
)

func poolSchema(overrides api.SchemaAttributesListType) (api.SchemaAttributesListType, error) {
	names := []string{"sub", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "phone_number", "phone_number_verified", "address", "updated_at"}
	schema := make(api.SchemaAttributesListType, 0, len(names)+len(overrides))
	for _, name := range names {
		a := api.SchemaAttributeType{Name: str[api.CustomAttributeNameType](name), AttributeDataType: str[api.AttributeDataType]("String"), Mutable: ptr(api.BooleanType(name != "sub")), DeveloperOnlyAttribute: ptr(api.BooleanType(false)), Required: ptr(api.BooleanType(name == "sub"))}
		switch name {
		case "email_verified", "phone_number_verified":
			a.AttributeDataType = str[api.AttributeDataType]("Boolean")
		case "updated_at":
			a.AttributeDataType = str[api.AttributeDataType]("Number")
			a.NumberAttributeConstraints = &api.NumberAttributeConstraintsType{MinValue: str[api.StringType]("0")}
		default:
			min, max := "0", "2048"
			if name == "sub" {
				min = "1"
			}
			if name == "birthdate" {
				min, max = "10", "10"
			}
			a.StringAttributeConstraints = &api.StringAttributeConstraintsType{MinLength: str[api.StringType](min), MaxLength: str[api.StringType](max)}
		}
		schema = append(schema, a)
	}
	seen := map[string]bool{}
	for _, in := range overrides {
		name := value(in.Name)
		if seen[name] {
			return nil, failure("InvalidParameterException", "Duplicate schema attribute.")
		}
		seen[name] = true
		index := slices.Index(names, name)
		if index < 0 {
			a, err := customSchema(in)
			if err != nil {
				return nil, err
			}
			for _, old := range schema {
				if value(old.Name) == value(a.Name) {
					return nil, failure("InvalidParameterException", "Duplicate schema attribute.")
				}
			}
			schema = append(schema, a)
			continue
		}
		a := &schema[index]
		if in.AttributeDataType != nil && value(in.AttributeDataType) != value(a.AttributeDataType) {
			return nil, failure("InvalidParameterException", "Cannot change a standard attribute data type.")
		}
		if in.DeveloperOnlyAttribute != nil && bool(*in.DeveloperOnlyAttribute) {
			return nil, failure("InvalidParameterException", "Standard attributes cannot be developer-only.")
		}
		if name == "sub" && ((in.Mutable != nil && bool(*in.Mutable)) || (in.Required != nil && !bool(*in.Required))) {
			return nil, failure("InvalidParameterException", "The sub attribute is required and immutable.")
		}
		if in.Mutable != nil {
			a.Mutable = in.Mutable
		}
		if in.Required != nil {
			a.Required = in.Required
		}
		if in.StringAttributeConstraints != nil {
			a.StringAttributeConstraints = in.StringAttributeConstraints
		}
		if in.NumberAttributeConstraints != nil {
			a.NumberAttributeConstraints = in.NumberAttributeConstraints
		}
		if err := validateSchemaConstraints(*a); err != nil {
			return nil, err
		}
	}
	return schema, nil
}

func customSchema(in api.SchemaAttributeType) (api.SchemaAttributeType, error) {
	name := value(in.Name)
	name = strings.TrimPrefix(strings.TrimPrefix(name, "custom:"), "dev:")
	if utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 20 || strings.ContainsFunc(name, unicode.IsSpace) || strings.Contains(name, ":") {
		return in, failure("InvalidParameterException", "Invalid custom attribute name.")
	}
	prefix := "custom:"
	if in.DeveloperOnlyAttribute != nil && bool(*in.DeveloperOnlyAttribute) {
		prefix = "dev:"
	}
	in.Name = str[api.CustomAttributeNameType](prefix + name)
	if in.Required != nil && bool(*in.Required) {
		return in, failure("InvalidParameterException", "Required custom attributes are not supported.")
	}
	if in.Required == nil {
		in.Required = ptr(api.BooleanType(false))
	}
	if in.DeveloperOnlyAttribute == nil {
		in.DeveloperOnlyAttribute = ptr(api.BooleanType(false))
	}
	if in.Mutable == nil {
		in.Mutable = ptr(api.BooleanType(false))
	}
	if in.AttributeDataType == nil {
		in.AttributeDataType = str[api.AttributeDataType]("String")
	}
	switch value(in.AttributeDataType) {
	case "String", "Number", "Boolean", "DateTime":
	default:
		return in, failure("InvalidParameterException", "Invalid custom attribute data type.")
	}
	if value(in.AttributeDataType) == "String" && in.StringAttributeConstraints == nil {
		in.StringAttributeConstraints = &api.StringAttributeConstraintsType{}
	}
	if err := validateSchemaConstraints(in); err != nil {
		return in, err
	}
	return in, nil
}
func validateSchemaConstraints(a api.SchemaAttributeType) error {
	invalid := func() error { return failure("InvalidParameterException", "Invalid attribute constraints.") }
	if c := a.StringAttributeConstraints; c != nil {
		if value(a.AttributeDataType) != "String" {
			return invalid()
		}
		min, max := 0, 2048
		var err error
		if c.MinLength != nil {
			min, err = strconv.Atoi(value(c.MinLength))
			if err != nil {
				return invalid()
			}
		}
		if c.MaxLength != nil {
			max, err = strconv.Atoi(value(c.MaxLength))
			if err != nil {
				return invalid()
			}
		}
		if min < 0 || max > 2048 || min > max {
			return invalid()
		}
	}
	if c := a.NumberAttributeConstraints; c != nil {
		if value(a.AttributeDataType) != "Number" {
			return invalid()
		}
		var min, max *big.Rat
		var ok bool
		if c.MinValue != nil {
			min, ok = parseAttributeNumber(value(c.MinValue))
			if !ok {
				return invalid()
			}
		}
		if c.MaxValue != nil {
			max, ok = parseAttributeNumber(value(c.MaxValue))
			if !ok {
				return invalid()
			}
		}
		if min != nil && max != nil && min.Cmp(max) > 0 {
			return invalid()
		}
	}
	return nil
}
func schemaAttribute(pool PoolRecord, name string) *api.SchemaAttributeType {
	for i := range pool.Data.SchemaAttributes {
		if value(pool.Data.SchemaAttributes[i].Name) == name {
			return &pool.Data.SchemaAttributes[i]
		}
	}
	return nil
}
func userAttribute(user UserRecord, name string) string {
	for _, a := range user.Data.Attributes {
		if value(a.Name) == name {
			return value(a.Value)
		}
	}
	return ""
}
func putUserAttribute(user *UserRecord, name, val string) {
	for i := range user.Data.Attributes {
		if value(user.Data.Attributes[i].Name) == name {
			user.Data.Attributes[i].Value = str[api.AttributeValueType](val)
			return
		}
	}
	user.Data.Attributes = append(user.Data.Attributes, api.AttributeType{Name: str[api.AttributeNameType](name), Value: str[api.AttributeValueType](val)})
}
func caseInsensitive(pool PoolRecord) bool {
	return pool.Data.UsernameConfiguration != nil && pool.Data.UsernameConfiguration.CaseSensitive != nil && !bool(*pool.Data.UsernameConfiguration.CaseSensitive)
}
func canonicalUsername(pool PoolRecord, name string) string {
	if caseInsensitive(pool) {
		return strings.ToLower(name)
	}
	return name
}
func usernameUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:]), nil
}
func validEmail(email string) bool {
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email && strings.Contains(email, "@")
}
func validPhone(phone string) bool {
	if len(phone) < 3 || len(phone) > 16 || phone[0] != '+' || phone[1] == '0' {
		return false
	}
	for _, r := range phone[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func initializeUser(pool PoolRecord, username string) (UserRecord, error) {
	var user UserRecord
	if len(username) == 0 || utf8.RuneCountInString(username) > 128 || strings.ContainsFunc(username, unicode.IsSpace) {
		return user, failure("InvalidParameterException", "Invalid username.")
	}
	sub, err := usernameUUID()
	if err != nil {
		return user, err
	}
	username = canonicalUsername(pool, username)
	user.Key = UserKey{PoolKey: pool.Key, Username: username}
	putUserAttribute(&user, "sub", sub)
	if len(pool.Data.UsernameAttributes) > 0 {
		attribute := ""
		for _, a := range pool.Data.UsernameAttributes {
			if (a == "email" && validEmail(username)) || (a == "phone_number" && validPhone(username)) {
				attribute = string(a)
				break
			}
		}
		if attribute == "" {
			return user, failure("InvalidParameterException", "Username must be a configured email address or phone number.")
		}
		user.Key.Username = sub
		putUserAttribute(&user, attribute, username)
	} else {
		if err := validateUsernameNamespace(pool, username); err != nil {
			return user, err
		}
	}
	user.Data.Username = str[api.UsernameType](user.Key.Username)
	return user, nil
}

// Usernames and preferred usernames cannot overlap the email/phone namespaces
// enabled as sign-in aliases.
func validateUsernameNamespace(pool PoolRecord, name string) error {
	for _, alias := range pool.Data.AliasAttributes {
		if alias == "email" && validEmail(name) || alias == "phone_number" && validPhone(name) {
			return failure("InvalidParameterException", "Username cannot be of email or phone format when that attribute is an alias.")
		}
	}
	return nil
}

func resolveUser(r Reader, pool PoolRecord, username string) (UserRecord, error) {
	username = canonicalUsername(pool, username)
	user, err := r.User(UserKey{PoolKey: pool.Key, Username: username})
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return UserRecord{}, err
	}
	// UsernameAttributes are unique identifiers even before verification. Ordinary
	// attributes only become sign-in aliases after verification.
	aliases := make([]string, 0, len(pool.Data.UsernameAttributes)+len(pool.Data.AliasAttributes)+1)
	aliases = append(aliases, "sub")
	for _, a := range pool.Data.UsernameAttributes {
		aliases = append(aliases, string(a))
	}
	for _, a := range pool.Data.AliasAttributes {
		aliases = append(aliases, string(a))
	}
	var found *UserRecord
	for _, name := range aliases {
		users, err := r.UsersByAttribute(pool.Key, name, username)
		if err != nil {
			return UserRecord{}, err
		}
		for _, candidate := range users {
			if name != "sub" && !slices.Contains(pool.Data.UsernameAttributes, api.UsernameAttributeType(name)) && !activeAlias(candidate, name) {
				continue
			}
			if found != nil && found.Key != candidate.Key {
				return UserRecord{}, failure("UserNotFoundException", "User does not exist.")
			}
			copy := candidate
			found = &copy
		}
	}
	if found != nil {
		return *found, nil
	}
	return UserRecord{}, failure("UserNotFoundException", "User does not exist.")
}
func activeAlias(user UserRecord, name string) bool {
	switch name {
	case "email":
		return userAttribute(user, "email_verified") == "true"
	case "phone_number":
		return userAttribute(user, "phone_number_verified") == "true"
	default:
		return true
	}
}

func setUserAttributes(pool PoolRecord, user *UserRecord, attributes api.AttributeListType, client *ClientRecord) error {
	last := make(map[string]int, len(attributes))
	for i, a := range attributes {
		last[value(a.Name)] = i
	}
	for i, a := range attributes {
		name, val := value(a.Name), value(a.Value)
		if last[name] != i {
			continue
		}
		schema := schemaAttribute(pool, name)
		if schema == nil {
			return failure("InvalidParameterException", "Attribute does not exist in the schema: "+name)
		}
		if name == "sub" || (user.Data.UserCreateDate != nil && schema.Mutable != nil && !bool(*schema.Mutable)) {
			return failure("InvalidParameterException", "Attribute is immutable: "+name)
		}
		if err := attributeWritePermission(client, name); err != nil {
			return err
		}
		if val == "" && user.Data.UserCreateDate != nil {
			if err := deleteUserAttributes(pool, user, api.AttributeNameListType{api.AttributeNameType(name)}, client); err != nil {
				return err
			}
			continue
		}
		if caseInsensitive(pool) && (name == "email" || name == "preferred_username") {
			val = strings.ToLower(val)
		}
		if err := validateAttributeValue(*schema, val); err != nil {
			return err
		}
		if (name == "email" || name == "phone_number") && userAttribute(*user, name) != val {
			verified := name + "_verified"
			if userAttribute(*user, verified) != "" {
				putUserAttribute(user, verified, "false")
			}
		}
		putUserAttribute(user, name, val)
	}
	// Verification flags in the same request apply after their corresponding
	// address regardless of input ordering.
	for i, a := range attributes {
		name := value(a.Name)
		if last[name] != i {
			continue
		}
		if name == "email_verified" || name == "phone_number_verified" {
			if value(a.Value) == "" && user.Data.UserCreateDate != nil {
				continue
			}
			if value(a.Value) == "true" && userAttribute(*user, strings.TrimSuffix(name, "_verified")) == "" {
				return failure("InvalidParameterException", "A verified attribute requires a value.")
			}
			putUserAttribute(user, name, value(a.Value))
		}
	}
	return nil
}

func attributeWritePermission(client *ClientRecord, name string) error {
	if client == nil {
		return nil
	}
	if name == "email_verified" || name == "phone_number_verified" {
		return failure("InvalidParameterException", "Cannot modify the non-mutable attribute "+name)
	}
	if strings.HasPrefix(name, "dev:") || (len(client.Data.WriteAttributes) > 0 && !slices.Contains(client.Data.WriteAttributes, api.ClientPermissionType(name))) {
		return failure("NotAuthorizedException", "A client attempted to write unauthorized attribute.")
	}
	return nil
}

var attributeNumberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE]([+-]?[0-9]+))?$`)

func parseAttributeNumber(raw string) (*big.Rat, bool) {
	if len(raw) > 2048 {
		return nil, false
	}
	parts := attributeNumberPattern.FindStringSubmatch(raw)
	if parts == nil {
		return nil, false
	}
	if parts[1] != "" {
		exponent, err := strconv.Atoi(parts[1])
		if err != nil || exponent < -308 || exponent > 308 {
			return nil, false
		}
	}
	return new(big.Rat).SetString(raw)
}

func validateAttributeValue(schema api.SchemaAttributeType, val string) error {
	name := value(schema.Name)
	invalid := func() error { return failure("InvalidParameterException", "Invalid value for attribute "+name+".") }
	if len(val) > 2048 {
		return invalid()
	}
	switch value(schema.AttributeDataType) {
	case "String":
		if c := schema.StringAttributeConstraints; c != nil {
			n := utf8.RuneCountInString(val)
			if c.MinLength != nil {
				min, _ := strconv.Atoi(value(c.MinLength))
				if n < min {
					return invalid()
				}
			}
			if c.MaxLength != nil {
				max, _ := strconv.Atoi(value(c.MaxLength))
				if n > max {
					return invalid()
				}
			}
		}
	case "Boolean":
		if val != "true" && val != "false" {
			return invalid()
		}
	case "DateTime":
		if _, err := time.Parse(time.RFC3339, val); err != nil {
			return invalid()
		}
	case "Number":
		n, ok := parseAttributeNumber(val)
		if !ok {
			return invalid()
		}
		if c := schema.NumberAttributeConstraints; c != nil {
			if c.MinValue != nil {
				min, _ := parseAttributeNumber(value(c.MinValue))
				if min == nil || n.Cmp(min) < 0 {
					return invalid()
				}
			}
			if c.MaxValue != nil {
				max, _ := parseAttributeNumber(value(c.MaxValue))
				if max == nil || n.Cmp(max) > 0 {
					return invalid()
				}
			}
		}
	}
	switch name {
	case "email":
		if !validEmail(val) {
			return invalid()
		}
	case "phone_number":
		if !validPhone(val) {
			return invalid()
		}
	}
	return nil
}

func ensureUserAliases(tx Transaction, pool PoolRecord, user *UserRecord, force bool) error {
	names := make([]string, 0, len(pool.Data.UsernameAttributes)+len(pool.Data.AliasAttributes))
	for _, a := range pool.Data.UsernameAttributes {
		names = append(names, string(a))
	}
	for _, a := range pool.Data.AliasAttributes {
		names = append(names, string(a))
	}
	for _, name := range names {
		val := userAttribute(*user, name)
		if val == "" {
			continue
		}
		usernameAttribute := slices.Contains(pool.Data.UsernameAttributes, api.UsernameAttributeType(name))
		if !usernameAttribute && !activeAlias(*user, name) {
			continue
		}
		if name == "preferred_username" {
			if err := validateUsernameNamespace(pool, val); err != nil {
				return err
			}
		}
		owner, err := tx.User(UserKey{PoolKey: pool.Key, Username: val})
		if err == nil && owner.Key != user.Key {
			return failure("AliasExistsException", "User account already exists for the alias.")
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		users, err := tx.UsersByAttribute(pool.Key, name, val)
		if err != nil {
			return err
		}
		for _, other := range users {
			if other.Key == user.Key || (!usernameAttribute && !activeAlias(other, name)) {
				continue
			}
			if !force || usernameAttribute || name == "preferred_username" {
				return failure("AliasExistsException", "An account with the given "+name+" already exists.")
			}
			putUserAttribute(&other, name+"_verified", "false")
			if err = tx.PutUser(other); err != nil {
				return err
			}
		}
	}
	return nil
}

func deleteUserAttributes(pool PoolRecord, user *UserRecord, names api.AttributeNameListType, client *ClientRecord) error {
	for _, n := range names {
		name := string(n)
		a := schemaAttribute(pool, name)
		if a == nil {
			return failure("InvalidParameterException", "Attribute does not exist in the schema: "+name)
		}
		if name == "sub" || (a.Required != nil && bool(*a.Required)) || (a.Mutable != nil && !bool(*a.Mutable)) || slices.Contains(pool.Data.UsernameAttributes, api.UsernameAttributeType(name)) {
			return failure("InvalidParameterException", "Cannot delete required or immutable attribute: "+name)
		}
		if err := attributeWritePermission(client, name); err != nil {
			return err
		}
		user.Data.Attributes = slices.DeleteFunc(user.Data.Attributes, func(v api.AttributeType) bool {
			return value(v.Name) == name || ((name == "email" || name == "phone_number") && value(v.Name) == name+"_verified")
		})
	}
	return nil
}
