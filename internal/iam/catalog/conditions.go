package catalog

import "strings"

// ContextTypes resolves unambiguous AWS types for trusted request context.
// Keys in the result are lowercase, matching IAM's case-insensitive lookup.
// Overloaded or unknown source definitions are left undeclared. Service code
// owns construction and validation of the values; metadata grants no access.
func ContextTypes(context map[string][]string) map[string]string {
	types := make(map[string]string)
	for key := range context {
		key = strings.ToLower(key)
		kind := conditionTypes[key]
		switch key {
		// The service reference includes TagKeys but omits the other global
		// arrays. Their classification comes from the IAM global key reference:
		// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
		case "aws:principalorgpaths", "aws:principalservicenameslist", "aws:vpceorgpaths", "aws:resourceorgpaths", "aws:calledvia", "aws:sourceorgpaths":
			kind = "stringList"
		}
		// OpenID authentication methods are multivalued for every issuer,
		// including Cognito, whose service-reference type is reported as String.
		// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif
		if strings.HasSuffix(key, ":amr") {
			kind = "stringList"
		}
		if kind != "" {
			types[key] = kind
		}
	}
	return types
}
