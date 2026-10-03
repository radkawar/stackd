package ssm

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ssm"
)

type parameterFilter struct {
	Key, Option string
	Values      []string
}

func compileParameterFilters(filters api.ParameterStringFilterList, byPath bool) ([]parameterFilter, error) {
	out := make([]parameterFilter, 0, len(filters))
	for _, input := range filters {
		key, option := value(input.Key), value(input.Option)
		valid := key == "Type" || key == "KeyId"
		if byPath {
			valid = valid || key == "Label"
		} else {
			valid = valid || key == "Name" || key == "Path" || key == "Tier" || key == "DataType" || strings.HasPrefix(key, "tag:") && len(key) > 4
		}
		if !valid {
			return nil, failure("InvalidFilterKey", "Unsupported parameter filter key: "+key)
		}
		if option == "" {
			option = "Equals"
			if key == "Path" {
				option = "OneLevel"
			}
		}
		valid = option == "Equals" || option == "BeginsWith" || key == "Name" && option == "Contains"
		if key == "Path" {
			valid = option == "Recursive" || option == "OneLevel"
		}
		if key == "Label" {
			valid = option == "Equals"
		}
		if !valid {
			return nil, failure("InvalidFilterOption", "Unsupported option for "+key+": "+option)
		}
		if len(input.Values) == 0 || len(input.Values) > 50 {
			return nil, failure("InvalidFilterValue", "A filter must have between 1 and 50 values.")
		}
		if key == "Label" && len(input.Values) != 1 {
			return nil, failure("InvalidFilterValue", "A Label filter must have exactly one value.")
		}
		f := parameterFilter{Key: key, Option: option, Values: make([]string, 0, len(input.Values))}
		for _, item := range input.Values {
			text := string(item)
			if len(text) == 0 || len(text) > 1024 {
				return nil, failure("InvalidFilterValue", "Filter values must have between 1 and 1024 characters.")
			}
			if key == "Path" {
				var err error
				text, err = parameterPath(text)
				if err != nil {
					return nil, failure("InvalidFilterValue", "Invalid parameter path filter.")
				}
			}
			f.Values = append(f.Values, text)
		}
		out = append(out, f)
	}
	return out, nil
}

func describeParameterFilters(in *api.DescribeParametersRequest) ([]parameterFilter, error) {
	if len(in.Filters) > 0 && len(in.ParameterFilters) > 0 {
		return nil, failure("ValidationException", "Filters and ParameterFilters cannot be specified together.")
	}
	if len(in.Filters) == 0 {
		return compileParameterFilters(in.ParameterFilters, false)
	}
	modern := make(api.ParameterStringFilterList, 0, len(in.Filters))
	for _, old := range in.Filters {
		key := value(old.Key)
		if key != "Name" && key != "Type" && key != "KeyId" {
			return nil, failure("InvalidFilterKey", "Unsupported parameter filter key: "+key)
		}
		f := api.ParameterStringFilter{Key: new(api.ParameterStringFilterKey(key))}
		if key == "Name" {
			f.Option = new(api.ParameterStringQueryOption("BeginsWith"))
		}
		for _, v := range old.Values {
			f.Values = append(f.Values, api.ParameterStringFilterValue(v))
		}
		modern = append(modern, f)
	}
	return compileParameterFilters(modern, false)
}

func parameterPath(input string) (string, error) {
	path := strings.TrimSpace(input)
	if !strings.HasPrefix(path, "/") || len(path) > 2048 {
		return "", failure("ValidationException", "A parameter path must begin with / and contain at most 2048 characters.")
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return "/", nil
	}
	if strings.Contains(path, "//") || strings.Count(path, "/") > 15 {
		return "", failure("ValidationException", "Invalid parameter hierarchy.")
	}
	for _, c := range path {
		if c != '/' && c != '_' && c != '.' && c != '-' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return "", failure("ValidationException", "Invalid character in parameter path.")
		}
	}
	return path, nil
}

func parameterInPath(name, path string, recursive bool) bool {
	prefix := path
	if prefix != "/" {
		prefix += "/"
	}
	rest, ok := strings.CutPrefix(name, prefix)
	// Root-level names do not need a leading slash in Parameter Store.
	if path == "/" && !strings.HasPrefix(name, "/") {
		rest, ok = name, true
	}
	return ok && rest != "" && (recursive || !strings.Contains(rest, "/"))
}

func matchesParameterFilters(p ParameterRecord, v VersionRecord, filters []parameterFilter) bool {
	for _, filter := range filters {
		var actual string
		switch filter.Key {
		case "Name":
			actual = p.Key.Name
		case "Type":
			actual = v.Type
		case "KeyId":
			actual = v.KeyID
		case "Tier":
			actual = p.Tier
		case "DataType":
			actual = p.DataType
		case "Path", "Label":
		default:
			var exists bool
			actual, exists = p.Tags[strings.TrimPrefix(filter.Key, "tag:")]
			if !exists {
				return false
			}
		}
		matched := false
		for _, expected := range filter.Values {
			switch filter.Key {
			case "Path":
				matched = parameterInPath(p.Key.Name, expected, filter.Option == "Recursive")
			case "Label":
				matched = slices.Contains(v.Labels, expected)
			default:
				switch filter.Option {
				case "Equals":
					matched = actual == expected
				case "BeginsWith":
					matched = strings.HasPrefix(actual, expected)
				case "Contains":
					matched = strings.Contains(actual, expected)
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// The exclusive key survives deletions without offset skips. The MAC binds the
// continuation to this service incarnation, action, query, account and Region.
type parameterCursor[K cmp.Ordered] struct {
	Scope         Scope
	Action, Query string
	After         K
}

func parameterPage[T any, K cmp.Ordered](s *Service, r Reader, action string, query any, rows []T, key func(T) K, size, maximum int, token *api.NextToken) ([]T, *api.NextToken, error) {
	if size < 1 || size > maximum {
		return nil, nil, failure("ValidationException", fmt.Sprintf("MaxResults must be between 1 and %d.", maximum))
	}
	selection, err := json.Marshal(query)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(selection)
	expected := parameterCursor[K]{Scope: scopeFor(r.Context()), Action: action, Query: base64.RawURLEncoding.EncodeToString(digest[:])}
	var after K
	if token != nil {
		encoded, signature, ok := strings.Cut(value(token), ".")
		body, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		sig, sigErr := base64.RawURLEncoding.DecodeString(signature)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		var cursor parameterCursor[K]
		if !ok || decodeErr != nil || sigErr != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(body, &cursor) != nil {
			return nil, nil, failure("InvalidNextToken", "The pagination token is invalid.")
		}
		after, cursor.After = cursor.After, after
		if cursor != expected {
			return nil, nil, failure("InvalidNextToken", "The pagination token belongs to a different request.")
		}
	}
	slices.SortFunc(rows, func(a, b T) int { return cmp.Compare(key(a), key(b)) })
	start := 0
	if token != nil {
		start, _ = slices.BinarySearchFunc(rows, after, func(row T, boundary K) int {
			if key(row) <= boundary {
				return -1
			}
			return 1
		})
	}
	end := min(start+size, len(rows))
	var next *api.NextToken
	if end < len(rows) {
		expected.After = key(rows[end-1])
		body, err := json.Marshal(expected)
		if err != nil {
			return nil, nil, err
		}
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		next = new(api.NextToken(base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))))
	}
	return rows[start:end], next, nil
}
