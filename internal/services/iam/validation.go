package iam

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]+$`)

func invalid(message string) *awswire.Error {
	return &awswire.Error{Code: "ValidationError", Message: message, StatusCode: 400}
}
func missing(kind, name string) *awswire.Error {
	return &awswire.Error{Code: "NoSuchEntity", Message: fmt.Sprintf("The %s with name %s cannot be found.", kind, name), StatusCode: 404}
}
func duplicate(kind, name string) *awswire.Error {
	return &awswire.Error{Code: "EntityAlreadyExists", Message: fmt.Sprintf("%s with name %s already exists.", kind, name), StatusCode: 409}
}
func conflict(message string) *awswire.Error {
	return &awswire.Error{Code: "DeleteConflict", Message: message, StatusCode: 409}
}
func limit(message string) *awswire.Error {
	return &awswire.Error{Code: "LimitExceeded", Message: message, StatusCode: 409}
}
func invalidInput(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidInput", Message: message, StatusCode: 400}
}

func validateName(v, key string, max int) *awswire.Error {
	if len(v) == 0 || len(v) > max || !namePattern.MatchString(v) {
		return invalid(fmt.Sprintf("%s must contain 1-%d alphanumeric or _+=,.@- characters.", key, max))
	}
	return nil
}

func validPath(v string) (string, *awswire.Error) {
	if v == "" {
		return "/", nil
	}
	if len(v) > 512 || !strings.HasPrefix(v, "/") || !strings.HasSuffix(v, "/") {
		return "", invalid("Path must begin and end with / and contain at most 512 characters.")
	}
	for _, r := range v {
		if r < 0x21 || r > 0x7e {
			return "", invalid("Path contains an invalid character.")
		}
	}
	return v, nil
}

func resourceARN(m awsctx.Metadata, kind, path, name string) string {
	return "arn:" + m.Partition + ":iam::" + m.AccountID + ":" + kind + path + name
}

func newID(prefix string) string {
	b := make([]byte, 11)
	if _, err := rand.Read(b); err != nil {
		panic("iam: random source unavailable: " + err.Error())
	}
	return prefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:17]
}

func randomUUID() (string, error) {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

func encodedDocument(v string) string { return strings.ReplaceAll(url.QueryEscape(v), "+", "%20") }
