package eks

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var nativePrivateKey = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)`)
var nativeCredentialField = regexp.MustCompile(`(?i)(\b["']?(?:[a-z0-9_.-]*(?:token|password|secret|credentials?|private[-_]?key|secret[-_]?access[-_]?key)|client-key-data|` + regexp.QuoteMeta(ownerLabel) + `)["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,}\]"']+)`)
var nativeJoinToken = regexp.MustCompile(`K10[0-9a-fA-F]+::[^\s"':]+:[^\s"']+`)
var nativeURLPassword = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:"']+:)[^\s/@"']+(@)`)
var nativeAuthorization = regexp.MustCompile(`(?i)(\bauthorization["']?\s*[:=]\s*["']?(?:bearer|basic)\s+)[^\s"']+`)

func nativeCommandFailure(binary string, args, environment []string, stdout []byte, commandErr error) error {
	redact := func(body []byte) string {
		text := string(body)
		for _, entries := range [][]string{args, environment} {
			for _, entry := range entries {
				key, value, found := strings.Cut(entry, "=")
				key = strings.ToLower(key)
				if !found || value == "" || !(strings.Contains(key, "token") || strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "credential") || strings.Contains(key, "private-key") || strings.Contains(key, "private_key") || key == ownerLabel) {
					continue
				}
				// k3d adds a node selector to the secret-bearing k3s argument.
				if selector := strings.LastIndexByte(value, '@'); selector >= 0 && (strings.HasPrefix(value[selector:], "@server:") || strings.HasPrefix(value[selector:], "@agent:") || value[selector:] == "@all") {
					value = value[:selector]
				}
				if value != "" {
					text = strings.ReplaceAll(text, value, "***")
				}
			}
		}
		text = nativePrivateKey.ReplaceAllString(text, "***")
		text = nativeAuthorization.ReplaceAllString(text, "${1}***")
		text = nativeCredentialField.ReplaceAllString(text, "${1}***")
		text = nativeJoinToken.ReplaceAllString(text, "***")
		return nativeURLPassword.ReplaceAllString(text, "${1}***${2}")
	}
	detail := redact(stdout)
	var exit *exec.ExitError
	if errors.As(commandErr, &exit) {
		// Keep the unwrapped process failure safe too: callers may inspect it.
		exit.Stderr = []byte(redact(exit.Stderr))
		detail += "\n" + string(exit.Stderr)
	}
	operation := ""
	if len(args) != 0 {
		operation = args[0]
	}
	if detail = strings.TrimSpace(detail); detail != "" {
		return fmt.Errorf("eks: %s %s failed: %w: %s", filepath.Base(binary), operation, commandErr, detail)
	}
	return fmt.Errorf("eks: %s %s failed: %w", filepath.Base(binary), operation, commandErr)
}
