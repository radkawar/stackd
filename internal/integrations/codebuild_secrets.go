package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awswire"
)

// CodeBuildSecrets resolves user-selected values using the current build role.
type CodeBuildSecretsAPI interface {
	GetSecretValue(context.Context, *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error)
}
type CodeBuildSecrets struct{ Secrets CodeBuildSecretsAPI }

func (a CodeBuildSecrets) Read(ctx context.Context, reference string) (string, error) {
	parts := strings.Split(reference, ":")
	base := 1
	if strings.HasPrefix(reference, "arn:") {
		base = 7
	}
	if len(parts) < base || len(parts) > base+3 {
		return "", fmt.Errorf("invalid CodeBuild Secrets Manager reference")
	}
	id := strings.Join(parts[:base], ":")
	input := &api.GetSecretValueInput{SecretId: new(api.SecretIdType(id))}
	key := ""
	if len(parts) > base {
		key = parts[base]
	}
	if len(parts) > base+1 && parts[base+1] != "" {
		input.VersionStage = new(api.SecretVersionStageType(parts[base+1]))
	}
	if len(parts) > base+2 && parts[base+2] != "" {
		input.VersionId = new(api.SecretVersionIdType(parts[base+2]))
	}
	out, rejected := a.Secrets.GetSecretValue(codeBuildCommandContext(ctx), input)
	if rejected != nil {
		return "", rejected
	}
	value := string(out.SecretBinary)
	if out.SecretString != nil {
		value = string(*out.SecretString)
	}
	if key == "" {
		return value, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &fields); err != nil {
		return "", fmt.Errorf("CodeBuild secret is not a JSON object")
	}
	var selected string
	raw, ok := fields[key]
	if !ok || json.Unmarshal(raw, &selected) != nil {
		return "", fmt.Errorf("CodeBuild secret JSON key is absent or not a string")
	}
	return selected, nil
}

// CodeBuildCredentialCipher retains imported provider credentials as ciphertext
// under the existing KMS owner, not as a second public Secrets Manager resource.
type CodeBuildCredentialCipher struct{ Keys ServiceDataKeys }
type codeBuildSourceCredential struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

func (a CodeBuildCredentialCipher) Seal(ctx context.Context, credentialARN, username, token string) ([]byte, error) {
	key, rejected := a.Keys.EnsureServiceKey(ctx, "codebuild")
	if rejected != nil {
		return nil, rejected
	}
	plain, err := json.Marshal(codeBuildSourceCredential{Username: username, Token: token})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	ciphertext, _, rejected := a.Keys.Encrypt(codeBuildCommandContext(ctx), key, plain, map[string]string{"aws:codebuild:source-credential": credentialARN})
	if rejected != nil {
		return nil, rejected
	}
	return ciphertext, nil
}
func (a CodeBuildCredentialCipher) Open(ctx context.Context, credentialARN string, ciphertext []byte) (string, string, error) {
	plain, _, rejected := a.Keys.Decrypt(codeBuildCommandContext(ctx), ciphertext, map[string]string{"aws:codebuild:source-credential": credentialARN})
	if rejected != nil {
		return "", "", rejected
	}
	defer clear(plain)
	var value codeBuildSourceCredential
	if err := json.Unmarshal(plain, &value); err != nil {
		return "", "", fmt.Errorf("invalid retained CodeBuild source credential")
	}
	return value.Username, value.Token, nil
}
