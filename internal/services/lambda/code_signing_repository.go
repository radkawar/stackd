package lambda

import "time"

// CodeSigningConfigKey is regional and account-owned. Configurations are not
// versions of functions; changing a policy affects only subsequent deployments.
type CodeSigningConfigKey struct {
	Scope
	ID string
}

func (k CodeSigningConfigKey) ARN() string {
	return "arn:" + k.Partition + ":lambda:" + k.Region + ":" + k.Account + ":code-signing-config:" + k.ID
}

type CodeSigningConfigRecord struct {
	Key         CodeSigningConfigKey
	Description string
	Policy      string
	Publishers  []string
	Tags        map[string]string
	Modified    time.Time
}

type CodeSigningReader interface {
	CodeSigningConfig(CodeSigningConfigKey) (CodeSigningConfigRecord, error)
	CodeSigningConfigs(Scope) ([]CodeSigningConfigRecord, error)
	FunctionCodeSigningConfig(FunctionKey) (CodeSigningConfigKey, error)
	FunctionsByCodeSigningConfig(CodeSigningConfigKey) ([]FunctionKey, error)
}

type CodeSigningWriter interface {
	PutCodeSigningConfig(CodeSigningConfigRecord) error
	DeleteCodeSigningConfig(CodeSigningConfigKey) error
	PutFunctionCodeSigningConfig(FunctionKey, CodeSigningConfigKey) error
	DeleteFunctionCodeSigningConfig(FunctionKey) error
}
