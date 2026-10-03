package lambda

import (
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func applyDurableConfig(record *FunctionRecord, input *api.DurableConfig, creating bool) *awswire.Error {
	if input == nil {
		return nil
	}
	if !creating && record.Durable == nil {
		return durableParameter("Durability must be enabled when the function is created.")
	}
	config := cloneDurableConfig(input)
	if config.ExecutionTimeout == nil {
		config.ExecutionTimeout = new(api.ExecutionTimeout(86400))
	}
	if config.RetentionPeriodInDays == nil {
		config.RetentionPeriodInDays = new(api.RetentionPeriodInDays(14))
	}
	if config.ExecutionTimeout == nil || *config.ExecutionTimeout < 1 || *config.ExecutionTimeout > 31622400 {
		return durableParameter("ExecutionTimeout must be between 1 and 31622400 seconds.")
	}
	if config.RetentionPeriodInDays == nil || *config.RetentionPeriodInDays < 1 || *config.RetentionPeriodInDays > 90 {
		return durableParameter("RetentionPeriodInDays must be between 1 and 90.")
	}
	record.Durable = config
	return nil
}
