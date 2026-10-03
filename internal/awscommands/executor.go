// Package awscommands connects generated AWS inputs to in-process service commands.
package awscommands

import (
	"context"

	"stackd/internal/awsapi"
	"stackd/internal/awswire"
)

// CommandExecutor executes an admitted generated input without an HTTP loopback.
// Implementations retain their service authorization, audit and transaction
// boundaries and return modeled output, not transport response wrappers.
type CommandExecutor interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}
