package lambda

import (
	"context"
	"io"

	runtime "stackd/compute/lambda"
)

// LogProvider opens an environment's output destination using that environment's
// actual execution-role credentials. Delivery failures are separate from Invoke.
// The service owns closing the writer after its runtime has drained output.
type LogProvider interface {
	Open(context.Context, FunctionKey, runtime.Credentials, string, string) io.WriteCloser
}

type loggedEnvironment struct {
	runtime.Environment
	output io.Closer
}

func (e *loggedEnvironment) Close(ctx context.Context) error {
	if err := e.Environment.Close(ctx); err != nil {
		return err
	}
	return e.output.Close()
}
