package lambda

import (
	"context"
	"fmt"
	"strings"
)

// A provided ZIP runtime is the customer's executable bootstrap, not the
// OS-only image's language-runtime entrypoint. The official provided image
// supplies the OS while bootstrap talks directly to our Runtime API.
func (e *dockerEnvironment) customerRuntimeCommand(ctx context.Context, container string) ([]string, error) {
	if e.spec.Image != nil {
		command, _, err := imageCommand(e.spec.Image, e.spec.ImageConfig)
		return command, err
	}
	if strings.HasPrefix(e.spec.Runtime, "provided.") {
		output, err := execOutput(e.engine, ctx, container, []string{"/bin/bash", "-c", `if test -e /var/task/bootstrap; then
 if test -x /var/task/bootstrap; then printf '/var/task/bootstrap'; else printf 'invalid'; fi
elif test -x /opt/bootstrap; then printf '/opt/bootstrap'
else printf 'invalid'; fi`})
		if err != nil {
			return nil, fmt.Errorf("checking custom runtime bootstrap: %w", err)
		}
		switch string(output) {
		case "/var/task/bootstrap", "/opt/bootstrap":
			return []string{string(output)}, nil
		default:
			return nil, &customerFailure{errorType: "Runtime.InvalidEntrypoint", message: "Couldn't find a valid executable bootstrap in the deployment package or layers."}
		}
	}
	return []string{"/lambda-entrypoint.sh", e.spec.Handler}, nil
}
