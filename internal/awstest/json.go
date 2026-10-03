package awstest

import (
	"bytes"
	"context"
	"fmt"

	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// JSONBody preserves captured fields that an SDK serializer cannot represent,
// including explicit nulls and malformed inputs. The SDK still owns routing,
// signing and response decoding. The caller must keep body immutable.
func JSONBody(body []byte) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Build.Add(middleware.BuildMiddlewareFunc("AWSFixtureJSONBody", func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
			request, ok := input.Request.(*smithyhttp.Request)
			if !ok {
				return middleware.BuildOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected SDK request %T", input.Request)
			}
			request, err := request.SetStream(bytes.NewReader(body))
			if err != nil {
				return middleware.BuildOutput{}, middleware.Metadata{}, err
			}
			request.ContentLength = int64(len(body))
			input.Request = request
			return next.HandleBuild(ctx, input)
		}), middleware.Before)
	}
}
