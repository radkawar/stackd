// Package awstest supports SDK replay of captured AWS wire inputs.
package awstest

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// QueryValues changes selected fields after SDK serialization and before signing.
// Nil values remove a field, allowing fixtures to replace SDK list indexing too.
func QueryValues(values url.Values) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Build.Add(middleware.BuildMiddlewareFunc("AWSFixtureQueryValues", func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
			request, ok := input.Request.(*smithyhttp.Request)
			if !ok {
				return middleware.BuildOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected SDK request %T", input.Request)
			}
			query := request.URL.RawQuery
			if request.Method != "GET" {
				data, err := io.ReadAll(request.GetStream())
				if err != nil {
					return middleware.BuildOutput{}, middleware.Metadata{}, err
				}
				query = string(data)
			}
			parameters, err := url.ParseQuery(query)
			if err != nil {
				return middleware.BuildOutput{}, middleware.Metadata{}, err
			}
			for name, value := range values {
				if value == nil {
					parameters.Del(name)
				} else {
					parameters[name] = value
				}
			}
			body := parameters.Encode()
			if request.Method == "GET" {
				request.URL.RawQuery = body
			} else {
				request, err = request.SetStream(strings.NewReader(body))
				if err != nil {
					return middleware.BuildOutput{}, middleware.Metadata{}, err
				}
				request.ContentLength = int64(len(body))
			}
			input.Request = request
			return next.HandleBuild(ctx, input)
		}), middleware.Before)
	}
}
