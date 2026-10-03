package awsapi

import "context"

type decodedRequestKey struct{}

func WithDecodedRequest(ctx context.Context, request DecodedRequest) context.Context {
	return context.WithValue(ctx, decodedRequestKey{}, request)
}

func FromContext(ctx context.Context) (DecodedRequest, bool) {
	request, ok := ctx.Value(decodedRequestKey{}).(DecodedRequest)
	return request, ok
}

// Input returns the operation-specific generated request stored by the gateway.
func Input[T any](ctx context.Context) (*T, bool) {
	request, ok := FromContext(ctx)
	if !ok {
		return nil, false
	}
	input, ok := request.Input.(*T)
	return input, ok
}
