package organizations

import (
	"io"
	"net/http"

	"stackd/internal/awsapi"
	orgapi "stackd/internal/awsapi/organizations"
	"stackd/internal/awswire"
)

// register uses the generated wire contract before state publication.
// Direct provider users use the same decoder as requests through the gateway.
func register[I, O any](s *Service, action string, fn func(*operationState, *http.Request, *I) (*O, *awswire.Error)) {
	s.operations[action] = func(r *http.Request, prepareResponse func(any) *awswire.Error) (any, *awswire.Error) {
		input, ok := awsapi.Input[I](r.Context())
		if !ok {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
			if err != nil || len(body) > 1<<20 {
				return nil, s.requestFailure(r.Context(), action, nil, failure("InvalidInputException", "Invalid request body."))
			}
			decoded, err := orgapi.DecodeRequest(action, awsapi.Request{JSON: body})
			if err != nil {
				return nil, s.requestFailure(r.Context(), action, nil, s.RequestError(action, err))
			}
			input, ok = decoded.Input.(*I)
			if !ok {
				return nil, s.requestFailure(r.Context(), action, nil, storageFailure())
			}
		}
		return s.execute(r, action, input, func(worker *operationState, r *http.Request) (any, *awswire.Error) {
			out, apiErr := fn(worker, r, input)
			if apiErr != nil {
				return nil, apiErr
			}
			if prepareResponse != nil {
				if apiErr := prepareResponse(out); apiErr != nil {
					return nil, apiErr
				}
			}
			worker.auditOutput = out
			return out, nil
		})
	}
}

func inputString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
