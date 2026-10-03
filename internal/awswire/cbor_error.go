package awswire

import (
	"net/http"
	"strings"

	"github.com/aws/smithy-go/encoding/cbor"

	"stackd/internal/awscatalog"
)

// RPCV2Error uses the absolute Smithy error identity, not its legacy Query code.
func RPCV2Error(w http.ResponseWriter, r *http.Request, service *awscatalog.Service, err *Error) {
	namespace, _, _ := strings.Cut(string(service.ID), "#")
	errorType, messageName := namespace+"#"+err.Code, "message"
	shape, ok := service.ErrorShape(err.Code)
	if ok {
		errorType = string(shape.ID)
		for _, member := range shape.Members {
			if strings.EqualFold(member.Name, "message") {
				messageName = member.Name
				break
			}
		}
	}
	body := cbor.Map{
		"__type":    cbor.String(errorType),
		messageName: cbor.String(err.Message),
	}
	if service.QueryCompatible {
		setQueryErrorHeader(w, r, err, shape.Error.Code)
	}
	setHeaders(w, r, "application/cbor")
	w.Header().Set("Smithy-Protocol", "rpc-v2-cbor")
	w.WriteHeader(errorStatus(err))
	_, _ = w.Write(cbor.Encode(body))
}
