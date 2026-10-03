package awswire

import (
	"net/http"
	"strings"

	"stackd/internal/awscatalog"
)

// AWS JSON error members are case sensitive. Organizations models Message,
// while KMS models message. Use the same generated shapes as normal responses;
// unmodeled protocol/authentication errors retain the common JSON envelope.
func jsonErrorEnvelope(w http.ResponseWriter, r *http.Request, err *Error) (map[string]any, string) {
	errorType, headerType := err.Code, err.Code
	var model *awscatalog.Service
	prefix, _, _ := JSONTarget(r.Header.Get("X-Amz-Target"))
	if prefix != "" {
		for _, info := range awscatalog.Services() {
			if info.TargetPrefix != prefix {
				continue
			}
			service, _ := awscatalog.LookupService(info.Name)
			model = &service
			shape, ok := service.ErrorShape(err.Code)
			if service.QueryCompatible {
				headerType = ""
				setQueryErrorHeader(w, r, err, shape.Error.Code)
				if ok {
					errorType = string(shape.ID)
				}
			}
			break
		}
	}
	body := jsonErrorBody(model, err, "Reason")
	if model != nil && model.Name == "sqs" && err.Code == "AccessDenied" {
		// Native JSON uses the Coral exception; query-compatible SDKs retain
		// AccessDenied through X-Amzn-Query-Error, not the JSON type name.
		errorType = "com.amazon.coral.service#AccessDeniedException"
		delete(body, "message")
		body["Message"] = err.Message
	}
	body["__type"] = errorType
	return body, headerType
}

// JSON protocols share modeled member binding; their unmodeled reason spelling
// and outer type envelopes differ.
func jsonErrorBody(service *awscatalog.Service, err *Error, reasonName string) map[string]any {
	messageName, typeName, fieldsName, resourcesName := "message", "Type", "fieldList", "resourceIds"
	body := make(map[string]any)
	if service != nil {
		if shape, ok := service.ErrorShape(err.Code); ok {
			for _, member := range shape.Members {
				name := member.JSONName
				if name == "" {
					name = member.Name
				}
				switch strings.ToLower(member.Name) {
				case "message":
					messageName = name
				case "reason":
					reasonName = name
				case "type":
					typeName = name
				case "fieldlist":
					fieldsName = name
				case "resourceids":
					resourcesName = name
				}
				if detail, exists := err.Details[name]; exists {
					body[name] = detail
				}
			}
		}
	}
	body[messageName] = err.Message
	if err.Reason != "" {
		body[reasonName] = err.Reason
	}
	if err.Type != "" {
		body[typeName] = err.Type
	}
	if err.Fields != nil {
		body[fieldsName] = err.Fields
	}
	if err.ResourceIDs != nil {
		body[resourcesName] = err.ResourceIDs
	}
	return body
}

// Query-compatible JSON and CBOR clients use this header to retain the legacy
// AWS Query error code even when the document names a different Smithy shape.
func setQueryErrorHeader(w http.ResponseWriter, r *http.Request, err *Error, queryCode string) {
	if r.Header.Get("X-Amzn-Query-Mode") != "true" {
		return
	}
	kind := "Sender"
	if errorStatus(err) >= 500 {
		kind = "Receiver"
	}
	if queryCode == "" {
		queryCode = err.Code
	}
	w.Header().Set("X-Amzn-Query-Error", queryCode+";"+kind)
}
