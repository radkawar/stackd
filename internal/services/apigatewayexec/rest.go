package apigatewayexec

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

// MockIntegration is the supported literal MOCK mapping, snapshotted at deployment.
type MockIntegration struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// GatewayResponse is live API configuration, not a backend response mapping.
type GatewayResponse struct {
	StatusCode int
	Headers    map[string]string
	Templates  map[string]string
}

func binaryMedia(media string, configured []string) bool {
	media, _, _ = strings.Cut(media, ",")
	parsed, _, err := mime.ParseMediaType(strings.TrimSpace(media))
	if err != nil {
		return false
	}
	kind, subtype, ok := strings.Cut(strings.ToLower(parsed), "/")
	if !ok {
		return false
	}
	for _, pattern := range configured {
		pKind, pSubtype, valid := strings.Cut(strings.ToLower(pattern), "/")
		if valid && (pKind == "*" || pKind == kind) && (pSubtype == "*" || pSubtype == subtype) {
			return true
		}
	}
	return false
}

type gatewayResponseWriter struct {
	http.ResponseWriter
	route   *Route
	request *http.Request
}

func (w *gatewayResponseWriter) recordRejection(rejected *rejection) {
	if recorder, ok := w.ResponseWriter.(interface{ recordRejection(*rejection) }); ok {
		recorder.recordRejection(rejected)
	}
}

func (w *gatewayResponseWriter) writeGatewayRejection(rejected *rejection) bool {
	key := "DEFAULT_4XX"
	if rejected.Status >= 500 {
		key = "DEFAULT_5XX"
	}
	config, ok := w.route.GatewayResponses[key]
	if !ok {
		return false
	}
	if recorder, ok := w.ResponseWriter.(interface{ recordRejection(*rejection) }); ok {
		recorder.recordRejection(rejected)
	}
	status := rejected.Status
	if config.StatusCode != 0 {
		status = config.StatusCode
	}
	for name, value := range config.Headers {
		w.Header().Set(name, value)
	}
	media, _, _ := strings.Cut(w.request.Header.Get("Accept"), ",")
	media, _, _ = strings.Cut(strings.TrimSpace(media), ";")
	template, found := config.Templates[media]
	if !found {
		media = "application/json"
		template, found = config.Templates[media]
	}
	if found {
		quoted, _ := json.Marshal(rejected.Message)
		template = strings.NewReplacer("$context.error.messageString", string(quoted), "$context.error.message", rejected.Message, "$context.error.responseType", key).Replace(template)
		w.Header().Set("Content-Type", media)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(template))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(struct {
			Message string `json:"message"`
		}{rejected.Message})
	}
	return true
}
