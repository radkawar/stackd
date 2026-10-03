package lambda

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// A syntactic preflight is intercepted even when its origin, method or requested
// headers are denied. Denial is an empty 200 without CORS grants, not invocation.
func functionURLPreflight(w http.ResponseWriter, r *http.Request, cors *FunctionURLCORS) bool {
	if cors == nil || r.Method != http.MethodOptions || r.Header.Get("Origin") == "" || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", "0")
	allowed := functionURLAllowOrigin(r, cors) != "" && (slices.Contains(cors.AllowMethods, "*") || slices.Contains(cors.AllowMethods, r.Header.Get("Access-Control-Request-Method")))
	for _, requested := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		requested = strings.TrimSpace(requested)
		if requested == "" {
			continue
		}
		if !slices.ContainsFunc(cors.AllowHeaders, func(allowed string) bool { return allowed == "*" || strings.EqualFold(allowed, requested) }) {
			allowed = false
			break
		}
	}
	if allowed {
		functionURLCORSHeaders(header, r, cors, true)
		if len(cors.AllowMethods) != 0 {
			header.Set("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ","))
		}
		if len(cors.AllowHeaders) != 0 {
			header.Set("Access-Control-Allow-Headers", strings.Join(cors.AllowHeaders, ","))
		}
		if cors.MaxAge != nil {
			header.Set("Access-Control-Max-Age", strconv.FormatInt(int64(*cors.MaxAge), 10))
		}
	}
	w.WriteHeader(http.StatusOK)
	return true
}

func functionURLAllowOrigin(r *http.Request, cors *FunctionURLCORS) string {
	if cors == nil || r.Header.Get("Origin") == "" {
		return ""
	}
	if slices.Contains(cors.AllowOrigins, "*") {
		return "*"
	}
	if slices.Contains(cors.AllowOrigins, r.Header.Get("Origin")) {
		return r.Header.Get("Origin")
	}
	return ""
}

// Native URLs preserve separate configured/function origin and credential
// fields, but merge their exposed-header lists into a single field.
func functionURLCORSHeaders(header http.Header, r *http.Request, cors *FunctionURLCORS, preflight bool) {
	origin := functionURLAllowOrigin(r, cors)
	if origin == "" {
		return
	}
	header.Add("Access-Control-Allow-Origin", origin)
	if origin != "*" {
		header.Add("Vary", "Origin")
	}
	if cors.AllowCredentials != nil && *cors.AllowCredentials {
		header.Add("Access-Control-Allow-Credentials", "true")
	}
	if !preflight && len(cors.ExposeHeaders) != 0 {
		values := header.Values("Access-Control-Expose-Headers")
		values = append(values, cors.ExposeHeaders...)
		header.Set("Access-Control-Expose-Headers", strings.Join(values, ","))
	}
}
