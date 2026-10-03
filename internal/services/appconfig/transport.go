package appconfig

import (
	"context"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

type configurationRequestKey struct{}
type configurationRequest struct {
	accept  string
	headers http.Header
}

func configurationAccept(ctx context.Context) string {
	if v, ok := ctx.Value(configurationRequestKey{}).(*configurationRequest); ok {
		return v.accept
	}
	return ""
}
func setConfigurationHeader(ctx context.Context, key, value string) {
	if v, ok := ctx.Value(configurationRequestKey{}).(*configurationRequest); ok {
		if v.headers == nil {
			v.headers = make(http.Header)
		}
		v.headers.Set(key, value)
	}
}
func isAgentRequest(ctx context.Context) bool {
	for _, part := range strings.Split(configurationAccept(ctx), ",") {
		kind, parameters, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || kind != "application/ion" || parameters["type"] != "AWS.AppConfig.FeatureFlags" {
			continue
		}
		if q, ok := parameters["q"]; ok {
			quality, err := strconv.ParseFloat(q, 64)
			if err != nil || quality <= 0 {
				continue
			}
		}
		return true
	}
	return false
}
