package apigatewayexec

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

type proxyResponse struct {
	StatusCode        *int                `json:"statusCode"`
	Headers           map[string]string   `json:"headers"`
	MultiValueHeaders map[string][]string `json:"multiValueHeaders"`
	Cookies           []string            `json:"cookies"`
	Body              string              `json:"body"`
	IsBase64Encoded   bool                `json:"isBase64Encoded"`
}

func writeProxyResponse(w http.ResponseWriter, payload []byte, version2 bool, binaryNegotiated ...bool) bool {
	bad := func() { writeRejection(w, &rejection{http.StatusBadGateway, "Internal Server Error"}) }
	if !json.Valid(payload) {
		bad()
		return false
	}
	var members map[string]json.RawMessage
	_ = json.Unmarshal(payload, &members)
	if _, status := members["statusCode"]; version2 && !status {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return true
	}
	var output proxyResponse
	if json.Unmarshal(payload, &output) != nil || output.StatusCode == nil || *output.StatusCode < 100 || *output.StatusCode > 599 {
		bad()
		return false
	}
	body := []byte(output.Body)
	if output.IsBase64Encoded && (len(binaryNegotiated) == 0 || binaryNegotiated[0]) {
		var err error
		body, err = base64.StdEncoding.DecodeString(output.Body)
		if err != nil {
			bad()
			return false
		}
	}
	for name, value := range output.Headers {
		if strings.EqualFold(name, "content-length") || strings.EqualFold(name, "transfer-encoding") {
			continue
		}
		w.Header().Set(name, value)
	}
	if !version2 {
		for name, values := range output.MultiValueHeaders {
			if strings.EqualFold(name, "content-length") || strings.EqualFold(name, "transfer-encoding") {
				continue
			}
			w.Header().Del(name)
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
	} else {
		for _, cookie := range output.Cookies {
			w.Header().Add("Set-Cookie", cookie)
		}
	}
	w.WriteHeader(*output.StatusCode)
	_, _ = w.Write(body)
	return true
}
