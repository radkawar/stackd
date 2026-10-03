package lambda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/lambda/internal/telemetryapi"
)

type telemetryDestination struct {
	protocol, uri, method string
	port                  int
}

type telemetryOwner interface {
	lookupExtension(string) (string, *runtimeAPIError)
	initializing() bool
}

type telemetryManager struct {
	ctx                                        context.Context
	cancel                                     context.CancelFunc
	owner                                      telemetryOwner
	remote                                     *telemetryBridge
	remoteFailure                              func(error)
	deliver                                    func(context.Context, telemetryDestination, []byte) error
	mu                                         sync.Mutex
	closed                                     bool
	subscribers                                []*telemetrySubscriber
	identities                                 map[string]string
	streams                                    map[*telemetryOutput]struct{}
	history                                    []telemetryEvent
	historyBytes                               int
	recordingInit                              bool
	historyDroppedRecords, historyDroppedBytes uint64
	outputMu                                   sync.Mutex
	output                                     io.Writer
	forwardOutput                              func([]byte, bool, bool)
	logging                                    LoggingConfig
	sinkFailed                                 bool
	tail                                       []byte
	tailActive                                 bool
	tailRecords                                []int
}

func newTelemetryManager(ctx context.Context, owner telemetryOwner, output io.Writer) *telemetryManager {
	ctx, cancel := context.WithCancel(ctx)
	return &telemetryManager{ctx: ctx, cancel: cancel, owner: owner, output: output,
		identities: make(map[string]string), streams: make(map[*telemetryOutput]struct{}), tail: make([]byte, 0, 4096)}
}

func (m *telemetryManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	api := ""
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case "/2020-08-15/logs":
		api = "Logs"
	case "/2022-07-01/telemetry":
		api = "Telemetry"
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	name, err := m.owner.lookupExtension(r.Header.Get("Lambda-Extension-Identifier"))
	if err != nil {
		writeRuntimeError(w, err)
		return
	}
	if !m.owner.initializing() {
		writeRuntimeError(w, &runtimeAPIError{status: 403, code: api + ".SubscriptionClosed", message: api + " API subscription is closed already"})
		return
	}
	body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if readErr != nil {
		writeRuntimeError(w, telemetryError(api, "DeserializationError", readErr.Error()))
		return
	}
	if m.remote != nil {
		reply, bridgeErr := m.remote.call(r.Context(), telemetryCommand{Operation: "subscribe", Name: name, Path: r.URL.Path, Body: body})
		if bridgeErr != nil {
			m.remoteFailure(bridgeErr)
			http.Error(w, "telemetry helper unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.Status)
		_, _ = w.Write(reply.Body)
		return
	}
	request, decodeErr := decodeTelemetrySubscription(body, api)
	if decodeErr != nil {
		writeRuntimeError(w, decodeErr)
		return
	}
	config, validationErr := validateTelemetrySubscription(request, api)
	if validationErr != nil {
		writeRuntimeError(w, validationErr)
		return
	}
	// Keep the presence of optional values in the identity. Native evidence
	// establishes exact duplicate tuples, not equivalence of omitted defaults.
	keyBytes, marshalErr := json.Marshal(request)
	if marshalErr != nil {
		writeRuntimeError(w, telemetryError(api, "DeserializationError", marshalErr.Error()))
		return
	}
	key := string(keyBytes)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		writeRuntimeError(w, &runtimeAPIError{status: 403, code: api + ".SubscriptionClosed", message: api + " API subscription is closed already"})
		return
	}
	if previous := m.identities[name]; previous != "" && previous != api {
		m.mu.Unlock()
		writeRuntimeError(w, telemetryError(api, "AccessDenied", fmt.Sprintf("The extension %s is already subscribed to the %sAPI. You must either subscribe to the LogsAPI or the TelemetryAPI", name, previous)))
		return
	}
	for _, subscriber := range m.subscribers {
		if subscriber.name == name && subscriber.api == api && subscriber.key == key {
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `"AlreadySubscribed"`)
			m.subscriptionEvent(name, api, "Already subscribed", request.Types)
			return
		}
	}
	subscriber := newTelemetrySubscriber(m, name, api, key, config)
	m.identities[name] = api
	m.subscribers = append(m.subscribers, subscriber)
	for _, event := range m.history {
		subscriber.enqueueHistory(event)
	}
	subscriber.droppedRecords += m.historyDroppedRecords
	subscriber.droppedBytes += m.historyDroppedBytes
	m.mu.Unlock()
	go subscriber.run()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `"OK"`)
	m.subscriptionEvent(name, api, "Subscribed", request.Types)
}

func telemetryError(api, code, message string) *runtimeAPIError {
	return &runtimeAPIError{status: 400, code: api + "." + code, message: message}
}

func decodeTelemetrySubscription(body []byte, api string) (*telemetryapi.Subscription, *runtimeAPIError) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, telemetryError(api, "DeserializationError", err.Error())
	}
	if fields == nil {
		return nil, telemetryError(api, "DeserializationError", "expected subscription object")
	}
	for _, field := range []string{"destination", "types"} {
		if len(fields[field]) == 0 {
			return nil, telemetryError(api, "DeserializationError", fmt.Sprintf("missing field `%s`", field))
		}
		if bytes.Equal(fields[field], []byte("null")) {
			return nil, telemetryError(api, "DeserializationError", fmt.Sprintf("invalid null for `%s`", field))
		}
	}
	for _, field := range []string{"schemaVersion", "buffering"} {
		if bytes.Equal(fields[field], []byte("null")) {
			return nil, telemetryError(api, "DeserializationError", fmt.Sprintf("invalid null for `%s`", field))
		}
	}
	for _, object := range []struct {
		name   string
		fields []string
	}{
		{"buffering", []string{"maxBytes", "maxItems", "timeoutMs"}},
		{"destination", []string{"protocol", "URI", "port", "method", "encoding"}},
	} {
		if raw, ok := fields[object.name]; ok {
			var values map[string]json.RawMessage
			if err := json.Unmarshal(raw, &values); err != nil {
				return nil, telemetryError(api, "DeserializationError", err.Error())
			}
			for _, field := range object.fields {
				if bytes.Equal(values[field], []byte("null")) {
					return nil, telemetryError(api, "DeserializationError", fmt.Sprintf("invalid null for `%s`", field))
				}
			}
		}
	}
	var request telemetryapi.Subscription
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, telemetryError(api, "DeserializationError", err.Error())
	}
	if request.SchemaVersion != nil {
		if _, ok := telemetryapi.Versions[*request.SchemaVersion]; !ok {
			versions := make([]string, 0, len(telemetryapi.Versions))
			for version := range telemetryapi.Versions {
				versions = append(versions, string(version))
			}
			sort.Strings(versions)
			return nil, telemetryUnknownVariant(api, string(*request.SchemaVersion), versions)
		}
	}
	for _, eventType := range request.Types {
		if !slices.Contains(telemetryapi.NativeEventTypeValues, string(eventType)) {
			return nil, telemetryUnknownVariant(api, string(eventType), telemetryapi.NativeEventTypeValues)
		}
	}
	d := request.Destination
	if d == nil || d.Protocol == nil {
		return nil, telemetryError(api, "DeserializationError", "missing field `protocol`")
	}
	if *d.Protocol != "HTTP" && *d.Protocol != "TCP" {
		return nil, telemetryUnknownVariant(api, *d.Protocol, []string{"HTTP", "TCP"})
	}
	if d.Method != nil && !slices.Contains(telemetryapi.EnumValues["HttpMethod"], string(*d.Method)) {
		return nil, telemetryUnknownVariant(api, string(*d.Method), telemetryapi.EnumValues["HttpMethod"])
	}
	if d.Encoding != nil && !slices.Contains(telemetryapi.EnumValues["Encoding"], string(*d.Encoding)) {
		return nil, telemetryUnknownVariant(api, string(*d.Encoding), telemetryapi.EnumValues["Encoding"])
	}
	if *d.Protocol == "HTTP" && d.URI == nil {
		return nil, telemetryError(api, "DeserializationError", "missing field `URI`")
	}
	if *d.Protocol == "TCP" && d.Port == nil {
		return nil, telemetryError(api, "DeserializationError", "missing field `port`")
	}
	return &request, nil
}

func telemetryUnknownVariant(api, value string, variants []string) *runtimeAPIError {
	quoted := make([]string, len(variants))
	for i, variant := range variants {
		quoted[i] = "`" + variant + "`"
	}
	expected := "one of " + strings.Join(quoted, ", ")
	if len(quoted) == 1 {
		expected = quoted[0]
	}
	if len(quoted) == 2 {
		expected = quoted[0] + " or " + quoted[1]
	}
	return telemetryError(api, "DeserializationError", fmt.Sprintf("unknown variant `%s`, expected %s", value, expected))
}

type telemetryConfig struct {
	version            telemetryapi.SchemaVersion
	types              []telemetryapi.EventType
	destination        telemetryDestination
	maxBytes, maxItems int
	timeout            time.Duration
}

func validateTelemetrySubscription(r *telemetryapi.Subscription, api string) (telemetryConfig, *runtimeAPIError) {
	versionRule := telemetryapi.SchemaVersionRules[api]
	c := telemetryConfig{version: versionRule.Default, types: slices.Clone(r.Types)}
	if r.SchemaVersion != nil {
		c.version = *r.SchemaVersion
	}
	if (versionRule.Required && r.SchemaVersion == nil) || telemetryapi.Versions[c.version].API != api {
		message := "LogsAPI only supports the following SchemaVersion: 2020-08-15, 2021-03-18"
		if api == "Telemetry" {
			message = "TelemetryAPI only supports the SchemaVersion released after 2021-03-18"
		}
		return c, telemetryError(api, "ValidationError", message)
	}
	if len(r.Types) == 0 {
		return c, telemetryError(api, "ValidationError", "types should not be empty")
	}
	seen := make(map[telemetryapi.EventType]bool, len(r.Types))
	for _, kind := range r.Types {
		if !slices.Contains(telemetryapi.EnumValues["EventType"], string(kind)) {
			return c, telemetryError(api, "ValidationError", "Unrecognized enum variant")
		}
		if seen[kind] {
			return c, telemetryError(api, "ValidationError", "types should be unique")
		}
		seen[kind] = true
	}
	var b telemetryapi.BufferingCfg
	if r.Buffering != nil {
		b = *r.Buffering
	}
	for _, setting := range []struct {
		name   string
		value  *uint64
		target *int
	}{
		{"maxBytes", b.MaxBytes, &c.maxBytes}, {"maxItems", b.MaxItems, &c.maxItems}, {"timeoutMs", b.TimeoutMs, nil},
	} {
		bounds := telemetryapi.BufferingLimits[setting.name]
		value := bounds.Default
		if setting.value != nil {
			value = *setting.value
			if value < bounds.Minimum || value > bounds.Maximum {
				return c, telemetryError(api, "ValidationError", fmt.Sprintf("%s should be between %d and %d", setting.name, bounds.Minimum, bounds.Maximum))
			}
		}
		if setting.target != nil {
			*setting.target = int(value)
		} else {
			c.timeout = time.Duration(value) * time.Millisecond
		}
	}
	d := r.Destination
	c.destination.protocol = *d.Protocol
	if *d.Protocol == "HTTP" {
		u, err := url.Parse(*d.URI)
		if err != nil {
			return c, telemetryError(api, "ValidationError", "invalid destination URI: "+err.Error())
		}
		if u.Scheme != "http" {
			return c, &runtimeAPIError{status: 403, code: api + ".AccessDenied", message: "Only 'http' scheme is supported."}
		}
		if u.Hostname() != "sandbox.localdomain" {
			return c, &runtimeAPIError{status: 403, code: api + ".AccessDenied", message: "Only 'sandbox.localdomain' hostname is supported."}
		}
		if u.User != nil || u.Fragment != "" {
			return c, telemetryError(api, "ValidationError", "invalid destination URI")
		}
		if u.Port() == "" {
			return c, telemetryError(api, "ValidationError", "URI port is not provided")
		}
		port, portErr := strconv.ParseUint(u.Port(), 10, 16)
		if portErr != nil {
			return c, telemetryError(api, "ValidationError", "invalid destination port")
		}
		c.destination.port = int(port)
		c.destination.uri = u.String()
		c.destination.method = telemetryapi.Defaults["HttpMethod"]
		if d.Method != nil {
			c.destination.method = string(*d.Method)
		}
	} else {
		c.destination.port = int(*d.Port)
	}
	limits := telemetryapi.DestinationPortLimits
	if c.destination.protocol == "TCP" && (uint64(c.destination.port) < limits.Minimum || uint64(c.destination.port) > limits.Maximum) {
		return c, telemetryError(api, "ValidationError", fmt.Sprintf("port should be between %d and %d", limits.Minimum, limits.Maximum))
	}
	if c.destination.port == 9001 {
		return c, telemetryError(api, "ValidationError", "port 9001 is reserved")
	}
	return c, nil
}
