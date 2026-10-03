package lambda

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"stackd/compute/lambda/internal/extensionapi"
	"stackd/compute/lambda/internal/telemetryapi"
)

// External extensions share function credentials and customer variables, but
// AWS excludes runtime-only configuration, including values inherited from the
// base image. Apply that boundary to the external process, not the container.
func (e *dockerEnvironment) startExtension(ctx context.Context, runtime *dockerRuntime, name string) error {
	command := []string{
		"/usr/bin/env",
		"-u", "AWS_EXECUTION_ENV",
		"-u", "AWS_LAMBDA_LOG_GROUP_NAME",
		"-u", "AWS_LAMBDA_LOG_STREAM_NAME",
		"-u", "AWS_XRAY_CONTEXT_MISSING",
		"-u", "AWS_XRAY_DAEMON_ADDRESS",
		"-u", "LAMBDA_RUNTIME_DIR",
		"-u", "LAMBDA_TASK_ROOT",
		"-u", "_AWS_XRAY_DAEMON_ADDRESS",
		"-u", "_AWS_XRAY_DAEMON_PORT",
		"-u", "_HANDLER",
		"/opt/extensions/" + name,
	}
	_, err := e.startCustomer(ctx, runtime, name, "extension", command)
	return err
}

const extensionPrefix = "/2020-01-01/extension/"

type runtimeAPIError struct {
	status        int
	code, message string
}

func writeRuntimeError(w http.ResponseWriter, err *runtimeAPIError) {
	writeRuntimeJSON(w, err.status, extensionapi.ErrorResponse{ErrorType: &err.code, ErrorMessage: &err.message})
}

func newRuntimeID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	value[6] = value[6]&15 | 64
	value[8] = value[8]&63 | 128
	text := hex.EncodeToString(value[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

type runtimeExtension struct {
	id, name, state                             string
	external, polling, invoke, shutdown, exited bool
	shutdownDelivered                           bool
	events                                      chan any
	readyAt                                     time.Time
}

func extensionIdentifierError(identifier string) *runtimeAPIError {
	if identifier == "" {
		return &runtimeAPIError{403, "Extension.MissingExtensionIdentifier", "Missing Lambda-Extension-Identifier header"}
	}
	if len(identifier) != 36 || identifier[8] != '-' || identifier[13] != '-' || identifier[18] != '-' || identifier[23] != '-' {
		return &runtimeAPIError{403, "Extension.InvalidExtensionIdentifier", "Invalid Lambda-Extension-Identifier"}
	}
	if _, err := hex.DecodeString(strings.ReplaceAll(identifier, "-", "")); err != nil {
		return &runtimeAPIError{403, "Extension.InvalidExtensionIdentifier", "Invalid Lambda-Extension-Identifier"}
	}
	return nil
}

func (e *dockerEnvironment) lookupExtension(identifier string) (string, *runtimeAPIError) {
	if err := extensionIdentifierError(identifier); err != nil {
		return "", err
	}
	runtime := e.currentRuntime()
	if runtime != nil {
		runtime.mu.Lock()
		extension := runtime.extensions[strings.ToLower(identifier)]
		runtime.mu.Unlock()
		if extension != nil && runtime.ctx.Err() == nil {
			return extension.name, nil
		}
	}
	return "", &runtimeAPIError{403, "Extension.UnknownExtensionIdentifier", "Unknown extension " + identifier}
}

func (e *dockerEnvironment) initializing() bool {
	runtime := e.currentRuntime()
	if runtime == nil {
		return false
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.phase == "Init"
}

func invalidExtensionState(extension *runtimeExtension, target string) *runtimeAPIError {
	return &runtimeAPIError{403, "Extension.InvalidExtensionState", fmt.Sprintf("State transition from %s to %s failed for extension %s. Error: State transition is not allowed", extension.state, target, extension.id)}
}

func (e *dockerEnvironment) extensionAPI(runtime *dockerRuntime, w http.ResponseWriter, request *http.Request) {
	operation := strings.TrimPrefix(request.URL.Path, extensionPrefix)
	if operation == "register" && request.Method == http.MethodPost {
		e.registerExtension(runtime, w, request)
		return
	}
	identifier := request.Header.Get("Lambda-Extension-Identifier")
	if _, err := e.lookupExtension(identifier); err != nil {
		writeRuntimeError(w, err)
		return
	}
	runtime.mu.Lock()
	extension := runtime.extensions[strings.ToLower(identifier)]
	runtime.mu.Unlock()
	if extension == nil {
		writeRuntimeError(w, &runtimeAPIError{403, "Extension.UnknownExtensionIdentifier", "Unknown extension " + identifier})
		return
	}
	switch {
	case operation == "event/next" && request.Method == http.MethodGet:
		e.nextExtension(runtime, extension, w, request)
	case (operation == "init/error" || operation == "exit/error") && request.Method == http.MethodPost:
		e.extensionError(runtime, extension, operation, w, request)
	default:
		http.NotFound(w, request)
	}
}

func (e *dockerEnvironment) registerExtension(runtime *dockerRuntime, w http.ResponseWriter, request *http.Request) {
	name := request.Header.Get("Lambda-Extension-Name")
	if name == "" {
		writeRuntimeError(w, &runtimeAPIError{403, "Extension.InvalidExtensionName", "Empty extension name"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, maxRuntimeResponse))
	var input extensionapi.RegisterRequest
	if err == nil {
		err = json.Unmarshal(body, &input)
	}
	if err != nil {
		writeRuntimeError(w, &runtimeAPIError{403, "InvalidRequestFormat", err.Error()})
		return
	}
	runtime.mu.Lock()
	fail := func(err *runtimeAPIError) { runtime.mu.Unlock(); writeRuntimeError(w, err) }
	if runtime.phase != "Init" || runtime.initialized {
		fail(&runtimeAPIError{403, "Extension.RegistrationClosed", "Extension registration is closed"})
		return
	}
	external := runtime.expected[name]
	extension := &runtimeExtension{id: newRuntimeID(), name: name, state: "Registered", external: external, events: make(chan any, 1)}
	for _, event := range input.Events {
		switch event {
		case "INVOKE":
			extension.invoke = true
		case "SHUTDOWN":
			if !external {
				fail(&runtimeAPIError{403, "Extension.InvalidEventType", "SHUTDOWN: ShutdownEventNotSupportedForInternalExtension"})
				return
			}
			extension.shutdown = true
		default:
			fail(&runtimeAPIError{403, "Extension.InvalidEventType", event + ": ErrorInvalidEventType"})
			return
		}
	}
	if _, exists := runtime.byName[name]; exists {
		fail(&runtimeAPIError{403, "Extension.AlreadyRegistered", "Extension already registered"})
		return
	}
	if len(runtime.extensions) == 10 {
		fail(&runtimeAPIError{403, "Extension.TooManyExtensions", "Extension limit (10) reached"})
		return
	}
	runtime.extensions[extension.id] = extension
	runtime.byName[name] = extension
	runtime.changedLocked()
	runtime.mu.Unlock()
	response := extensionapi.RegisterResponse{FunctionName: &e.spec.FunctionName, FunctionVersion: new(e.functionVersion()), Handler: &e.spec.Handler}
	for _, feature := range strings.Split(request.Header.Get("Lambda-Extension-Accept-Feature"), ",") {
		if strings.TrimSpace(feature) == "accountId" {
			response.AccountId = new(strings.Split(e.spec.FunctionARN, ":")[4])
		}
	}
	w.Header().Set("Lambda-Extension-Identifier", extension.id)
	e.telemetry.Emit(time.Now(), "platform.extension", telemetryapi.PlatformExtension{Name: name, State: "Ready", Events: input.Events})
	writeRuntimeJSON(w, http.StatusOK, response)
}

func (e *dockerEnvironment) nextExtension(runtime *dockerRuntime, extension *runtimeExtension, w http.ResponseWriter, request *http.Request) {
	runtime.mu.Lock()
	if extension.polling || (extension.state != "Registered" && extension.state != "Running" && extension.state != "Shutdown") {
		err := invalidExtensionState(extension, "Ready")
		runtime.mu.Unlock()
		writeRuntimeError(w, err)
		return
	}
	extension.state = "Ready"
	extension.polling = true
	extension.readyAt = time.Now()
	runtime.changedLocked()
	runtime.mu.Unlock()
	defer func() { runtime.mu.Lock(); extension.polling = false; runtime.changedLocked(); runtime.mu.Unlock() }()
	select {
	case event := <-extension.events:
		runtime.mu.Lock()
		if _, shutdown := event.(extensionapi.EventShutdown); shutdown {
			extension.state = "Shutdown"
			extension.shutdownDelivered = true
		} else {
			extension.state = "Running"
		}
		runtime.mu.Unlock()
		writeRuntimeJSON(w, http.StatusOK, event)
	case <-runtime.ctx.Done():
		writeRuntimeError(w, &runtimeAPIError{403, "Extension.UnknownExtensionIdentifier", "Unknown extension " + extension.id})
	case <-request.Context().Done():
	}
}

func (e *dockerEnvironment) extensionError(runtime *dockerRuntime, extension *runtimeExtension, operation string, w http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, maxRuntimeResponse))
	var input extensionapi.ErrorRequest
	if err == nil && len(body) != 0 {
		err = json.Unmarshal(body, &input)
	}
	if err != nil {
		writeRuntimeError(w, &runtimeAPIError{400, "InvalidRequestFormat", err.Error()})
		return
	}
	target := "ExitError"
	if operation == "init/error" {
		target = "InitError"
	}
	runtime.mu.Lock()
	allowed := extension.state == target || (target == "InitError" && extension.state == "Registered") || (target == "ExitError" && extension.state != "InitError")
	if !allowed {
		stateErr := invalidExtensionState(extension, target)
		runtime.mu.Unlock()
		writeRuntimeError(w, stateErr)
		return
	}
	extension.state = target
	if runtime.phase != "Shutdown" && runtime.reportedError == nil {
		message := "Extension failed to initialize"
		errorType := "Extension.InitError"
		if target == "ExitError" {
			errorType = "Extension.Crash"
			message = "Extension failed to exit"
		}
		runtime.reportedError = &customerFailure{errorType: errorType, message: message}
	}
	// The error state is terminal, but repeated reports remain accepted while the
	// extension exits. Its real exit supplies the native status/message; a process
	// which refuses to exit still cannot pass the phase's deadline or Ready barrier.
	runtime.changedLocked()
	runtime.mu.Unlock()
	writeRuntimeJSON(w, http.StatusAccepted, extensionapi.StatusResponse{Status: new("OK")})
	_ = http.NewResponseController(w).Flush()
}

func (e *dockerEnvironment) functionVersion() string {
	parts := strings.Split(e.spec.FunctionARN, ":")
	if len(parts) > 7 {
		return parts[7]
	}
	return "$LATEST"
}
