package lambda

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"stackd/clock"
	runtime "stackd/compute/lambda"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type execution struct {
	key FunctionVersionKey
	// image is a retention root from admission through slot collection, including
	// cold preparation before any native container exists. Guarded by Service.mu.
	image                 *runtime.Image
	mu                    sync.Mutex
	environment           runtime.Environment
	retired               []runtime.Environment
	revision              string
	expires               time.Time
	lastUse               time.Time
	leased, retiring      bool
	idleTimer             clock.Timer
	stopIdle              func()
	provisioned           FunctionReference
	provisionedGeneration string
	provisionedReady      bool
	provisionedExpires    time.Time
}

func (e *execution) close(ctx context.Context) error {
	if e.stopIdle != nil {
		e.stopIdle()
	}
	var errs []error
	if e.environment != nil {
		if err := e.environment.Close(ctx); err != nil {
			errs = append(errs, err)
		} else {
			e.environment = nil
			e.revision = ""
		}
	}
	retained := e.retired[:0]
	for _, environment := range e.retired {
		if err := environment.Close(ctx); err != nil {
			errs = append(errs, err)
			retained = append(retained, environment)
		}
	}
	e.retired = retained
	return errors.Join(errs...)
}
func (e *execution) retire(environment runtime.Environment) {
	if environment == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := environment.Close(ctx); err != nil {
		e.retired = append(e.retired, environment)
		slog.Error("Lambda environment cleanup failed; retained for shutdown retry", "error", err)
	}
}
func (s *Service) execution(v FunctionRecord) *execution {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.executionLocked(FunctionVersionKey{FunctionKey: v.Key, Version: v.Version})
	slot.image = v.Image
	return slot
}

// executionLocked reserves exclusive engine ownership during admission. It
// never waits for an engine lock while Service.mu is held.
func (s *Service) executionLocked(key FunctionVersionKey) *execution {
	for _, slot := range s.environments[key] {
		if !slot.leased && !slot.retiring && slot.provisionedGeneration == "" {
			slot.leased = true
			return slot
		}
	}
	slot := &execution{key: key, leased: true}
	s.environments[key] = append(s.environments[key], slot)
	return slot
}
func ownerContext(ctx context.Context, key FunctionKey) context.Context {
	origin := awsctx.FromContext(ctx)
	// Execution credentials belong to Lambda, not the invoking actor. Retain
	// only correlation metadata for the independently audited STS assumption.
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.Account, Region: key.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID})
}
func (s *Service) prepare(ctx context.Context, v FunctionRecord) (runtime.Environment, time.Time, error) {
	return s.prepareMode(ctx, v, false)
}

func (s *Service) prepareMode(ctx context.Context, v FunctionRecord, provisioned bool) (runtime.Environment, time.Time, error) {
	if v.Capacity != nil {
		return nil, time.Time{}, failure("InvalidParameterValueException", "Managed-instance functions must execute through their capacity provider.", 400)
	}
	if s.executor == nil || s.roles == nil {
		return nil, time.Time{}, unsupported("No Lambda container executor is configured.")
	}
	var archive CodeArchive
	var layers [][]byte
	if err := s.repository.View(ctx, func(r Reader) error {
		if v.Image != nil {
			return nil
		}
		var err error
		archive, err = r.CodeArchive(CodeArchiveKey{Scope: v.Key.Scope, SHA256: v.CodeSHA256})
		if err != nil {
			return err
		}
		layers, err = deploymentLayerCode(r, v.Layers)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	credentials, wire := s.roles.Assume(ownerContext(ctx, v.Key), v.Role, v.Key.ARN(), v.Key.Name)
	if wire != nil {
		return nil, time.Time{}, wire
	}
	specification := runtime.Specification{FunctionARN: (FunctionVersionKey{FunctionKey: v.Key, Version: v.Version}).ARN(), FunctionName: v.Key.Name, Runtime: v.Runtime, Handler: v.Handler, Architecture: v.Architecture, Code: archive.Code, Layers: layers, Variables: v.Variables, Timeout: time.Duration(v.Timeout) * time.Second, MemoryMB: v.MemoryMB, EphemeralMB: v.EphemeralMB, Credentials: credentials, Endpoint: s.endpoint}
	specification.Image = cloneDeploymentImage(v.Image)
	specification.ImageConfig = runtimeImageConfig(v.ImageConfig)
	specification.Provisioned = provisioned
	specification.LogGroup = functionLogGroup(v)
	specification.LogStream = functionLogStream(v, s.clock.Now())
	specification.Logging = v.Logging
	network, err := s.openFunctionNetwork(ctx, v)
	if err != nil {
		if network != nil {
			if cleanupErr := network.Close(context.WithoutCancel(ctx)); cleanupErr != nil {
				return wrapFunctionNetworkFailure(network, err), time.Time{}, errors.Join(err, cleanupErr)
			}
		}
		return nil, time.Time{}, err
	}
	specification.FunctionNetwork = network
	if network != nil {
		network.BindExecutionCredential(credentials.AccessKeyID)
	}
	var output io.WriteCloser
	if s.logs != nil {
		output = s.logs.Open(ownerContext(ctx, v.Key), v.Key, credentials, specification.LogGroup, specification.LogStream)
		specification.Logs = output
	}
	environment, err := s.executor.Prepare(ctx, specification)
	if environment == nil && network != nil {
		if cleanupErr := network.Close(context.WithoutCancel(ctx)); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
			environment = wrapFunctionNetworkFailure(network, err)
		}
	}
	if output != nil {
		if environment == nil {
			_ = output.Close()
		} else {
			environment = &loggedEnvironment{Environment: environment, output: output}
		}
	}
	if environment != nil {
		environment = &invocationEnvironment{Environment: environment, service: s, accessKeyID: credentials.AccessKeyID}
	}
	return environment, credentials.Expiration, err
}
func (s *Service) activate(v FunctionRecord) {
	if v.Capacity != nil {
		s.activateManaged(v)
		return
	}
	slot := s.execution(v)
	slot.mu.Lock()
	released := false
	defer func() {
		if !released {
			s.releaseExecution(slot)
		}
		slot.mu.Unlock()
	}()
	ctx := ownerContext(s.lifetime, v.Key)
	var current FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error { var err error; current, err = r.Function(v.Key); return err })
	if err != nil || current.DeploymentRevision != v.DeploymentRevision || current.State != "Pending" {
		return
	}
	environment, expiration, prepareErr := s.prepare(ctx, v)
	s.mu.Lock()
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Function(v.Key)
		if err != nil {
			return err
		}
		if current.DeploymentRevision != v.DeploymentRevision {
			return errors.New("function deployment was superseded")
		}
		current.Revision = uuid.NewString()
		if prepareErr == nil {
			current.State, current.StateReason, current.StateReasonCode = "Active", "", ""
		} else {
			current.State, current.StateReason, current.StateReasonCode = "Failed", prepareErr.Error(), "InternalError"
		}
		if err := tx.PutFunction(current); err != nil {
			return err
		}
		current.Revision = uuid.NewString()
		return tx.SetPublishedDeploymentState(current)
	})
	if err == nil && prepareErr == nil {
		slot.environment = environment
		slot.revision = v.DeploymentRevision
		slot.expires = expiration
		slot.lastUse = s.clock.Now()
		if s.keepAlive != 0 {
			s.releaseExecutionLocked(slot)
			released = true
		}
	}
	s.mu.Unlock()
	if err != nil || prepareErr != nil {
		slot.retire(environment)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrNotFound) {
			slog.Error("Lambda activation commit failed", "function", v.Key.ARN(), "error", err)
		}
		return
	}
	s.jobs.Wake()
}

// Start resumes committed pending deployments. Active functions load lazily into
// new owned containers; a persisted state does not claim a running environment.
func (s *Service) Start() error {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	started, closed := s.started.Load(), s.closed.Load()
	if closed {
		return errors.New("lambda service is closed")
	}
	if started {
		return nil
	}
	if s.executor == nil && s.capacityBackend == nil {
		return nil
	}
	s.imageMu.Lock()
	retentionErr := s.reconcileImages(s.lifetime)
	s.imageMu.Unlock()
	if retentionErr != nil {
		return retentionErr
	}
	if err := s.recoverDurableExecutions(); err != nil {
		return err
	}
	if err := s.recoverInvocations(); err != nil {
		return err
	}
	var pending, updates []FunctionRecord
	err := s.repository.View(s.lifetime, func(r Reader) error {
		rows, err := r.AllFunctions()
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.State == "Pending" {
				pending = append(pending, v)
			}
		}
		updates, err = r.PendingFunctions()
		return err
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errors.New("lambda service is closed")
	}
	s.started.Store(true)
	s.startSQSPollingLocked()
	s.startStreamPollingLocked()
	s.startKafkaPollingLocked()
	s.startProvisionedLocked()
	s.startMQPollingLocked()
	s.startDocumentDBPollingLocked()
	s.jobs.Wake()
	for _, v := range pending {
		s.work.Add(1)
		go func() { defer s.work.Done(); s.activate(v) }()
	}
	for _, v := range updates {
		s.work.Add(1)
		go func() { defer s.work.Done(); s.deployUpdate(v) }()
	}
	return nil
}
func (s *Service) Close() error {
	s.mu.Lock()
	s.closed.Store(true)
	s.cancel()
	s.mu.Unlock()
	s.jobs.Close()
	s.work.Wait()
	s.mu.Lock()
	var slots []*execution
	for _, pool := range s.environments {
		slots = append(slots, pool...)
	}
	s.mu.Unlock()
	cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var errs []error
	for _, slot := range slots {
		slot.mu.Lock()
		err := slot.close(cleanup)
		s.mu.Lock()
		slot.leased, slot.retiring = false, true
		s.collectExecutionLocked(slot)
		s.mu.Unlock()
		slot.mu.Unlock()
		if err != nil {
			errs = append(errs, err)
		}
	}
	s.imageMu.Lock()
	if err := s.reconcileImages(cleanup); err != nil {
		errs = append(errs, err)
	}
	s.imageMu.Unlock()
	return errors.Join(errs...)
}

// executionResponse crosses the function-response boundary, not phase completion.
type executionResponse struct {
	output *invocationOutput
	wire   *awswire.Error
}

// invocationOptions owns source-specific admission and trace information that
// is not a customer field in the generated Invoke input.
type invocationOptions struct {
	URLAuthType string
	TraceID     string
}

func (s *Service) invoke(ctx context.Context, in *api.InvokeInput) (*invocationOutput, *awswire.Error) {
	return s.submitInvocation(ctx, in, nil, invocationOptions{})
}

func (s *Service) submitInvocation(ctx context.Context, in *api.InvokeInput, stream *invocationStream, options invocationOptions) (*invocationOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	key := ref.FunctionKey
	kind := value(in.InvocationType)
	if kind == "" || stream != nil {
		kind = "RequestResponse"
	}
	if in.TenantId != nil {
		return nil, unsupported("Tenant-isolated invocation is not implemented.")
	}
	if kind != "RequestResponse" && kind != "DryRun" && kind != "Event" {
		return nil, failure("InvalidParameterValueException", "Invalid InvocationType.", 400)
	}
	if out, wire, handled := s.submitDurableInvocation(ctx, in, stream, options); handled {
		return out, wire
	}
	payload := []byte(in.Payload)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if kind == "Event" {
		if wire := s.acceptEvent(ctx, ref, payload); wire != nil {
			return nil, wire
		}
		return &invocationOutput{InvokeOutput: api.InvokeOutput{StatusCode: new(api.Integer(202))}}, nil
	}
	if wire := checkSynchronousPayloadSize(in.Payload); wire != nil {
		return nil, wire
	}
	if !json.Valid(payload) {
		return nil, failure("InvalidRequestContentException", "Could not parse request body into JSON.", 400)
	}
	clientContext := ""
	if in.ClientContext != nil {
		encoded := value(in.ClientContext)
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(encoded) > 3583 {
			return nil, failure("InvalidRequestContentException", "ClientContext must be base64-encoded JSON within the 3583-byte limit.", 400)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, decoded); err != nil {
			return nil, failure("InvalidRequestContentException", "ClientContext must contain JSON.", 400)
		}
		clientContext = compact.String()
	}
	metadata := awsctx.FromContext(ctx)
	if options.TraceID == "" {
		options.TraceID = metadata.TraceHeader
	}
	var v FunctionRecord
	var slot *execution
	admitted := false
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil, failure("ServiceException", "Lambda service is shutting down.", 503)
	}
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		if kind == "DryRun" {
			v, err = loadFunction(r, ref)
		} else {
			v, err = selectFunction(r, ref, metadata.RequestID, 0)
		}
		if err != nil {
			return err
		}
		if wire := s.authorizeInvocation(r, ref, v, options.URLAuthType); wire != nil {
			return wire
		}
		if kind != "DryRun" {
			_, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: key, Version: v.Version}, ref)
			if wire != nil {
				return wire
			}
			admitted = true
			slot = s.invocationExecutionLocked(FunctionVersionKey{FunctionKey: key, Version: v.Version}, ref)
			slot.image = v.Image
		}
		return nil
	})
	if err == nil && options.URLAuthType != "" {
		// Commit the accepted URL's parent event before starting customer code.
		// The original caller context avoids making this event its own parent.
		auditContext, cancel := apievents.CompletionContext(ctx)
		err = s.recordFunctionURLInvocation(auditContext, ref, versionName(v.Version))
		cancel()
	}
	if err == nil && kind != "DryRun" {
		// Register accepted background execution before shutdown can begin Wait.
		s.work.Add(1)
		if stream != nil {
			s.work.Add(1)
		}
	}
	s.mu.Unlock()
	if err != nil {
		if admitted {
			s.releaseInvocation(key, slot)
			slot.mu.Lock()
			s.releaseExecution(slot)
			slot.mu.Unlock()
		}
		wire := wireError(err)
		if wire.Code == "TooManyRequestsException" || wire.Code == "RecursiveInvocationException" {
			if err := s.repository.Update(context.WithoutCancel(ctx), func(tx Transaction) error {
				if wire.Code == "RecursiveInvocationException" {
					return s.stageMetric(tx, ref, s.clock.Now(), "RecursiveInvocationsDropped", 1)
				}
				return s.stageThrottleMetrics(tx, ref, s.clock.Now())
			}); err != nil {
				return nil, wireError(err)
			}
			s.jobs.Wake()
		}
		return nil, wire
	}
	if kind == "DryRun" {
		if err := s.recordInvocation(ctx, "Invoke", in, nil, versionName(v.Version)); err != nil {
			return nil, wireError(err)
		}
		return &invocationOutput{InvokeOutput: api.InvokeOutput{StatusCode: new(api.Integer(204))}}, nil
	}
	response := make(chan executionResponse, 1)
	if stream != nil {
		stream.response = response
		stream.output.ExecutedVersion = new(api.Version(versionName(v.Version)))
		go func() {
			defer s.work.Done()
			stream.finish()
		}()
	}
	metadata.ParentEventID = ""
	if s.apiEvents != nil {
		metadata.ParentEventID = apievents.EventID(ctx)
	}
	executionContext := awsctx.WithMetadata(context.WithoutCancel(ctx), metadata)
	go func() {
		defer s.work.Done()
		s.execute(executionContext, slot, v, ref, payload, clientContext, options.TraceID, value(in.LogType) == "Tail", stream, func(output *invocationOutput, wire *awswire.Error) {
			if stream != nil {
				stream.completed <- executionResponse{output: output, wire: wire}
			} else {
				response <- executionResponse{output: output, wire: wire}
			}
		})
	}()
	select {
	case result := <-response:
		return result.output, result.wire
	case <-ctx.Done():
		return nil, wireError(ctx.Err())
	}
}

// execute owns an admitted slot through the complete runtime-and-extension phase.
// Accepted asynchronous work does not replay or reauthorize the submitting caller.
// Only pending extension work permits an early response. Otherwise publication
// follows metric commit and lease release so sequential callers can reuse it.
func (s *Service) execute(ctx context.Context, slot *execution, v FunctionRecord, ref FunctionReference, payload []byte, clientContext, traceID string, logTail bool, stream *invocationStream, respond func(*invocationOutput, *awswire.Error)) {
	if v.Capacity != nil {
		s.executeManagedAccepted(ctx, slot, v, ref, payload, clientContext, traceID, logTail, stream, respond)
		return
	}
	if v.Durable != nil && !isDurableRuntimeInvocation(ctx) {
		s.executeDurableAccepted(ctx, slot, v, ref, payload, clientContext, traceID, logTail, stream, respond)
		return
	}
	var output *invocationOutput
	var responseError *awswire.Error
	responded := false
	slot.mu.Lock()
	defer func() {
		s.releaseInvocation(v.Key, slot)
		s.releaseExecution(slot)
		slot.mu.Unlock()
		if !responded {
			respond(output, responseError)
		}
	}()
	if v.State != "Active" {
		responseError = failure("ResourceConflictException", "Function is not active: "+v.State, 409)
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer stop()
	defer cancel()
	now := s.clock.Now()
	if slot.environment != nil && (slot.revision != v.DeploymentRevision || !now.Before(slot.expires.Add(-time.Minute)) || slot.provisionedGeneration == "" && (s.keepAlive == 0 || now.Sub(slot.lastUse) >= s.keepAlive)) {
		if err := slot.close(ctx); err != nil {
			responseError = wireError(err)
			return
		}
	}
	if slot.environment == nil {
		environment, expiration, err := s.prepareMode(ctx, v, slot.provisionedGeneration != "")
		if err != nil {
			slot.retire(environment)
			responseError = wireError(err)
			return
		}
		slot.environment = environment
		slot.revision = v.DeploymentRevision
		slot.expires = expiration
		if slot.provisionedGeneration != "" {
			s.mu.Lock()
			slot.provisionedReady, slot.provisionedExpires = true, expiration
			s.mu.Unlock()
		}
	}
	// Customer execution uses wall time. The instance clock timestamps the
	// resulting service facts; it never substitutes for measured duration.
	started := s.clock.Now()
	invocation := runtime.Invocation{
		RequestID: awsctx.FromContext(ctx).RequestID, FunctionARN: ref.ARN(),
		Payload: payload, ClientContext: clientContext, TraceID: recursionTrace(traceID, v.Key, s.clock.Now()),
	}
	if stream != nil {
		invocation.Stream = stream.write
	}
	report, err := slot.environment.Invoke(ctx, invocation, func(result runtime.Result) {
		output = &invocationOutput{InvokeOutput: api.InvokeOutput{StatusCode: new(api.Integer(200)), Payload: api.Blob(result.Payload), ExecutedVersion: new(api.Version(versionName(v.Version)))}, streamed: result.Streaming, runtimeContentType: result.ContentType}
		if result.FunctionError != "" {
			output.FunctionError = new(api.String(result.FunctionError))
		}
		if !logTail && result.ExtensionsPending {
			responded = true
			respond(output, nil)
		}
	})
	slot.lastUse = s.clock.Now()
	if slot.provisionedGeneration != "" && (err != nil || report.Status != runtime.InvocationSuccess) {
		// A reset runtime is not pre-initialized capacity. Replace it through
		// the real Init worker rather than claiming READY until the next call.
		s.mu.Lock()
		slot.provisionedReady, slot.retiring = false, true
		s.provisionedChangedLocked()
		s.mu.Unlock()
	}
	if err != nil {
		cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		closeErr := slot.close(cleanup)
		cleanupCancel()
		if closeErr != nil {
			slog.Error("Lambda backend cleanup failed; retaining execution outcome", "function", v.Key.ARN(), "error", closeErr)
		}
		if output == nil {
			responseError = wireError(err)
			return
		}
	}
	if err := s.repository.Update(context.WithoutCancel(ctx), func(tx Transaction) error {
		return s.stageExecutionMetrics(tx, ref, value(output.ExecutedVersion), started, report)
	}); err != nil {
		// A publication failure cannot rewrite an accepted function response.
		slog.Error("Lambda execution metric commit failed", "function", v.Key.ARN(), "request", awsctx.FromContext(ctx).RequestID, "error", err)
	} else {
		s.jobs.Wake()
	}
	if logTail {
		output.LogResult = new(api.String(base64.StdEncoding.EncodeToString(report.Logs)))
	}
}
