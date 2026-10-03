package s3

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/gateway"
)

type requestObservationKey struct{}

// One observation spans the public response, including gateway rejections and
// nested browser handlers. Neither request nor response bodies are retained.
type requestObservation struct {
	request                            *http.Request
	writer                             *requestWriter
	at, started                        time.Time
	received, firstByte                time.Time
	bucketName, key, action, operation string
	accessPointARN                     string
	command, captured                  bool
	bucket                             BucketRecord
	config                             *LoggingConfiguration
	call                               *apiCall
	objectSize                         int64
	captureErr                         error
	bytesRead                          int64
	metrics                            *requestMetricsObservation
}

func observedRequestQuery(ctx context.Context) url.Values {
	if observation, ok := ctx.Value(requestObservationKey{}).(*requestObservation); ok {
		return observation.request.URL.Query()
	}
	return nil
}

// ObserveHTTP returns the source-owned response observer and a completion hook.
// The outermost hook publishes; nested hooks only retain final request metadata.
func (s *Service) ObserveHTTP(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request, func(*http.Request)) {
	if observation, ok := r.Context().Value(requestObservationKey{}).(*requestObservation); ok {
		observation.rememberRequest(r)
		return w, r, observation.rememberRequest
	}
	observation := &requestObservation{request: r, at: s.clock.Now(), started: time.Now(), objectSize: -1}
	if r.Body == nil || r.Body == http.NoBody {
		observation.received = observation.started
	} else {
		r.Body = &requestBodyObserver{ReadCloser: r.Body, observation: observation}
	}
	observation.bucketName, observation.key, observation.action, observation.operation = requestTarget(r)
	writer := &requestWriter{ResponseWriter: w, observation: observation}
	observation.writer = writer
	r = r.WithContext(context.WithValue(r.Context(), requestObservationKey{}, observation))
	observation.request = r
	return writer, r, func(final *http.Request) {
		observation.rememberRequest(final)
		elapsed := time.Since(observation.started)
		request := observation.request
		ctx, cancel := apievents.CompletionContext(request.Context())
		defer cancel()
		if !observation.captured && !observation.command && observation.bucketName != "" {
			m := awsctx.FromContext(ctx)
			partition := m.Partition
			if partition != "" {
				err := s.repository.View(ctx, func(reader Reader) error {
					bucket, point, err := resolveBucketReference(reader, observation.bucketName)
					if err != nil {
						if wireError(err).StatusCode < 500 {
							return nil
						}
						return err
					}
					s.captureRequest(reader, bucket, point)
					return nil
				})
				if err != nil {
					slog.Warn("S3 request accounting source lookup failed", "bucket", observation.bucketName, "error", err)
				}
			}
		}
		if observation.captureErr != nil {
			slog.Warn("S3 request accounting configuration lookup failed", "bucket", observation.bucketName, "error", observation.captureErr)
		}
		if err := s.publishHTTPMetrics(ctx, observation, elapsed); err != nil {
			slog.Warn("S3 request metric publication failed", "bucket", observation.bucketName, "request_id", awsctx.FromContext(ctx).RequestID, "error", err)
		}
		if observation.config == nil {
			return
		}
		delivery := AccessLogDelivery{
			Source: observation.bucket.Key, AccountID: observation.bucket.AccountID, Region: observation.bucket.Region,
			Destination: *observation.config, Record: formatAccessLog(observation, elapsed), At: observation.at,
		}
		if err := s.enqueueAccessLog(ctx, delivery); err != nil {
			slog.Warn("S3 access log enqueue failed", "bucket", observation.bucketName, "request_id", awsctx.FromContext(ctx).RequestID, "error", err)
		}
	}
}

func (o *requestObservation) rememberRequest(r *http.Request) {
	previous, next := awsctx.FromContext(o.request.Context()), awsctx.FromContext(r.Context())
	// An outer gateway still holds its pre-authentication request when a nested
	// dispatch has already supplied the verified identity or website context.
	if previous.SignatureVersion != "" && next.SignatureVersion == "" || previous.TransportKnown && !next.TransportKnown || websiteRequest(o.request) && !websiteRequest(r) {
		return
	}
	o.request = r
}

// captureRequest observes configurations before mutation, from the same
// Reader snapshot that admitted the source bucket. Copy-source bucket lookups
// must not replace the destination's public HTTP observation.
func (s *Service) captureRequest(reader Reader, bucket BucketRecord, point *AccessPointRecord) {
	o, ok := reader.Context().Value(requestObservationKey{}).(*requestObservation)
	if !ok || o.captured {
		return
	}
	var pointARN string
	if point != nil {
		pointARN = point.Key.ARN()
		if o.bucketName != point.Alias && o.bucketName != pointARN {
			return
		}
	} else if bucket.Key.Name != o.bucketName {
		return
	}
	o.captured, o.bucket, o.accessPointARN = true, bucket, pointARN
	var loggingErr, metricsErr error
	o.config, loggingErr = reader.BucketLogging(bucket.Key)
	o.metrics, metricsErr = s.captureRequestMetrics(reader, bucket, o.action, o.key, o.request.URL.Query().Get("versionId"), pointARN, false, o.at)
	o.captureErr = errors.Join(loggingErr, metricsErr)
}

// A semantic command that found no source bucket must not discover a different
// bucket through a post-command fallback read (notably CreateBucket).
func noteRequestCommand(ctx context.Context) {
	if o, ok := ctx.Value(requestObservationKey{}).(*requestObservation); ok {
		o.command = true
	}
}

func noteAccessLogObject(ctx context.Context, size int64) {
	if o, ok := ctx.Value(requestObservationKey{}).(*requestObservation); ok {
		o.objectSize = size
	}
}

func requestTarget(r *http.Request) (bucket, key, action, operation string) {
	if websiteRequest(r) {
		bucket, _, _, _ = websiteEndpoint(r.Host)
		key = strings.TrimPrefix(r.URL.Path, "/")
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			operation = "WEBSITE." + r.Method + ".OBJECT"
			action = "GetObject"
			if r.Method == http.MethodHead {
				action = "HeadObject"
			}
		}
		return
	}
	path := gateway.S3RequestPath(r)
	rawBucket, rawKey, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	var err error
	bucket, err = url.PathUnescape(rawBucket)
	if err != nil {
		return "", "", "", ""
	}
	key, err = url.PathUnescape(rawKey)
	if err != nil {
		return bucket, "", "", ""
	}
	if r.Method == http.MethodOptions {
		return bucket, key, "", "REST.OPTIONS.PREFLIGHT"
	}
	model, _ := awscatalog.LookupService("s3")
	if matched, _, ok := model.MatchHTTPOperation(r.Method, path, r.URL.Query(), r.Header); ok {
		action = string(matched.Name)
		operation = accessLogOperation(action)
	}
	return
}

type requestBodyObserver struct {
	io.ReadCloser
	observation *requestObservation
}

func (b *requestBodyObserver) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.observation.bytesRead += int64(n)
	if err == io.EOF {
		b.observation.received = time.Now()
	}
	return n, err
}

type requestWriter struct {
	http.ResponseWriter
	observation                  *requestObservation
	status                       int
	bytes                        int64
	errorCode, requestID, hostID string
}

func (w *requestWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Error writers report source error codes before committing headers. This also
// covers HEAD failures and S3's HTTP-200 embedded errors without parsing bodies.
func (w *requestWriter) ObserveS3Error(code string) { w.errorCode = code }

func (w *requestWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.status = status
	w.observation.firstByte = time.Now()
	w.requestID, w.hostID = w.Header().Get("x-amz-request-id"), w.Header().Get("x-amz-id-2")
	w.ResponseWriter.WriteHeader(status)
}

func (w *requestWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	if w.observation.request.Method != http.MethodHead && w.status != http.StatusNoContent && w.status != http.StatusNotModified && w.status >= 200 {
		w.bytes += int64(n)
	}
	return n, err
}

func (w *requestWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *requestWriter) Flush() { _ = w.FlushError() }
