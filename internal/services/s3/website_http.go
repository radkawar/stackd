package s3

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"stackd/iam/policy"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
)

type websiteContextKey struct{}

func websiteRequest(r *http.Request) bool {
	present, _ := r.Context().Value(websiteContextKey{}).(bool)
	return present
}

// ServeWebsite is a separate anonymous HTTP surface, never a REST authentication
// shortcut. Object selection, resource authority and encrypted bytes remain S3's.
func (s *Service) ServeWebsite(w http.ResponseWriter, r *http.Request) bool {
	bucket, region, partition, ok := websiteEndpoint(r.Host)
	if !ok {
		return false
	}
	metadata := awsctx.Metadata{RequestID: uuid.NewString(), AccountID: policy.AnonymousAccountID, Region: region, Partition: partition}
	gateway.BindRequestTransport(r, &metadata)
	ctx := awsctx.WithMetadata(r.Context(), metadata)
	ctx = context.WithValue(ctx, websiteContextKey{}, true)
	r = r.WithContext(ctx)
	var finish func(*http.Request)
	w, r, finish = s.ObserveHTTP(w, r)
	defer func() { finish(r) }()
	ctx = r.Context()
	w.Header().Set("Server", "AmazonS3")
	w.Header().Set("x-amz-request-id", metadata.RequestID)
	w.Header().Set("x-amz-id-2", awswire.S3HostID(metadata.RequestID))
	if s.ServeCORS(w, r, bucket) {
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		wire := failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
		wire.Method, wire.ResourceType = r.Method, "OBJECT"
		writeWebsiteError(w, r, wire, "", nil, "")
		return true
	}
	var config *WebsiteConfiguration
	err := s.repository.View(ctx, func(reader Reader) error {
		b, err := s.bucket(reader, call(ctx, "GetObject", bucket, ""), "")
		if err != nil {
			return err
		}
		config, err = reader.BucketWebsite(b.Key)
		if err != nil {
			return err
		}
		if config == nil {
			return noWebsite(bucket)
		}
		return nil
	})
	if err != nil {
		writeWebsiteError(w, r, wireError(err), "", nil, "")
		return true
	}
	if d := config.RedirectAll; d != nil {
		protocol := "http"
		if d.Protocol != nil {
			protocol = *d.Protocol
		}
		websiteRedirect(w, protocol+"://"+d.HostName+websiteRawTarget(r), 301)
		return true
	}
	rawKey := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	key := strings.TrimPrefix(r.URL.Path, "/")
	selected := key
	if key == "" || strings.HasSuffix(key, "/") {
		selected += *config.IndexSuffix
	}
	read, wire := s.websiteRead(r, bucket, selected, true)
	// A non-slash exact object wins. A missing exact object can resolve an
	// existing nested index, but first redirect to its canonical slash URL.
	slash := false
	if wire != nil && (wire.StatusCode == 403 || wire.StatusCode == 404) && key != "" && !strings.HasSuffix(key, "/") {
		missing := false
		err := s.repository.View(ctx, func(reader Reader) error {
			object, err := selectObjectVersion(reader, ObjectKey{BucketKey{partition, bucket}, key}, nil)
			missing = errors.Is(err, ErrNotFound) || err == nil && object.DeleteMarker
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		})
		if err != nil {
			wire = wireError(err)
		} else if missing {
			index, indexWire := s.websiteRead(r, bucket, key+"/"+*config.IndexSuffix, false)
			if indexWire == nil {
				read, wire, slash = index, nil, true
			}
		}
	}
	status := 200
	if wire != nil {
		status = wire.StatusCode
	}
	if location, code, matched := websiteRouting(r, config, rawKey, status); matched {
		websiteRedirect(w, location, code)
		return true
	}
	if slash {
		// Native decodes space and plus here, while keeping percent escaped.
		w.Header().Set("Location", "/"+strings.ReplaceAll(key, "%", "%25")+"/")
		writeWebsiteError(w, r, failure("Found", "Resource Found", 302), "", nil, "")
		return true
	}
	if wire == nil && read.object.WebsiteRedirectLocation != "" {
		websiteRedirect(w, read.object.WebsiteRedirectLocation, 301)
		return true
	}
	if wire != nil {
		if wire.StatusCode == 304 {
			w.WriteHeader(304)
			return true
		}
		s.serveWebsiteError(w, r, bucket, selected, config, wire)
		return true
	}
	if wire = s.writeWebsiteObject(w, r, read, 0); wire != nil {
		s.serveWebsiteError(w, r, bucket, selected, config, wire)
	}
	return true
}

func websiteEndpoint(host string) (bucket, region, partition string, ok bool) {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	bucket, endpoint, found := strings.Cut(host, ".s3-website")
	if !found || bucket == "" || len(endpoint) < 2 || endpoint[0] != '.' && endpoint[0] != '-' {
		return "", "", "", false
	}
	endpoint = endpoint[1:]
	for _, suffix := range []string{".amazonaws.com.cn", ".amazonaws.com", ".localhost"} {
		if strings.HasSuffix(endpoint, suffix) {
			region = strings.TrimSuffix(endpoint, suffix)
			partition = awscatalog.RegionPartition(region)
			return bucket, region, partition, partition != ""
		}
	}
	return "", "", "", false
}

func websiteRawTarget(r *http.Request) string {
	target := r.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		target += "?" + r.URL.RawQuery
	}
	return target
}

func websiteRouting(r *http.Request, config *WebsiteConfiguration, key string, status int) (string, int, bool) {
	for _, rule := range config.Rules {
		prefix := ""
		if c := rule.Condition; c != nil {
			if c.KeyPrefix != nil {
				prefix = *c.KeyPrefix
				if !strings.HasPrefix(key, prefix) {
					continue
				}
			}
			if c.ErrorCode != nil {
				code, _ := strconv.Atoi(*c.ErrorCode)
				if status != code {
					continue
				}
			}
		}
		d := rule.Redirect
		host, protocol, target, code := r.Host, "http", key, 301
		if d.HostName != nil {
			host = *d.HostName
		}
		if d.Protocol != nil {
			protocol = *d.Protocol
		}
		if d.StatusCode != nil {
			code, _ = strconv.Atoi(*d.StatusCode)
		}
		if d.ReplaceKey != nil {
			target = *d.ReplaceKey
		} else {
			if d.ReplaceKeyPrefix != nil {
				target = *d.ReplaceKeyPrefix + strings.TrimPrefix(key, prefix)
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery {
				target += "?" + r.URL.RawQuery
			}
		}
		return protocol + "://" + host + "/" + target, code, true
	}
	return "", 0, false
}

func websiteRedirect(w http.ResponseWriter, location string, status int) {
	w.Header().Set("Location", location)
	if status != http.StatusNotModified {
		w.Header().Set("Content-Length", "0")
	}
	w.WriteHeader(status)
}

type websiteObject struct {
	objectRead
	encrypted [][]byte
}

// TODO: Comeback capture native website data events without fabricating REST
// GetObject calls for internal index/error selections.
func (s *Service) websiteRead(r *http.Request, bucket, key string, conditions bool) (websiteObject, *awswire.Error) {
	in := &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key))}
	if conditions {
		if v := r.Header.Get("Range"); v != "" {
			in.Range = new(api.Range(v))
		}
		if v := r.Header.Get("If-Match"); v != "" {
			in.IfMatch = new(api.IfMatch(v))
		}
		if v := r.Header.Get("If-None-Match"); v != "" {
			in.IfNoneMatch = new(api.IfNoneMatch(v))
		}
		if v, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil {
			in.IfModifiedSince = &v
		}
		if v, err := http.ParseTime(r.Header.Get("If-Unmodified-Since")); err == nil {
			in.IfUnmodifiedSince = &v
		}
	}
	var read websiteObject
	operation := "GetObject"
	if r.Method == http.MethodHead {
		operation = "HeadObject"
	}
	err := s.repository.View(r.Context(), func(reader Reader) error {
		var err error
		read.objectRead, err = s.selectObjectRead(reader, call(r.Context(), operation, bucket, key), in, true)
		if err == nil && r.Method != http.MethodHead {
			read.encrypted, err = reader.ObjectData(read.object.VersionKey())
		}
		return err
	})
	return read, wireError(err)
}

func (s *Service) writeWebsiteObject(w http.ResponseWriter, r *http.Request, read websiteObject, status int) *awswire.Error {
	var body []byte
	if r.Method != http.MethodHead {
		var err error
		key, wire := s.objectDataKey(r.Context(), read.bucket, read.object, nil)
		if wire != nil {
			return wire
		}
		defer clear(key)
		body, err = decryptObject(key, read.encrypted)
		if err != nil {
			return wireError(err)
		}
		if int64(len(body)) != read.object.Size {
			return wireError(errors.New("object size does not match encrypted payload"))
		}
		if read.object.Tiering != nil {
			if err := s.repository.Update(r.Context(), func(tx Transaction) error {
				state := ObjectTiering{Accessed: s.clock.Now().UTC()}
				return tx.SetObjectTiering(read.object.VersionKey(), read.object.CreatedOrder, &state)
			}); err != nil {
				return wireError(err)
			}
		}
		body = body[read.start:read.end]
	}
	record := read.object
	for _, header := range [...]struct{ name, value string }{
		{"Content-Type", record.ContentType},
		{"Cache-Control", record.CacheControl},
		{"Content-Disposition", record.ContentDisposition},
		{"Content-Encoding", record.ContentEncoding},
		{"Content-Language", record.ContentLanguage},
		{"ETag", record.ETag},
	} {
		if header.value != "" {
			w.Header().Set(header.name, header.value)
		}
	}
	w.Header().Set("Last-Modified", record.Modified.UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Length", strconv.FormatInt(read.end-read.start, 10))
	if record.Expires != nil {
		w.Header().Set("Expires", record.Expires.UTC().Format(http.TimeFormat))
	}
	if status == 0 {
		status = 200
		if read.contentRange {
			status = 206
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", read.start, read.end-1, record.Size))
		}
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return nil
}

func (s *Service) serveWebsiteError(w http.ResponseWriter, r *http.Request, bucket, key string, config *WebsiteConfiguration, wire *awswire.Error) {
	var secondary *awswire.Error
	secondaryKey := ""
	if config.ErrorKey != nil && wire.StatusCode >= 400 {
		// Native HEAD errors do not resolve or expose the custom error document.
		if r.Method == http.MethodHead {
			websiteErrorHeaders(w.Header(), wire, key)
			w.WriteHeader(wire.StatusCode)
			return
		}
		secondaryKey = *config.ErrorKey
		read, rejected := s.websiteRead(r, bucket, secondaryKey, false)
		secondary = rejected
		if rejected == nil {
			websiteErrorHeaders(w.Header(), wire, key)
			secondary = s.writeWebsiteObject(w, r, read, wire.StatusCode)
			if secondary == nil {
				return
			}
		}
	}
	writeWebsiteError(w, r, wire, key, secondary, secondaryKey)
}

func websiteErrorHeaders(h http.Header, wire *awswire.Error, key string) {
	h.Set("x-amz-error-code", wire.Code)
	h.Set("x-amz-error-message", wire.Message)
	if wire.Code == "NoSuchKey" {
		h.Set("x-amz-error-detail-Key", key)
	}
}

func writeWebsiteError(w http.ResponseWriter, r *http.Request, wire *awswire.Error, key string, secondary *awswire.Error, secondaryKey string) {
	if observer, ok := w.(interface{ ObserveS3Error(string) }); ok {
		observer.ObserveS3Error(wire.Code)
	}
	if wire.Code == "Found" {
		websiteErrorHeaders(w.Header(), wire, key)
	}
	if r.Method == http.MethodHead {
		websiteErrorHeaders(w.Header(), wire, key)
		w.WriteHeader(wire.StatusCode)
		return
	}
	title := strconv.Itoa(wire.StatusCode) + " " + http.StatusText(wire.StatusCode)
	var body strings.Builder
	fmt.Fprintf(&body, "<html>\n<head><title>%s</title></head>\n<body>\n<h1>%s</h1>\n<ul>\n", html.EscapeString(title), html.EscapeString(title))
	field := func(name, value string) { fmt.Fprintf(&body, "<li>%s: %s</li>\n", name, html.EscapeString(value)) }
	field("Code", wire.Code)
	field("Message", wire.Message)
	if wire.Code == "NoSuchKey" {
		field("Key", key)
	}
	if wire.BucketName != "" {
		field("BucketName", wire.BucketName)
	}
	if wire.Method != "" {
		field("Method", wire.Method)
	}
	if wire.ResourceType != "" {
		field("ResourceType", wire.ResourceType)
	}
	field("RequestId", awsctx.FromContext(r.Context()).RequestID)
	field("HostId", awswire.S3HostID(awsctx.FromContext(r.Context()).RequestID))
	body.WriteString("</ul>\n")
	if secondary != nil {
		body.WriteString("<h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>\n<ul>\n")
		field("Code", secondary.Code)
		field("Message", secondary.Message)
		if secondary.Code == "NoSuchKey" {
			field("Key", secondaryKey)
		}
		body.WriteString("</ul>\n")
	}
	body.WriteString("<hr/>\n</body>\n</html>\n")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(wire.StatusCode)
	_, _ = fmt.Fprint(w, body.String())
}
