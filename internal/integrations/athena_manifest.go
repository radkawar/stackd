package integrations

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/url"
	"sort"

	api "stackd/internal/awsapi/s3"
)

// Only the authenticated execution callback can contribute entries. Parts and
// failed writes are not objects; retries collapse to one entry and native
// cleanup removes objects deleted before successful query completion.
type athenaObjectResponse struct {
	http.ResponseWriter
	status  int
	capture bool
	body    bytes.Buffer
}

func (w *athenaObjectResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *athenaObjectResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.capture {
		w.body.Write(body)
	}
	return w.ResponseWriter.Write(body)
}

func (a *athenaDataPlane) retainObjectWrite(input any, response []byte) {
	var bucket *api.BucketName
	var key *api.ObjectKey
	remove := false
	switch in := input.(type) {
	case *api.PutObjectInput:
		bucket, key = in.Bucket, in.Key
	case *api.CompleteMultipartUploadInput:
		bucket, key = in.Bucket, in.Key
	case *api.CopyObjectInput:
		bucket, key = in.Bucket, in.Key
	case *api.DeleteObjectInput:
		bucket, key, remove = in.Bucket, in.Key, true
	case *api.DeleteObjectsInput:
		if in.Bucket == nil || in.Delete == nil {
			return
		}
		var result struct {
			XMLName xml.Name `xml:"DeleteResult"`
			Errors  []struct {
				Key string `xml:"Key"`
			} `xml:"Error"`
		}
		if xml.Unmarshal(response, &result) != nil {
			return
		}
		failed := make(map[string]struct{}, len(result.Errors))
		for _, failure := range result.Errors {
			failed[failure.Key] = struct{}{}
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, object := range in.Delete.Objects {
			if object.Key != nil {
				if _, denied := failed[string(*object.Key)]; !denied {
					delete(a.writes, athenaObjectURI(string(*in.Bucket), string(*object.Key)))
				}
			}
		}
		return
	default:
		return
	}
	if bucket == nil || key == nil {
		return
	}
	location := athenaObjectURI(string(*bucket), string(*key))
	a.mu.Lock()
	defer a.mu.Unlock()
	if remove {
		delete(a.writes, location)
		return
	}
	if a.writes == nil {
		a.writes = make(map[string]struct{})
	}
	a.writes[location] = struct{}{}
}

func athenaObjectURI(bucket, key string) string {
	return (&url.URL{Scheme: "s3", Host: bucket, Path: "/" + key}).String()
}

func (a *athenaDataPlane) manifest() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	locations := make([]string, 0, len(a.writes))
	for location := range a.writes {
		locations = append(locations, location)
	}
	sort.Strings(locations)
	var body bytes.Buffer
	for _, location := range locations {
		body.WriteString(location)
		body.WriteByte('\n')
	}
	// Preserve a supported zero-object write independently of unsupported SQL.
	if len(locations) == 0 {
		return []byte{}
	}
	return body.Bytes()
}
