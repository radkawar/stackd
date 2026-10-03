package ecr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ecr"
	"strconv"
	"strings"
)

func registryPath(k RepositoryKey) string {
	return "/v2/" + k.Partition + "/" + k.AccountID + "/" + k.Region + "/" + k.Name
}
func (s *Service) RegistryHandler() http.Handler { return http.HandlerFunc(s.serveRegistry) }

// IsRegistryRequest leaves unrelated AWS REST APIs, including API Gateway's
// /v2/apis routes, with the AWS gateway.
func IsRegistryRequest(r *http.Request) bool {
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		return true
	}
	_, err := parseRegistryRoute(r.URL.Path)
	return err == nil
}

type registryRoute struct {
	key             RepositoryKey
	kind, reference string
}

func parseRegistryRoute(p string) (registryRoute, error) {
	var out registryRoute
	if !strings.HasPrefix(p, "/v2/") {
		return out, failure("InvalidParameterException", "Invalid registry route.")
	}
	rest := strings.TrimPrefix(p, "/v2/")
	scope := strings.SplitN(rest, "/", 4)
	if len(scope) != 4 || scope[0] == "" || len(scope[1]) != 12 || scope[2] == "" {
		return out, failure("InvalidParameterException", "Registry names must include partition, account and region.")
	}
	for _, c := range scope[1] {
		if c < '0' || c > '9' {
			return out, failure("InvalidParameterException", "Invalid account scope.")
		}
	}
	out.key.Scope = Scope{scope[0], scope[1], scope[2]}
	resource := scope[3]
	// Repository components may themselves be named blobs, uploads or
	// manifests. Only the terminal operation and reference delimit the name.
	i := strings.LastIndexByte(resource, '/')
	if i < 0 {
		return out, failure("InvalidParameterException", "Unsupported registry route.")
	}
	prefix := resource[:i]
	out.reference = resource[i+1:]
	switch {
	case strings.HasSuffix(prefix, "/tags") && out.reference == "list":
		out.key.Name = strings.TrimSuffix(prefix, "/tags")
		out.kind = "tags"
		out.reference = ""
	case strings.HasSuffix(prefix, "/blobs/uploads"):
		out.key.Name = strings.TrimSuffix(prefix, "/blobs/uploads")
		out.kind = "uploads"
	case strings.HasSuffix(prefix, "/manifests"):
		out.key.Name = strings.TrimSuffix(prefix, "/manifests")
		out.kind = "manifests"
	case strings.HasSuffix(prefix, "/blobs"):
		out.key.Name = strings.TrimSuffix(prefix, "/blobs")
		out.kind = "blobs"
	default:
		return out, failure("InvalidParameterException", "Unsupported registry route.")
	}
	if !repositoryName.MatchString(out.key.Name) || strings.Contains(out.reference, "/") {
		return out, failure("InvalidParameterException", "Invalid repository name or content reference.")
	}
	return out, nil
}
func (s *Service) serveRegistry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		if _, err := s.registryIdentity(r, RepositoryKey{}, ""); err != nil {
			registryError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{}"))
		return
	}
	route, err := parseRegistryRoute(r.URL.Path)
	if err != nil {
		registryError(w, err)
		return
	}
	ctx, err := s.registryIdentity(r, route.key, route.reference)
	if err != nil {
		registryError(w, err)
		return
	}
	r = r.WithContext(ctx)
	switch route.kind {
	case "manifests":
		s.registryManifest(w, r, route)
	case "blobs":
		s.registryBlob(w, r, route)
	case "uploads":
		s.registryUpload(w, r, route)
	case "tags":
		s.registryTags(w, r, route)
	}
}
func registryError(w http.ResponseWriter, err error) {
	e := wireError(err)
	status := e.StatusCode
	code := "UNKNOWN"
	switch e.Code {
	case "RegistryAuthenticationException":
		status = 401
		code = "UNAUTHORIZED"
		w.Header().Set("WWW-Authenticate", `Basic realm="Amazon ECR"`)
	case "AccessDeniedException":
		status = 403
		code = "DENIED"
	case "RepositoryNotFoundException":
		status = 404
		code = "NAME_UNKNOWN"
	case "ImageNotFoundException":
		status = 404
		code = "MANIFEST_UNKNOWN"
	case "LayersNotFoundException":
		status = 404
		code = "BLOB_UNKNOWN"
	case "UploadNotFoundException":
		status = 404
		code = "BLOB_UPLOAD_UNKNOWN"
	case "InvalidLayerPartException":
		status = 416
		code = "RANGE_INVALID"
	case "InvalidLayerException", "InvalidDigestException", "ImageDigestDoesNotMatchException":
		status = 400
		code = "DIGEST_INVALID"
	case "ImageTagAlreadyExistsException":
		status = 400
		code = "TAG_INVALID"
	case "InvalidParameterException":
		status = 400
		code = "MANIFEST_INVALID"
	case "UnsupportedOperationException":
		status = 405
		code = "UNSUPPORTED"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]string{"code": code, "message": e.Message}}})
}
func imageID(reference string) api.ImageIdentifier {
	if strings.Contains(reference, ":") {
		return api.ImageIdentifier{ImageDigest: new(api.ImageDigest(reference))}
	}
	return api.ImageIdentifier{ImageTag: new(api.ImageTag(reference))}
}
func (s *Service) registryManifest(w http.ResponseWriter, r *http.Request, route registryRoute) {
	key := route.key
	id := imageID(route.reference)
	switch r.Method {
	case "GET", "HEAD":
		out, err := runCommand(s, r.Context(), "BatchGetImage", &api.BatchGetImageInput{RegistryId: new(api.RegistryId(key.AccountID)), RepositoryName: new(api.RepositoryName(key.Name)), ImageIds: api.ImageIdentifierList{id}}, s.batchGetImage)
		if err != nil {
			registryError(w, err)
			return
		}
		if len(out.Images) == 0 {
			registryError(w, failure("ImageNotFoundException", "The manifest is unavailable."))
			return
		}
		image := out.Images[0]
		manifest := value(image.ImageManifest)
		w.Header().Set("Content-Type", value(image.ImageManifestMediaType))
		w.Header().Set("Docker-Content-Digest", value(image.ImageId.ImageDigest))
		w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		w.WriteHeader(200)
		if r.Method == "GET" {
			_, _ = io.WriteString(w, manifest)
		}
	case "PUT":
		data, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
		if err != nil {
			registryError(w, err)
			return
		}
		in := &api.PutImageInput{RegistryId: new(api.RegistryId(key.AccountID)), RepositoryName: new(api.RepositoryName(key.Name)), ImageManifest: new(api.ImageManifest(data)), ImageManifestMediaType: new(api.MediaType(strings.Split(r.Header.Get("Content-Type"), ";")[0])), ImageTag: id.ImageTag, ImageDigest: id.ImageDigest}
		out, rejected := runCommand(s, r.Context(), "PutImage", in, s.putImage)
		if rejected != nil && rejected.Code != "ImageAlreadyExistsException" {
			registryError(w, rejected)
			return
		}
		digest := digestBytes(data)
		if out != nil {
			digest = value(out.Image.ImageId.ImageDigest)
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", registryPath(key)+"/manifests/"+digest)
		w.WriteHeader(201)
	case "DELETE":
		out, err := runCommand(s, r.Context(), "BatchDeleteImage", &api.BatchDeleteImageInput{RegistryId: new(api.RegistryId(key.AccountID)), RepositoryName: new(api.RepositoryName(key.Name)), ImageIds: api.ImageIdentifierList{id}}, s.batchDeleteImage)
		if err != nil {
			registryError(w, err)
			return
		}
		if len(out.Failures) > 0 {
			registryError(w, failure("ImageNotFoundException", value(out.Failures[0].FailureReason)))
			return
		}
		w.WriteHeader(202)
	default:
		registryError(w, failure("UnsupportedOperationException", "Unsupported manifest method."))
	}
}
func (s *Service) registryBlob(w http.ResponseWriter, r *http.Request, route registryRoute) {
	if r.Method != "GET" && r.Method != "HEAD" {
		registryError(w, failure("UnsupportedOperationException", "Unsupported blob method."))
		return
	}
	if !digestPattern.MatchString(route.reference) {
		registryError(w, failure("InvalidDigestException", "Invalid blob digest."))
		return
	}
	var payload []byte
	action := "GetDownloadUrlForLayer"
	if r.Method == "HEAD" {
		action = "BatchCheckLayerAvailability"
	}
	ctx, err := apievents.Reserve(r.Context())
	if err != nil {
		registryError(w, err)
		return
	}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		repo, err := s.resolveRepository(tx, new(api.RegistryId(route.key.AccountID)), new(api.RepositoryName(route.key.Name)), action)
		if err != nil {
			return err
		}
		blob, err := tx.Blob(ImageKey{repo.Key, route.reference})
		if errors.Is(err, ErrNotFound) {
			return failure("LayersNotFoundException", "The layer does not exist.")
		}
		if err != nil {
			return err
		}
		payload, err = s.openPayload(tx.Context(), repo, "blob:"+route.reference, blob.Payload)
		if err != nil {
			return err
		}
		if action == "BatchCheckLayerAvailability" {
			return s.recordCall(tx.Context(), action, &api.BatchCheckLayerAvailabilityInput{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: new(api.RepositoryName(repo.Key.Name)), LayerDigests: api.BatchedOperationLayerDigestList{api.BatchedOperationLayerDigest(route.reference)}}, nil, nil)
		}
		return s.recordCall(tx.Context(), action, &api.GetDownloadUrlForLayerInput{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: new(api.RepositoryName(repo.Key.Name)), LayerDigest: new(api.LayerDigest(route.reference))}, nil, nil)
	})
	if err != nil {
		registryError(w, err)
		return
	}
	w.Header().Set("Docker-Content-Digest", route.reference)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, route.reference, s.clock.Now(), bytes.NewReader(payload))
}
func uploadHeaders(w http.ResponseWriter, u UploadRecord) {
	w.Header().Set("Location", registryPath(u.Key.Repository)+"/blobs/uploads/"+u.Key.ID)
	w.Header().Set("Docker-Upload-UUID", u.Key.ID)
	end := u.Size - 1
	if end < 0 {
		end = 0
	}
	w.Header().Set("Range", fmt.Sprintf("0-%d", end))
	w.Header().Set("Content-Length", "0")
}
func (s *Service) registryUpload(w http.ResponseWriter, r *http.Request, route registryRoute) {
	key := route.key
	if r.Method == "POST" && route.reference == "" {
		out, err := runCommand(s, r.Context(), "InitiateLayerUpload", &api.InitiateLayerUploadInput{RegistryId: new(api.RegistryId(key.AccountID)), RepositoryName: new(api.RepositoryName(key.Name))}, s.initiateLayerUpload)
		if err != nil {
			registryError(w, err)
			return
		}
		u := UploadRecord{Key: UploadKey{key, value(out.UploadId)}}
		uploadHeaders(w, u)
		w.WriteHeader(202)
		return
	}
	if route.reference == "" {
		registryError(w, failure("UploadNotFoundException", "An upload ID is required."))
		return
	}
	if r.Method != "GET" && r.Method != "PATCH" && r.Method != "PUT" && r.Method != "DELETE" {
		registryError(w, failure("UnsupportedOperationException", "Unsupported upload method."))
		return
	}
	var data []byte
	var err error
	if r.Method == "PATCH" || r.Method == "PUT" {
		data, err = io.ReadAll(io.LimitReader(r.Body, maxLayerSize+1))
		if err != nil {
			registryError(w, err)
			return
		}
		if int64(len(data)) > maxLayerSize {
			registryError(w, failure("LimitExceededException", "Layer is too large."))
			return
		}
	}
	var upload UploadRecord
	var blob BlobRecord
	action := "UploadLayerPart"
	if r.Method == "PUT" {
		action = "CompleteLayerUpload"
	}
	ctx, err := apievents.Reserve(r.Context())
	if err != nil {
		registryError(w, err)
		return
	}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		repo, err := s.resolveRepository(tx, new(api.RegistryId(key.AccountID)), new(api.RepositoryName(key.Name)), action)
		if err != nil {
			return err
		}
		upload, err = s.upload(tx, repo, route.reference)
		if err != nil {
			return err
		}
		if r.Method == "DELETE" {
			return tx.DeleteUpload(upload.Key)
		}
		if len(data) > 0 {
			if r.Method == "PUT" {
				if err = s.authorize(tx, "UploadLayerPart", repo, nil); err != nil {
					return err
				}
			}
			first, last := upload.Size, upload.Size+int64(len(data))-1
			if cr := r.Header.Get("Content-Range"); cr != "" {
				if _, err = fmt.Sscanf(cr, "%d-%d", &first, &last); err != nil {
					return failure("InvalidLayerPartException", "Invalid Content-Range.")
				}
			}
			upload, err = s.appendUpload(tx, repo, upload, data, first, last)
			if err != nil {
				return err
			}
		}
		if r.Method == "PUT" {
			blob, err = s.finishUpload(tx, repo, upload, r.URL.Query().Get("digest"))
			if e := wireError(err); e != nil && e.Code == "LayerAlreadyExistsException" {
				err = tx.DeleteUpload(upload.Key)
			}
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, &api.CompleteLayerUploadInput{RegistryId: new(api.RegistryId(key.AccountID)), RepositoryName: new(api.RepositoryName(key.Name)), UploadId: new(api.UploadId(route.reference)), LayerDigests: api.LayerDigestList{api.LayerDigest(blob.Key.Digest)}}, nil, nil)
		}
		if r.Method == "PATCH" {
			return s.recordCall(tx.Context(), action, &api.UploadLayerPartInput{RegistryId: new(api.RegistryId(key.AccountID)), RepositoryName: new(api.RepositoryName(key.Name)), UploadId: new(api.UploadId(route.reference)), PartFirstByte: new(api.PartSize(upload.Size - int64(len(data)))), PartLastByte: new(api.PartSize(upload.Size - 1))}, nil, nil)
		}
		return nil
	})
	if err != nil {
		registryError(w, err)
		return
	}
	switch r.Method {
	case "PUT":
		w.Header().Set("Docker-Content-Digest", blob.Key.Digest)
		w.Header().Set("Location", registryPath(key)+"/blobs/"+blob.Key.Digest)
		w.WriteHeader(201)
	case "DELETE":
		w.WriteHeader(204)
	case "GET":
		uploadHeaders(w, upload)
		w.WriteHeader(204)
	default:
		uploadHeaders(w, upload)
		w.WriteHeader(202)
	}
}
func (s *Service) registryTags(w http.ResponseWriter, r *http.Request, route registryRoute) {
	if r.Method != "GET" {
		registryError(w, failure("UnsupportedOperationException", "Unsupported tags method."))
		return
	}
	var tags []string
	err := s.repository.View(r.Context(), func(tx Reader) error {
		repo, err := tx.Repository(route.key)
		if err != nil {
			return err
		}
		if err = s.authorize(tx, "ListImages", repo, nil); err != nil {
			return err
		}
		rows, err := tx.Images(repo.Key)
		if err != nil {
			return err
		}
		for _, v := range rows {
			tags = append(tags, v.Tags...)
		}
		return nil
	})
	if err != nil {
		registryError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"name": route.key.Partition + "/" + route.key.AccountID + "/" + route.key.Region + "/" + route.key.Name, "tags": tags})
}
