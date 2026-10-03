package appconfig

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	api "stackd/internal/awsapi/appconfig"
)

func arn(s Scope, relative string) string {
	return "arn:" + s.Partition + ":appconfig:" + s.Region + ":" + s.AccountID + ":" + relative
}
func appARN(s Scope, id string) string      { return arn(s, "application/"+id) }
func envARN(s Scope, app, id string) string { return appARN(s, app) + "/environment/" + id }
func profileARN(s Scope, app, id string) string {
	return appARN(s, app) + "/configurationprofile/" + id
}
func strategyARN(s Scope, id string) string { return arn(s, "deploymentstrategy/"+id) }
func deploymentARN(s Scope, app, env string, n int32) string {
	return envARN(s, app, env) + "/deployment/" + strconv.FormatInt(int64(n), 10)
}
func findApplication(r Reader, s Scope, id string) (Application, error) {
	rows, err := r.Applications(s)
	if err != nil {
		return Application{}, err
	}
	for _, v := range rows {
		if v.ID == id {
			return v, nil
		}
	}
	for _, v := range rows {
		if v.Name == id {
			return v, nil
		}
	}
	return Application{}, failure("ResourceNotFoundException", "Application not found: "+id)
}
func findEnvironment(r Reader, s Scope, app, id string) (Environment, error) {
	rows, err := r.Environments(s, app)
	if err != nil {
		return Environment{}, err
	}
	for _, v := range rows {
		if v.ID == id {
			return v, nil
		}
	}
	for _, v := range rows {
		if v.Name == id {
			return v, nil
		}
	}
	return Environment{}, failure("ResourceNotFoundException", "Environment not found: "+id)
}
func findProfile(r Reader, s Scope, app, id string) (Profile, error) {
	rows, err := r.Profiles(s, app)
	if err != nil {
		return Profile{}, err
	}
	for _, v := range rows {
		if v.ID == id {
			return v, nil
		}
	}
	for _, v := range rows {
		if v.Name == id {
			return v, nil
		}
	}
	return Profile{}, failure("ResourceNotFoundException", "Configuration profile not found: "+id)
}
func findHostedVersion(r Reader, s Scope, app, profile, version string) (HostedVersion, error) {
	rows, err := r.HostedVersions(s, app, profile)
	if err != nil {
		return HostedVersion{}, err
	}
	n, e := strconv.ParseInt(version, 10, 32)
	for _, v := range rows {
		if (e == nil && v.Number == int32(n)) || (v.VersionLabel != "" && v.VersionLabel == version) {
			return v, nil
		}
	}
	return HostedVersion{}, failure("ResourceNotFoundException", "Hosted configuration version not found: "+version)
}
func findStrategy(r Reader, s Scope, id string) (Strategy, error) {
	rows, err := r.Strategies(s)
	if err != nil {
		return Strategy{}, err
	}
	for _, v := range rows {
		if v.ID == id {
			return v, nil
		}
	}
	for _, v := range builtinStrategies(s) {
		if v.ID == id {
			return v, nil
		}
	}
	return Strategy{}, failure("ResourceNotFoundException", "Deployment strategy not found: "+id)
}

// pageKey follows each list's existing order: newest creation time first,
// then numeric order, then stable resource identity. Event lists use their
// immutable ordinal from the oldest event, not a shifting slice offset.
type pageKey struct {
	CreatedAt time.Time `json:"t,omitzero"`
	Number    int64     `json:"n,omitempty"`
	ID        string    `json:"i,omitempty"`
}

func (k pageKey) compare(other pageKey) int {
	if n := other.CreatedAt.Compare(k.CreatedAt); n != 0 {
		return n
	}
	if n := cmp.Compare(k.Number, other.Number); n != 0 {
		return n
	}
	return cmp.Compare(k.ID, other.ID)
}

func pageBinding(sc Scope, action string, filters ...string) string {
	parts := append([]string{sc.Partition, sc.AccountID, sc.Region, action}, filters...)
	b, _ := json.Marshal(parts)
	digest := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type pageCursor struct {
	Binding string  `json:"b"`
	Last    pageKey `json:"k"`
}

func page[T any](items []T, next *api.NextToken, max *api.MaxResults, binding string, key func(int) pageKey) ([]T, *api.NextToken, error) {
	offset := 0
	if next != nil && *next != "" {
		b, err := base64.RawURLEncoding.DecodeString(string(*next))
		var cursor pageCursor
		if err != nil || json.Unmarshal(b, &cursor) != nil || cursor.Binding != binding {
			return nil, nil, failure("BadRequestException", "Invalid NextToken.")
		}
		for offset < len(items) && key(offset).compare(cursor.Last) <= 0 {
			offset++
		}
	}
	size := 50
	if max != nil {
		size = int(*max)
	}
	if size < 1 || size > 50 {
		return nil, nil, failure("BadRequestException", "MaxResults must be between 1 and 50.")
	}
	end := min(offset+size, len(items))
	out := items[offset:end]
	if end == len(items) {
		return out, nil, nil
	}
	b, _ := json.Marshal(pageCursor{Binding: binding, Last: key(end - 1)})
	token := api.NextToken(base64.RawURLEncoding.EncodeToString(b))
	return out, &token, nil
}
