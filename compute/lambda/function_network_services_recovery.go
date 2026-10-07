package lambda

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"stackd/compute/docker"
	"stackd/compute/network"
)

// RetireOrphanServices withdraws only this persistent controller's exact native
// endpoint incarnation after the EC2 owner proves the backing endpoint address
// was deleted. A source route withdrawal does not delete an endpoint shared by
// another function. Existing endpoints stay retained for listener adoption.
func (r *FunctionNetworkRuntime) RetireOrphanServices(ctx context.Context, source network.Specification, observe func(context.Context, string, string) (bool, error)) error {
	r.serviceMu.Lock()
	defer r.serviceMu.Unlock()
	filters, err := json.Marshal(map[string][]string{"label": {functionNetworkOwnerLabel + "=" + r.namespace}})
	if err != nil {
		return err
	}
	var containers []struct {
		ID     string
		Names  []string
		Labels map[string]string
	}
	if err := r.client.JSON(ctx, http.MethodGet, "/containers/json?all=true&filters="+url.QueryEscape(string(filters)), nil, &containers); err != nil {
		return err
	}
	for _, container := range containers {
		owner := container.Labels[functionNetworkLabel]
		key, ok := strings.CutPrefix(owner, "lambda-service-endpoint/")
		if !ok || r.services[key] != nil {
			continue
		}
		endpointID, address := "", ""
		if gateway, ok := strings.CutPrefix(key, "gateway/"); ok {
			if gateway != source.NetworkID {
				continue
			}
		} else {
			remainder, ok := strings.CutPrefix(key, "interface/")
			if !ok {
				continue
			}
			last := strings.LastIndexByte(remainder, '/')
			if last < 0 {
				continue
			}
			address = remainder[last+1:]
			remainder = remainder[:last]
			last = strings.LastIndexByte(remainder, '/')
			if last < 0 || remainder[:last] != source.NetworkID {
				continue
			}
			endpointID = remainder[last+1:]
		}
		identity := fmt.Sprintf("%x", sha256.Sum256([]byte(r.namespace+"\x00"+owner)))
		name := "stackd-lambda-endpoint-" + identity
		matched := false
		for _, candidate := range container.Names {
			if strings.TrimPrefix(candidate, "/") == name {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		alive, err := observe(ctx, endpointID, address)
		if err != nil {
			return err
		}
		if alive {
			continue
		}
		var info struct {
			Config struct {
				Labels map[string]string
				Image  string
			}
		}
		if err := r.client.JSON(ctx, http.MethodGet, "/containers/"+container.ID+"/json", nil, &info); err != nil {
			if sourceNetworkMissing(err) {
				continue
			}
			return err
		}
		if info.Config.Labels[functionNetworkLabel] != owner || info.Config.Labels[functionNetworkOwnerLabel] != r.namespace || info.Config.Image != docker.ToolkitImage {
			return fmt.Errorf("native endpoint retirement owner differs: %s", name)
		}
		if err := r.client.RemoveContainer(ctx, container.ID); err != nil {
			return err
		}
		if err := r.Retire(ctx, owner, source); err != nil {
			return err
		}
	}
	return nil
}
