// Package catalog exposes AWS service-reference metadata for IAM authorization,
// policy simulation and access reports. Metadata itself grants no permissions.
package catalog

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"stackd/internal/iam/catalog/schema"
)

type Service = schema.Service
type Action = schema.Action
type Resource = schema.Resource

//go:embed data/catalog.json.gz
var generated []byte
var load = sync.OnceValues(func() (*Catalog, error) { return decode(generated) })

// Load returns the immutable embedded catalog. No clone or network is needed.
func Load() (*Catalog, error) { return load() }

type actionPosition struct{ service, action int }

// Catalog returns detached records, so callers cannot mutate shared metadata.
type Catalog struct {
	data      []Service
	services  map[string]int
	actions   map[string]actionPosition
	variants  map[string][]actionPosition
	resources map[string]map[string]int
}

func decode(compressed []byte) (*Catalog, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open IAM metadata: %w", err)
	}
	defer reader.Close()
	var services []Service
	if err := json.NewDecoder(reader).Decode(&services); err != nil {
		return nil, fmt.Errorf("decode IAM metadata: %w", err)
	}
	c := &Catalog{data: services, services: make(map[string]int), actions: make(map[string]actionPosition), variants: make(map[string][]actionPosition), resources: make(map[string]map[string]int)}
	for si, service := range services {
		prefix := strings.ToLower(service.Prefix)
		c.services[prefix] = si
		for ai, action := range service.Actions {
			position := actionPosition{si, ai}
			c.actions[action.Name] = position
			name := strings.ToLower(action.Name)
			c.variants[name] = append(c.variants[name], position)
		}
		c.resources[prefix] = make(map[string]int)
		for ri, resource := range service.Resources {
			c.resources[prefix][resource.Name] = ri
		}
	}
	return c, nil
}

func (c *Catalog) ServicePrefixes() []string {
	result := make([]string, 0, len(c.data))
	for _, service := range c.data {
		result = append(result, service.Prefix)
	}
	return result
}

func (c *Catalog) LookupService(prefix string) (Service, bool) {
	i, ok := c.services[strings.ToLower(prefix)]
	if !ok {
		return Service{}, false
	}
	return cloneService(c.data[i]), true
}

// LookupAction prefers the published spelling. Case-insensitive fallback is
// available only when the source defines one unambiguous action.
func (c *Catalog) LookupAction(name string) (Action, bool) {
	p, ok := c.actions[name]
	if !ok {
		variants := c.variants[strings.ToLower(name)]
		if len(variants) != 1 {
			return Action{}, false
		}
		p = variants[0]
	}
	return cloneAction(c.data[p.service].Actions[p.action]), true
}

func (c *Catalog) LookupResource(prefix, name string) (Resource, bool) {
	prefix = strings.ToLower(prefix)
	i, ok := c.resources[prefix][name]
	if !ok {
		return Resource{}, false
	}
	return cloneResource(c.data[c.services[prefix]].Resources[i]), true
}
