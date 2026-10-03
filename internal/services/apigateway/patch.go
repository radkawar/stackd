package apigateway

import (
	"slices"
	api "stackd/internal/awsapi/apigateway"
	"strings"
)

// Patch is admitted against each native resource's supported operation table,
// not by unmarshalling arbitrary resource JSON or ignoring unknown paths.
func patchString(p api.PatchOperation, target *string, allowed ...string) error {
	op := value(p.Op)
	if p.From != nil || !slices.Contains(allowed, op) {
		return bad("Invalid patch operation for " + value(p.Path))
	}
	if op == "remove" {
		*target = ""
		return nil
	}
	if p.Value == nil {
		return bad("Patch value is required")
	}
	*target = value(p.Value)
	return nil
}
func replace(p api.PatchOperation, target *string) error { return patchString(p, target, "replace") }
func patchBool(p api.PatchOperation, target *bool) error {
	v := ""
	if err := replace(p, &v); err != nil {
		return err
	}
	switch strings.ToLower(v) {
	case "true":
		*target = true
	case "false":
		*target = false
	default:
		return bad("Patch value must be true or false")
	}
	return nil
}
func pointerPart(v string) (string, error) {
	for i := 0; i < len(v); i++ {
		if v[i] == '~' {
			if i+1 == len(v) || (v[i+1] != '0' && v[i+1] != '1') {
				return "", bad("Invalid JSON pointer escape")
			}
			i++
		}
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, "~1", "/"), "~0", "~"), nil
}
func patchListChange(p api.PatchOperation, base string) (string, string, error) {
	op := value(p.Op)
	if p.From != nil || (op != "add" && op != "remove") {
		return "", "", bad("Unsupported list patch operation")
	}
	path := value(p.Path)
	item := value(p.Value)
	if path != base {
		var err error
		item, err = pointerPart(strings.TrimPrefix(path, base+"/"))
		if err != nil {
			return "", "", err
		}
	}
	if item == "" {
		return "", "", bad("Patch list value is required")
	}
	return op, item, nil
}

func patchList(p api.PatchOperation, base string, target *[]string) error {
	op, item, err := patchListChange(p, base)
	if err != nil {
		return err
	}
	index := slices.Index(*target, item)
	if op == "add" {
		if index < 0 {
			*target = append(*target, item)
		}
		return nil
	}
	if index < 0 {
		return bad("Patch list value does not exist")
	}
	*target = slices.Delete(*target, index, index+1)
	return nil
}
func patchMap(p api.PatchOperation, base string, target map[string]string) error {
	if p.From != nil {
		return bad("Unsupported map patch operation")
	}
	path := value(p.Path)
	if !strings.HasPrefix(path, base+"/") {
		return bad("Patch must identify a map entry")
	}
	key, err := pointerPart(strings.TrimPrefix(path, base+"/"))
	if err != nil {
		return err
	}
	if key == "" {
		return bad("Patch map key is required")
	}
	switch value(p.Op) {
	case "add", "replace":
		if p.Value == nil {
			return bad("Patch value is required")
		}
		target[key] = value(p.Value)
	case "remove":
		if _, ok := target[key]; !ok {
			return bad("Patch map entry does not exist")
		}
		delete(target, key)
	default:
		return bad("Unsupported map patch operation")
	}
	return nil
}
