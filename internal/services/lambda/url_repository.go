package lambda

import (
	"slices"
	"time"
)

// FunctionURLCORS preserves omitted fields separately from explicit empty values.
type FunctionURLCORS struct {
	AllowCredentials                                        *bool
	AllowHeaders, AllowMethods, AllowOrigins, ExposeHeaders []string
	MaxAge                                                  *int32
}

type FunctionURLSettings struct {
	AuthType, InvokeMode string
	Cors                 *FunctionURLCORS
}

type FunctionURLRecord struct {
	Key                 FunctionReference
	Owner               AdditionalOwner
	ID                  string
	Created, Modified   time.Time
	Settings, Effective FunctionURLSettings
	AppliesAt           time.Time
}

// EffectiveSettings resolves propagation on demand; no external work is scheduled.
func (v FunctionURLRecord) EffectiveSettings(now time.Time) FunctionURLSettings {
	if now.Before(v.AppliesAt) {
		return v.Effective
	}
	return v.Settings
}

type FunctionURLReader interface {
	FunctionURL(FunctionReference) (FunctionURLRecord, error)
	FunctionURLByID(string) (FunctionURLRecord, error)
	FunctionURLs(FunctionKey) ([]FunctionURLRecord, error)
}

type FunctionURLWriter interface {
	PutFunctionURL(FunctionURLRecord) error
	DeleteFunctionURL(FunctionReference) error
}

func cloneFunctionURLSettings(v FunctionURLSettings) FunctionURLSettings {
	if v.Cors != nil {
		cors := *v.Cors
		cors.AllowHeaders = slices.Clone(cors.AllowHeaders)
		cors.AllowMethods = slices.Clone(cors.AllowMethods)
		cors.AllowOrigins = slices.Clone(cors.AllowOrigins)
		cors.ExposeHeaders = slices.Clone(cors.ExposeHeaders)
		if cors.AllowCredentials != nil {
			cors.AllowCredentials = new(*cors.AllowCredentials)
		}
		if cors.MaxAge != nil {
			cors.MaxAge = new(*cors.MaxAge)
		}
		v.Cors = &cors
	}
	return v
}

func cloneFunctionURL(v FunctionURLRecord) FunctionURLRecord {
	v.Settings = cloneFunctionURLSettings(v.Settings)
	v.Effective = cloneFunctionURLSettings(v.Effective)
	return v
}
