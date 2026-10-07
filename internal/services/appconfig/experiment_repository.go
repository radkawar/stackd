package appconfig

import "time"

// ExperimentAttribute preserves the modeled attribute union, including empty arrays.
type ExperimentAttribute struct {
	Kind    string
	Boolean bool
	Number  float64
	String  string
	Numbers []float64
	Strings []string
}
type ExperimentTreatment struct {
	Key, Description string
	Weight           float64
	Enabled          bool
	Attributes       map[string]ExperimentAttribute
}
type ExperimentDefinition struct {
	Scope
	ApplicationID, ID, Name, EnvironmentID, ProfileID, FlagKey                              string
	AudienceRule, AudienceDescription, Hypothesis, LaunchCriteria, KMSKeyIdentifier, Status string
	CreatedAt, UpdatedAt                                                                    time.Time
	Control                                                                                 ExperimentTreatment
	Treatments                                                                              []ExperimentTreatment
	Ownership                                                                               CloudFormationOwnership
}
type ExperimentResult struct{ ExecutiveSummary, ReasonsToLaunch, ReasonsNotToLaunch string }
type ExperimentRun struct {
	Scope
	ApplicationID, DefinitionID   string
	Number                        int32
	Description, Status           string
	Exposure                      float64
	Overrides                     map[string]string
	Snapshot                      ExperimentDefinition
	Result                        *ExperimentResult
	StartedAt, UpdatedAt, EndedAt time.Time
	Events                        []ExperimentEvent
	Ownership                     CloudFormationOwnership
}
type ExperimentEvent struct {
	Type, Description, TriggeredBy, DeploymentARN string
	At                                            time.Time
	Exposure                                      *float64
	Overrides                                     map[string]string
}
type ExperimentReader interface {
	ExperimentDefinitions(Scope, string) ([]ExperimentDefinition, error)
	ExperimentRuns(Scope, string, string) ([]ExperimentRun, error)
}
type ExperimentWriter interface {
	PutExperimentDefinition(ExperimentDefinition) error
	DeleteExperimentDefinition(Scope, string, string) error
	PutExperimentRun(ExperimentRun) error
}
