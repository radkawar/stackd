package cloudtrail

import (
	"strconv"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/cloudtrail"
	"stackd/journal"
)

func historyEvent(e journal.Event) (api.Event, error) {
	call := e.APICallCompleted
	id := call.Identity
	encoded, err := apievents.CloudTrailRecord(e)
	if err != nil {
		return api.Event{}, err
	}
	out := api.Event{EventId: str(call.EventID), EventName: str(call.EventName), EventSource: str(call.EventSource), EventTime: &e.At, ReadOnly: str(strconv.FormatBool(call.ReadOnly)), CloudTrailEvent: str(string(encoded)), Resources: api.ResourceList{}}
	if id.AccessKeyID != "" {
		out.AccessKeyId = str(id.AccessKeyID)
	}
	if id.UserName != "" {
		out.Username = str(id.UserName)
	}
	for _, r := range call.Resources {
		resource := api.Resource{ResourceName: str(r.Name)}
		if r.Type != "" {
			resource.ResourceType = str(r.Type)
		}
		out.Resources = append(out.Resources, resource)
	}
	return out, nil
}
