package xray

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	api "stackd/internal/awsapi/xray"
)

// traceView is an immutable decoded snapshot. Graph and filter consumers share
// the same entities rather than repeatedly parsing customer documents.
type traceView struct {
	Summary    api.TraceSummary
	Services   api.ServiceList
	key        TraceKey
	entities   []*traceEntity
	root       *traceEntity
	nodes      []*traceNode
	edges      []*traceEdge
	start, end float64
	causes     map[string][]any
	// Service graphs select retained observations by receipt, while topology is
	// projected as of the query's upper bound.
	graphWindow     *traceWindow
	graphMembership GroupMembership
}

type traceEntity struct {
	row            SegmentRecord
	doc            map[string]any
	parent         *traceEntity
	children       []*traceEntity
	node           *traceNode
	exceptions     api.RootCauseExceptions
	causeReference *traceEntity
	owner          *traceEntity
	history        []traceEnvelope
}

type traceIdentity struct{ name, kind, account, region string }
type traceNode struct {
	identity               traceIdentity
	inferred, root, client bool
	state                  string
	entities               []*traceEntity
}
type traceEdge struct {
	source, destination *traceNode
	entity              *traceEntity
	alias               *traceIdentity
}

func traceString(v string) *api.String {
	if v == "" {
		return nil
	}
	return new(api.String(v))
}
func traceBool(v bool) *api.NullableBoolean     { return new(api.NullableBoolean(v)) }
func traceDouble(v float64) *api.NullableDouble { return new(api.NullableDouble(v)) }
func traceTimestamp(v float64) *api.Timestamp {
	sec, fraction := math.Modf(v)
	return new(api.Timestamp(time.Unix(int64(sec), int64(math.Round(fraction*1e9))).UTC()))
}
func tracePath(doc map[string]any, path ...string) any {
	var current any = doc
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[key]
	}
	return current
}
func traceText(doc map[string]any, path ...string) string {
	s, _ := tracePath(doc, path...).(string)
	return s
}
func traceFlag(doc map[string]any, key string) bool { b, _ := doc[key].(bool); return b }
func (e *traceEntity) duration() (float64, bool) {
	if e.row.End == nil {
		return 0, false
	}
	return math.Max(0, *e.row.End-e.row.Start), true
}
func (e *traceEntity) remote() bool {
	ns := traceText(e.doc, "namespace")
	return ns == "remote" || ns == "aws"
}
func (e *traceEntity) outcome() (err, fault, throttle bool) {
	status, _ := tracePath(e.doc, "http", "response", "status").(float64)
	throttle = traceFlag(e.doc, "throttle") || status == 429
	fault = traceFlag(e.doc, "fault") || status >= 500 && status < 600
	err = !throttle && (traceFlag(e.doc, "error") || status >= 400 && status < 500)
	return
}
func (id traceIdentity) serviceID() api.ServiceId {
	return api.ServiceId{Name: traceString(id.name), Names: api.ServiceNames{api.String(id.name)}, Type: traceString(id.kind)}
}
func traceEntityIdentity(e *traceEntity) traceIdentity {
	id := traceIdentity{name: traceText(e.doc, "name"), kind: traceText(e.doc, "origin"), account: traceText(e.doc, "aws", "account_id"), region: traceText(e.doc, "aws", "region")}
	if !e.row.Subsegment {
		return id
	}
	switch traceText(e.doc, "namespace") {
	case "remote":
		id.kind = "remote"
		id.region = ""
	case "aws":
		id.kind = "AWS::" + id.name
		id.region = traceText(e.doc, "aws", "region")
		// Resource metadata identifies a call only when an operation is present.
		// Without it native graphs retain the generic AWS service identity.
		if traceText(e.doc, "aws", "operation") != "" {
			switch id.name {
			case "DynamoDB":
				if table := traceText(e.doc, "aws", "table_name"); table != "" {
					id.name = table
					id.kind = "AWS::DynamoDB::Table"
				}
			case "S3":
				if bucket := traceText(e.doc, "aws", "bucket_name"); bucket != "" {
					id.name = bucket
					id.kind = "AWS::S3::Bucket"
				}
			case "SQS":
				if queue := traceText(e.doc, "aws", "queue_url"); queue != "" {
					id.name = queue
					id.kind = "AWS::SQS::Queue"
				}
			case "SNS":
				if topic := traceText(e.doc, "aws", "topic_arn"); topic != "" {
					id.name = topic
				}
			case "Lambda":
				if function := traceText(e.doc, "aws", "function_name"); function != "" {
					id.name = function
				}
			}
		}
	}
	return id
}

func projectTrace(key TraceKey, rows []SegmentRecord) (*traceView, error) {
	v := &traceView{key: key, causes: map[string][]any{}}
	s := &v.Summary
	*s = api.TraceSummary{Id: new(api.TraceId(key.ID)), Annotations: api.Annotations{}, Users: api.TraceUsers{}, ServiceIds: api.ServiceIds{}, AvailabilityZones: api.TraceAvailabilityZones{}, InstanceIds: api.TraceInstanceIds{}, ResourceARNs: api.TraceResourceARNs{}, ErrorRootCauses: api.ErrorRootCauses{}, FaultRootCauses: api.FaultRootCauses{}, ResponseTimeRootCauses: api.ResponseTimeRootCauses{}, HasError: traceBool(false), HasFault: traceBool(false), HasThrottle: traceBool(false), IsPartial: traceBool(false), Http: &api.Http{}}
	byID := make(map[string]*traceEntity, len(rows))
	for _, row := range rows {
		e := &traceEntity{row: row}
		if err := json.Unmarshal([]byte(row.Document), &e.doc); err != nil {
			return nil, fmt.Errorf("decode stored X-Ray segment %s: %w", row.Key.ID, err)
		}
		if e.doc == nil {
			return nil, fmt.Errorf("stored X-Ray segment %s is not an object", row.Key.ID)
		}
		v.entities = append(v.entities, e)
		byID[row.Key.ID] = e
	}
	sort.Slice(v.entities, func(i, j int) bool {
		a, b := v.entities[i], v.entities[j]
		if a.row.Start != b.row.Start {
			return a.row.Start < b.row.Start
		}
		return a.row.Key.ID < b.row.Key.ID
	})
	if len(v.entities) == 0 {
		v.Services = api.ServiceList{}
		return v, nil
	}
	v.start = v.entities[0].row.Start
	v.end = v.start
	complete := true
	for _, e := range v.entities {
		e.parent = byID[e.row.ParentID]
		if e.parent != nil {
			e.parent.children = append(e.parent.children, e)
		} else if e.row.ParentID != "" {
			s.IsPartial = traceBool(true)
		}
		if !e.row.Subsegment && e.row.ParentID == "" && v.root == nil {
			v.root = e
		}
		if e.row.End == nil {
			complete = false
		} else {
			v.end = math.Max(v.end, *e.row.End)
		}
	}
	// Detect corrupt/cyclic topology without recursive traversal or hanging queries.
	for _, e := range v.entities {
		seen := map[*traceEntity]bool{}
		for p := e; p != nil; p = p.parent {
			if seen[p] {
				return nil, fmt.Errorf("cyclic X-Ray segment ancestry at %s", e.row.Key.ID)
			}
			seen[p] = true
		}
	}
	s.StartTime = traceTimestamp(v.start)
	if complete {
		s.Duration = traceDouble(v.end - v.start)
	}
	nodes := map[traceIdentity]*traceNode{}
	addNode := func(id traceIdentity, inferred, client bool) *traceNode {
		// Account identity defaults to the trace owner for selectors; native public
		// ServiceIds leave AccountId null for classic same-account traces.
		if id.account == "" {
			id.account = key.AccountID
		}
		n := nodes[id]
		if n == nil {
			state := "active"
			if inferred {
				state = "unknown"
				if id.kind == "remote" {
					state = "passive"
				}
			}
			if client {
				state = "unknown"
			}
			n = &traceNode{identity: id, inferred: inferred, client: client, state: state}
			nodes[id] = n
			v.nodes = append(v.nodes, n)
		}
		return n
	}
	for _, e := range v.entities {
		if !e.row.Subsegment {
			e.node = addNode(traceEntityIdentity(e), traceFlag(e.doc, "inferred"), false)
			e.node.entities = append(e.node.entities, e)
			if e == v.root {
				e.node.root = true
			}
		}
	}
	for _, e := range v.entities {
		if !e.row.Subsegment || !e.remote() {
			continue
		}
		var callee *traceEntity
		for _, child := range e.children {
			if !child.row.Subsegment {
				callee = child
				break
			}
		}
		if callee != nil {
			continue
		}
		e.node = addNode(traceEntityIdentity(e), true, false)
		e.node.entities = append(e.node.entities, e)
	}
	for _, e := range v.entities {
		if e.node != nil {
			continue
		}
		for p := e.parent; p != nil; p = p.parent {
			if p.node != nil {
				e.node = p.node
				break
			}
		}
	}
	for _, e := range v.entities {
		if e.node == nil {
			continue
		}
		if !e.row.Subsegment && e.parent != nil {
			caller := e.parent
			source := caller.node
			if caller.row.Subsegment && caller.remote() {
				for p := caller.parent; p != nil; p = p.parent {
					if p.node != nil {
						source = p.node
						break
					}
				}
			}
			if source != nil {
				edge := &traceEdge{source: source, destination: e.node, entity: e}
				if caller.row.Subsegment && caller.remote() {
					edge.entity = caller
					alias := traceEntityIdentity(caller)
					edge.alias = &alias
				}
				v.edges = append(v.edges, edge)
			}
		} else if e.row.Subsegment && e.remote() && e.node.inferred {
			for p := e.parent; p != nil; p = p.parent {
				if p.node != nil && p.node != e.node {
					v.edges = append(v.edges, &traceEdge{source: p.node, destination: e.node, entity: e})
					break
				}
			}
		}
	}
	if v.root != nil {
		e := v.root
		id := e.node.identity
		entry := id.serviceID()
		s.EntryPoint = &entry
		er, fa, th := e.outcome()
		s.HasError = traceBool(er)
		s.HasFault = traceBool(fa)
		s.HasThrottle = traceBool(th)
		if d, ok := e.duration(); ok {
			s.ResponseTime = traceDouble(d)
		}
		s.Http = &api.Http{ClientIp: traceString(traceText(e.doc, "http", "request", "client_ip")), HttpMethod: traceString(traceText(e.doc, "http", "request", "method")), HttpURL: traceString(traceText(e.doc, "http", "request", "url")), UserAgent: traceString(traceText(e.doc, "http", "request", "user_agent"))}
		if status, ok := tracePath(e.doc, "http", "response", "status").(float64); ok {
			s.Http.HttpStatus = new(api.NullableInteger(status))
		}
		clientID := id
		clientID.kind = "client"
		clientID.region = ""
		client := addNode(clientID, false, true)
		v.edges = append(v.edges, &traceEdge{source: client, destination: e.node, entity: e})
	}
	traceProjectHistory(v)
	traceProjectMetadata(v)
	traceResolveExceptions(v)
	traceProjectCauses(v)
	v.Services = traceGraphs([]*traceView{v}, false)
	for _, n := range v.nodes {
		s.ServiceIds = append(s.ServiceIds, n.identity.serviceID())
	}
	return v, nil
}

func traceAnnotation(value any) *api.AnnotationValue {
	switch x := value.(type) {
	case bool:
		return &api.AnnotationValue{BooleanValue: traceBool(x)}
	case float64:
		return &api.AnnotationValue{NumberValue: traceDouble(x)}
	case string:
		return &api.AnnotationValue{StringValue: new(api.String(x))}
	}
	return nil
}
func traceProjectMetadata(v *traceView) {
	users, zones, instances, arns := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	annotations := map[string]map[any]bool{}
	for _, e := range v.entities {
		if user := traceText(e.doc, "user"); user != "" && !users[user] {
			users[user] = true
			v.Summary.Users = append(v.Summary.Users, api.TraceUser{UserName: traceString(user)})
		}
		if zone := traceText(e.doc, "aws", "ec2", "availability_zone"); zone != "" && !zones[zone] {
			zones[zone] = true
			v.Summary.AvailabilityZones = append(v.Summary.AvailabilityZones, api.AvailabilityZoneDetail{Name: traceString(zone)})
		}
		if id := traceText(e.doc, "aws", "ec2", "instance_id"); id != "" && !instances[id] {
			instances[id] = true
			v.Summary.InstanceIds = append(v.Summary.InstanceIds, api.InstanceIdDetail{Id: traceString(id)})
		}
		if arn := traceText(e.doc, "resource_arn"); arn != "" && !arns[arn] {
			arns[arn] = true
			v.Summary.ResourceARNs = append(v.Summary.ResourceARNs, api.ResourceARNDetail{ARN: traceString(arn)})
		}
		values, _ := e.doc["annotations"].(map[string]any)
		for key, value := range values {
			annotation := traceAnnotation(value)
			if annotation == nil {
				continue
			}
			if annotations[key] == nil {
				annotations[key] = map[any]bool{}
			}
			if annotations[key][value] {
				continue
			}
			annotations[key][value] = true
			v.Summary.Annotations[api.AnnotationKey(key)] = append(v.Summary.Annotations[api.AnnotationKey(key)], api.ValueWithServiceIds{AnnotationValue: annotation})
		}
	}
}
