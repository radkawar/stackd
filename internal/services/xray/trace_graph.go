package xray

import (
	"math"
	"sort"
	"time"

	api "stackd/internal/awsapi/xray"
)

type traceWindow struct{ Start, End time.Time }

func (w *traceWindow) includes(e *traceEntity) bool {
	if w == nil {
		return true
	}
	if e.row.End == nil {
		return false
	}
	t := time.Time(*traceTimestamp(*e.row.End))
	return !t.Before(w.Start) && !t.After(w.End)
}

// A reported service owns its local/remote subsegments, but never the span of
// another reported service. Retained admission/completion ordinals reconstruct
// envelope transitions without retaining customer-document versions.
type traceEnvelope struct {
	revision int64
	at       time.Time
	duration float64
	adjusted float64
}

func traceProjectHistory(v *traceView) {
	type change struct {
		revision int64
		at       time.Time
		start    float64
		end      *float64
	}
	changes := make(map[*traceEntity][]change)
	pending := make([]*traceEntity, 0, len(v.entities))
	for _, e := range v.entities {
		if e.parent == nil {
			pending = append(pending, e)
		}
	}
	for len(pending) > 0 {
		e := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		pending = append(pending, e.children...)
		if !e.row.Subsegment {
			e.owner = e
		} else if e.parent != nil {
			e.owner = e.parent.owner
		}
		if e.owner == nil {
			continue
		}
		initial := change{revision: e.row.ReceivedRevision, at: e.row.Received, start: e.row.Start}
		if e.row.Revision == e.row.ReceivedRevision {
			initial.end = e.row.End
		}
		changes[e.owner] = append(changes[e.owner], initial)
		if e.row.Revision != e.row.ReceivedRevision {
			at := e.row.Received
			if e.row.Completed != nil {
				at = *e.row.Completed
			}
			changes[e.owner] = append(changes[e.owner], change{revision: e.row.Revision, at: at, start: e.row.Start, end: e.row.End})
		}
	}
	for owner, events := range changes {
		sort.Slice(events, func(i, j int) bool { return events[i].revision < events[j].revision })
		start, end := math.Inf(1), math.Inf(-1)
		previous, observed := 0.0, false
		for i := 0; i < len(events); {
			revision, at := events[i].revision, events[i].at
			for i < len(events) && events[i].revision == revision {
				event := events[i]
				start = math.Min(start, event.start)
				if event.end != nil {
					end = math.Max(end, *event.end)
				}
				if event.at.After(at) {
					at = event.at
				}
				i++
			}
			if math.IsInf(end, -1) {
				continue
			}
			duration := math.Max(0, end-start)
			adjusted := duration
			if observed {
				adjusted += duration - previous
			}
			owner.history = append(owner.history, traceEnvelope{revision: revision, at: at, duration: duration, adjusted: adjusted})
			previous, observed = duration, true
		}
	}
}

type traceGraphObservation struct {
	count      int
	duration   float64
	histograms bool
}

func (v *traceView) graphAdmits(at time.Time) bool {
	if v.graphMembership.Admitted.After(at) {
		at = v.graphMembership.Admitted
	}
	return v.graphWindow == nil || !at.Before(v.graphWindow.Start) && !at.After(v.graphWindow.End)
}

// A streamed completion contributes the assembled service at completion.
// Subsequent accepted snapshots retain that observation, unlike a service
// first received complete, whose single observation follows its envelope.
func (v *traceView) graphObservation(e *traceEntity, aggregate bool) traceGraphObservation {
	d, complete := e.duration()
	if !complete {
		return traceGraphObservation{}
	}
	observation := traceGraphObservation{duration: d, histograms: true}
	if !aggregate {
		observation.count = 1
		if e.owner == e && len(e.history) > 0 {
			observation.duration = e.history[len(e.history)-1].adjusted
		}
		return observation
	}
	sum := 0.0
	v.visitGraphObservations(e, func(_ time.Time, point traceGraphObservation) {
		observation.count += point.count
		observation.histograms = point.histograms
		sum += point.duration * float64(point.count)
	})
	if observation.count > 0 {
		observation.duration = sum / float64(observation.count)
	}
	return observation
}

// visitGraphObservations shares retained completion receipts between graph
// totals and time-series buckets without expanding weighted samples.
func (v *traceView) visitGraphObservations(e *traceEntity, visit func(time.Time, traceGraphObservation)) {
	d, complete := e.duration()
	if !complete {
		return
	}
	owner := e.owner
	if owner != nil && owner.row.InProgress {
		return
	}
	emit := func(at time.Time, observation traceGraphObservation) {
		if v.graphMembership.Admitted.After(at) {
			at = v.graphMembership.Admitted
		}
		if v.graphAdmits(at) {
			visit(at, observation)
		}
	}
	observation := traceGraphObservation{count: 1, duration: d, histograms: true}
	if owner != nil && owner.row.End != nil && owner.row.ReceivedRevision < owner.row.Revision {
		// Earlier receivers retain counts and edge latency, but no service
		// histograms until the owning reported service completes.
		observation.histograms = !(e != owner && e.row.Revision < owner.row.Revision && v.graphMembership.AdmittedRevision < owner.row.Revision)
		for i, point := range owner.history {
			if i+1 < len(owner.history) && owner.history[i+1].revision <= v.graphMembership.AdmittedRevision {
				continue
			}
			if point.revision < owner.row.Revision || point.revision < e.row.Revision {
				continue
			}
			if e == owner {
				observation.duration = point.adjusted
			} else {
				observation.duration = d
			}
			emit(point.at, observation)
		}
		return
	}
	if e.row.Completed == nil {
		return
	}
	if owner == e && len(e.history) > 0 {
		observation.duration = e.history[len(e.history)-1].duration
	}
	emit(*e.row.Completed, observation)
}

type traceGraphStats struct {
	ok, errors, throttles, faults, total int64
	latency                              float64
	histogram                            map[float64]int
	durationHistogram                    map[float64]int
	start, end                           float64
	timed                                bool
}

func (s *traceGraphStats) add(e *traceEntity, bucket float64, observation traceGraphObservation, service bool) {
	if e.row.End == nil || observation.count == 0 {
		return
	}
	s.addResponse(e, observation, service)
	if service && observation.histograms {
		if s.durationHistogram == nil {
			s.durationHistogram = map[float64]int{}
		}
		s.durationHistogram[traceGraphValue(observation.duration)] += observation.count
	}
	s.observeBucket(bucket)
}

func (s *traceGraphStats) addResponse(e *traceEntity, observation traceGraphObservation, service bool) {
	d, complete := e.duration()
	if !complete || observation.count == 0 {
		return
	}
	er, fa, th := e.outcome()
	count := int64(observation.count)
	s.total += count
	s.latency += d * float64(count)
	switch {
	case th:
		s.throttles += count
	case fa:
		s.faults += count
	case er:
		s.errors += count
	default:
		s.ok += count
	}
	if !service || observation.histograms {
		if s.histogram == nil {
			s.histogram = map[float64]int{}
		}
		s.histogram[traceGraphValue(d)] += observation.count
	}
}
func (s *traceGraphStats) observeBucket(bucket float64) {
	if !s.timed || bucket < s.start {
		s.start = bucket
	}
	if !s.timed || bucket+1 > s.end {
		s.end = bucket + 1
	}
	s.timed = true
}

// Graph durations are rendered with millisecond precision, after summing raw
// durations for TotalResponseTime rather than rounding each observation first.
func traceGraphValue(value float64) float64 { return math.Round(value*1000) / 1000 }
func (s *traceGraphStats) errorsAPI() *api.ErrorStatistics {
	return &api.ErrorStatistics{OtherCount: new(api.NullableLong(s.errors)), ThrottleCount: new(api.NullableLong(s.throttles)), TotalCount: new(api.NullableLong(s.errors + s.throttles))}
}
func (s *traceGraphStats) faultsAPI() *api.FaultStatistics {
	return &api.FaultStatistics{OtherCount: new(api.NullableLong(s.faults)), TotalCount: new(api.NullableLong(s.faults))}
}
func (s *traceGraphStats) serviceAPI() *api.ServiceStatistics {
	return &api.ServiceStatistics{OkCount: new(api.NullableLong(s.ok)), TotalCount: new(api.NullableLong(s.total)), TotalResponseTime: traceDouble(traceGraphValue(s.latency)), ErrorStatistics: s.errorsAPI(), FaultStatistics: s.faultsAPI()}
}
func (s *traceGraphStats) edgeAPI() *api.EdgeStatistics {
	return &api.EdgeStatistics{OkCount: new(api.NullableLong(s.ok)), TotalCount: new(api.NullableLong(s.total)), TotalResponseTime: traceDouble(traceGraphValue(s.latency)), ErrorStatistics: s.errorsAPI(), FaultStatistics: s.faultsAPI()}
}

// AWS documents t-digest histograms, but not its compression or merge order:
// https://aws.amazon.com/blogs/aws/latency-distribution-graph-in-aws-x-ray/
// Native readbacks of identical inputs vary (histogram_edges.json). This is a
// deterministic K_1 t-digest scan, not a reproduction of those stochastic bins.
// Compression 100 bounds this local representation to 100 centroids; that is
// not an AWS API limit (the fixture includes native histograms with >100 bins).
const traceHistogramCompression = 100

func traceHistogramAPI(histogram map[float64]int) api.Histogram {
	values := make([]float64, 0, len(histogram))
	total := 0.0
	for v, count := range histogram {
		total += float64(count)
		values = append(values, v)
	}
	sort.Float64s(values)
	out := make(api.Histogram, 0, min(len(values), traceHistogramCompression))
	if len(values) == 0 {
		return out
	}
	// K_1(q) = compression*asin(2q-1)/(2*pi). A centroid spans at
	// most one scale unit, except an indivisible repeated value. Adjacent
	// centroids cannot be combined, so their count is bounded by twice the
	// scale's total span. Sorting costs O(u log u), scanning O(u), for u
	// distinct millisecond values, without expanding repeated observations.
	before := 0
	limit := func() float64 {
		angle := math.Asin(2*float64(before)/total-1) + 2*math.Pi/traceHistogramCompression
		return total * (math.Sin(math.Min(math.Pi/2, angle)) + 1) / 2
	}
	end := limit()
	count := 0
	sum := 0.0
	emit := func() {
		value := traceGraphValue(sum / float64(count))
		if len(out) > 0 && float64(*out[len(out)-1].Value) == value {
			*out[len(out)-1].Count += api.Integer(count)
		} else {
			out = append(out, api.HistogramEntry{Value: new(api.Double(value)), Count: new(api.Integer(count))})
		}
		before += count
		count = 0
		sum = 0
	}
	for _, value := range values {
		weight := histogram[value]
		if count > 0 && float64(before+count+weight) > end {
			emit()
			end = limit()
		}
		count += weight
		sum += value * float64(weight)
	}
	emit()
	return out
}

type traceGraphNode struct {
	node  *traceNode
	stats traceGraphStats
	edges map[traceIdentity]*traceGraphEdge
}
type traceGraphEdge struct {
	stats   traceGraphStats
	aliases map[traceIdentity]bool
}

// Trace graphs have null time bounds. Service graphs expose the one-second
// buckets of trace start times, not the wall-clock span of individual entities.
func aggregateTraceGraphs(views []*traceView) api.ServiceList { return traceGraphs(views, true) }
func (s *traceGraphStats) histogramAPI() api.Histogram        { return traceHistogramAPI(s.histogram) }
func traceGraphs(views []*traceView, aggregate bool) api.ServiceList {
	nodes := map[traceIdentity]*traceGraphNode{}
	ensure := func(n *traceNode) *traceGraphNode {
		g := nodes[n.identity]
		if g == nil {
			copyNode := *n
			g = &traceGraphNode{node: &copyNode, edges: map[traceIdentity]*traceGraphEdge{}}
			nodes[n.identity] = g
		} else {
			g.node.root = g.node.root || n.root
			if n.state == "active" {
				g.node.state = "active"
			}
		}
		return g
	}
	for _, v := range views {
		if !aggregate && v.root != nil && v.root.row.End == nil {
			continue
		}
		observations := make(map[*traceEntity]traceGraphObservation, len(v.entities))
		for _, e := range v.entities {
			observations[e] = v.graphObservation(e, aggregate)
		}
		bucket := math.Floor(v.start)
		if v.root != nil {
			bucket = math.Floor(v.root.row.Start)
		}
		for _, n := range v.nodes {
			for _, e := range n.entities {
				observation := observations[e]
				if !aggregate || observation.count > 0 {
					ensure(n).stats.add(e, bucket, observation, true)
				}
			}
			if !aggregate {
				ensure(n)
			}
		}
		for _, e := range v.edges {
			observation := observations[e.entity]
			if aggregate && observation.count == 0 {
				continue
			}
			source := ensure(e.source)
			destination := ensure(e.destination)
			source.stats.observeBucket(bucket)
			destination.stats.observeBucket(bucket)
			edge := source.edges[e.destination.identity]
			if edge == nil {
				edge = &traceGraphEdge{aliases: map[traceIdentity]bool{}}
				source.edges[e.destination.identity] = edge
			}
			edge.stats.add(e.entity, bucket, observation, false)
			if e.source.client {
				source.stats.add(e.entity, bucket, observation, false)
			}
			if e.alias != nil {
				edge.aliases[*e.alias] = true
			}
		}
	}
	ids := make([]traceIdentity, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := ids[i], ids[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.account != b.account {
			return a.account < b.account
		}
		return a.region < b.region
	})
	refs := map[traceIdentity]int{}
	for i, id := range ids {
		refs[id] = i
	}
	out := make(api.ServiceList, 0, len(ids))
	for i, id := range ids {
		g := nodes[id]
		n := g.node
		svc := api.Service{Name: traceString(id.name), Names: api.ServiceNames{api.String(id.name)}, Type: traceString(id.kind), Region: traceString(id.region), ReferenceId: new(api.NullableInteger(i)), State: traceString(n.state), Edges: api.EdgeList{}}
		if aggregate {
			svc.Region = nil
			svc.HostedIn = map[string]any{}
			svc.KeyAttributes = map[string]any{}
		}
		if n.root {
			svc.Root = traceBool(true)
		}
		if !n.client {
			svc.SummaryStatistics = g.stats.serviceAPI()
			svc.DurationHistogram = traceHistogramAPI(g.stats.durationHistogram)
			svc.ResponseTimeHistogram = g.stats.histogramAPI()
		}
		if aggregate && g.stats.timed {
			svc.StartTime = traceTimestamp(g.stats.start)
			svc.EndTime = traceTimestamp(g.stats.end)
		}
		destinations := make([]traceIdentity, 0, len(g.edges))
		for dest := range g.edges {
			destinations = append(destinations, dest)
		}
		sort.Slice(destinations, func(i, j int) bool { return refs[destinations[i]] < refs[destinations[j]] })
		for _, dest := range destinations {
			edge := g.edges[dest]
			item := api.Edge{ReferenceId: new(api.NullableInteger(refs[dest])), SummaryStatistics: edge.stats.edgeAPI(), ResponseTimeHistogram: edge.stats.histogramAPI(), Aliases: api.AliasList{}}
			aliases := make([]traceIdentity, 0, len(edge.aliases))
			for alias := range edge.aliases {
				aliases = append(aliases, alias)
			}
			sort.Slice(aliases, func(i, j int) bool {
				if aliases[i].name != aliases[j].name {
					return aliases[i].name < aliases[j].name
				}
				return aliases[i].kind < aliases[j].kind
			})
			for _, alias := range aliases {
				item.Aliases = append(item.Aliases, api.Alias{Name: traceString(alias.name), Names: api.AliasNames{api.String(alias.name)}, Type: traceString(alias.kind)})
			}
			if aggregate && g.stats.timed {
				// Native edge bounds cover the source service's buckets, even
				// when other requests at that source did not traverse this edge.
				item.StartTime = traceTimestamp(g.stats.start)
				item.EndTime = traceTimestamp(g.stats.end)
			}
			svc.Edges = append(svc.Edges, item)
		}
		out = append(out, svc)
	}
	return out
}
