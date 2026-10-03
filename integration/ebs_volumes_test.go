package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"stackd"
	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
)

var ebsVolumeIDPattern = regexp.MustCompile(`^vol-[0-9a-f]{17}$`)

type ebsReplayVolume struct {
	created, modified, deleted time.Time
	lastSnapshot               time.Time
	modification               *ec2types.VolumeModification
}

type ebsVolumeReplay struct {
	*ebsSnapshotReplay
	operation        string
	volumes          map[string]*ebsReplayVolume
	zones            map[string]map[string]string
	pageTokens       map[string]string
	pageRows         map[string]map[string]json.RawMessage
	pageGroups       map[string]string
	checkedScopes    map[string]bool
	literalKeys      map[string]bool
	deletedSnapshots map[string]time.Time
}

// The same native SDK documents cover both retained owners. Reopening after each
// accepted call includes hydration, source deletion, modification, pagination,
// snapshot materialization and exact encrypted/plain block downloads.
func TestEBSNativeVolumes(t *testing.T) {
	for _, names := range [][]string{
		{"volume_controls"}, {"volume_controls_bounds"}, {"volume_controls_configuration"}, {"volume_controls_io"},
		{"volume_controls_deletion"},
		{"volume_controls_initialization"},
		{"volume_data", "volume_data_read_authority"}, {"volume_data_authority"},
		{"volume_data_source_authority"}, {"volume_data_snapshot_controls"},
		{"volume_data_key_reuse_settled"},
	} {
		t.Run(names[0], func(t *testing.T) {
			var fixture ebsCopyFixture
			awsReadFixture(t, "ebs/"+names[0]+".json", &fixture)
			for _, name := range names[1:] {
				var supplement ebsCopyFixture
				awsReadFixture(t, "ebs/"+name+".json", &supplement)
				if supplement.Account != fixture.Account || supplement.Member != fixture.Member || supplement.Region != fixture.Region {
					t.Fatal("volume supplement changes account or region")
				}
				fixture.Calls = append(fixture.Calls, supplement.Calls...)
				if fixture.Sessions == nil {
					fixture.Sessions = map[string]json.RawMessage{}
				}
				maps.Copy(fixture.Sessions, supplement.Sessions)
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					v := newEBSVolumeReplay(t, fixture, backend)
					for index, row := range fixture.Calls {
						if !v.include(t, fixture.Calls, index) {
							continue
						}
						if !t.Run(row.Label, func(t *testing.T) {
							v.call(t, row)
							if row.Code == "Success" && row.Operation == "CreateVolume" {
								if scope := v.zoneScope(row); !v.checkedScopes[scope] {
									var volume struct{ VolumeID string }
									awsDecodeJSON(t, row.Output, &volume)
									v.checkIsolationAndTags(t, row, v.bindings[volume.VolumeID])
									v.checkedScopes[scope] = true
								}
							}
							if row.Code == "Success" && row.Operation == "ModifySnapshotAttribute" {
								v.clock.Advance(ebsdomain.SharingDelay)
							}
						}) {
							return
						}
					}
				})
			}
		})
	}
}

func newEBSVolumeReplay(t *testing.T, fixture ebsCopyFixture, backend string, start ...func(stackd.Config) (*stackd.Stack, *httptest.Server)) *ebsVolumeReplay {
	t.Helper()
	var r *ebsSnapshotReplay
	if fixture.Member == "" {
		r = newEBSSnapshotReplay(t, fixture.ebsNativeFixture, backend, start...)
	} else {
		r = newEBSCopyReplay(t, fixture, backend, start...)
		// The read-only deleted-source supplement retains member session
		// policies but did not repeat GetCallerIdentity for each session.
		for caller := range fixture.Sessions {
			if r.sessionRoles[caller] == "" {
				r.sessionRoles[caller] = "arn:aws:iam::222222222222:role/CopyRecipient"
			}
		}
	}
	v := &ebsVolumeReplay{ebsSnapshotReplay: r, volumes: map[string]*ebsReplayVolume{}, zones: map[string]map[string]string{},
		pageTokens: map[string]string{}, pageRows: map[string]map[string]json.RawMessage{}, pageGroups: map[string]string{}, checkedScopes: map[string]bool{}, literalKeys: map[string]bool{}, deletedSnapshots: map[string]time.Time{}}
	r.volumes = v
	for _, row := range fixture.Calls {
		if row.Operation == "DescribeAvailabilityZones" && row.Code == "Success" {
			v.bindZones(t, row)
		}
	}
	// Native random resource IDs change which rows fit on an individual page.
	// Keep exact row documents and assert the complete chain's membership, not
	// an incidental ordering or per-page identity partition.
	groups := map[string]string{}
	for _, row := range fixture.Calls {
		if row.Operation != "DescribeVolumes" || row.Code != "Success" || row.ResponsePaginationTokenSHA256 == "" && row.RequestPaginationTokenSHA256 == "" {
			continue
		}
		group := groups[row.RequestPaginationTokenSHA256]
		if group == "" {
			group = row.Label
		}
		if row.ResponsePaginationTokenSHA256 != "" {
			groups[row.ResponsePaginationTokenSHA256] = group
		}
		v.pageGroups[row.Label] = group
		if v.pageRows[group] == nil {
			v.pageRows[group] = map[string]json.RawMessage{}
		}
		var output struct{ Volumes []json.RawMessage }
		awsDecodeJSON(t, row.Output, &output)
		if len(output.Volumes) == 0 && row.RequestPaginationTokenSHA256 != "" {
			delete(v.pageGroups, row.Label) // Changed-filter empty continuation remains an exact SDK assertion.
		}
		for _, raw := range output.Volumes {
			var volume struct{ VolumeID string }
			awsDecodeJSON(t, raw, &volume)
			v.pageRows[group][volume.VolumeID] = raw
		}
	}
	return v
}

func (v *ebsVolumeReplay) account(row ebsNativeCall) string {
	if role := v.sessionRoles[row.Caller]; role != "" {
		return strings.SplitN(role, ":", 6)[4]
	}
	if row.Caller == "member" {
		return "222222222222"
	}
	return v.fixture.Account
}

func (v *ebsVolumeReplay) zoneScope(row ebsNativeCall) string {
	return v.account(row) + "/" + v.region(row)
}

func (v *ebsVolumeReplay) bindZones(t *testing.T, row ebsNativeCall) {
	t.Helper()
	scope := v.zoneScope(row)
	if v.zones[scope] != nil {
		return
	}
	var native ec2.DescribeAvailabilityZonesOutput
	if err := json.Unmarshal(row.Output, &native); err != nil {
		t.Fatal(err)
	}
	client := ec2.New(ec2.Options{Region: v.region(row), BaseEndpoint: aws.String(v.clients.server.URL), Credentials: v.provider(t, row.Caller), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
	actual, err := client.DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(native.AvailabilityZones, func(a, b ec2types.AvailabilityZone) int {
		return strings.Compare(aws.ToString(a.ZoneName), aws.ToString(b.ZoneName))
	})
	slices.SortFunc(actual.AvailabilityZones, func(a, b ec2types.AvailabilityZone) int {
		return strings.Compare(aws.ToString(a.ZoneName), aws.ToString(b.ZoneName))
	})
	if len(actual.AvailabilityZones) < len(native.AvailabilityZones) {
		t.Fatal("local catalog cannot bind captured physical zones")
	}
	bindings := map[string]string{}
	for i, zone := range native.AvailabilityZones {
		bindings[aws.ToString(zone.ZoneName)] = aws.ToString(actual.AvailabilityZones[i].ZoneName)
		bindings[aws.ToString(zone.ZoneId)] = aws.ToString(actual.AvailabilityZones[i].ZoneId)
	}
	v.zones[scope] = bindings
}

func (v *ebsVolumeReplay) include(t *testing.T, rows []ebsNativeCall, index int) bool {
	t.Helper()
	row := rows[index]
	if strings.HasPrefix(row.Label, "cleanup-") {
		return false // Capture teardown is not an admitted volume API scenario.
	}
	if row.Label == "missing-source" && row.Code == "InvalidSnapshotID.Malformed" {
		t.Run(row.Label, func(t *testing.T) {
			t.Skip("approved deferral: opaque native snapshot-ID encoding; retained in volume_controls_snapshot_ids_contract.json")
		})
		return false
	}
	switch row.Service {
	case "ec2", "ebs":
	case "iam":
		if row.Operation != "CreateRole" && row.Operation != "PutRolePolicy" {
			t.Fatalf("unclassified native IAM volume operation %s", row.Operation)
		}
	case "kms":
		if row.Operation != "CreateKey" && row.Operation != "PutKeyPolicy" && row.Operation != "DisableKey" && row.Operation != "EnableKey" {
			t.Fatalf("unclassified native KMS volume operation %s", row.Operation)
		}
	case "sts", "s3", "cloudtrail", "sqs", "events":
		return false // Identity/trail/delivery setup is owned by the audit replay.
	default:
		t.Fatalf("unclassified native volume service %s", row.Service)
	}
	if row.Operation == "DescribeAvailabilityZones" {
		return false // Account-specific catalog was bound as setup, not fabricated.
	}
	if row.Label == "bounds-page-describe_volume_status-5" {
		// This empty page's token comes from an ambient account-wide scan;
		// the capture owns only one disk. Do not invent the other account's
		// volumes. The owned controls fixture exercises real scan/page chains.
		t.Log("retaining ambient status-pagination observation without replaying unowned inventory")
		return false
	}
	if group := v.pageGroups[row.Label]; group != "" {
		if row.RequestPaginationTokenSHA256 == "" {
			t.Run(row.Label, func(t *testing.T) { v.replayPageChain(t, row, group) })
		}
		return false // Replayed as a complete native chain, including local token replay.
	}
	if row.Operation == "DescribeVolumes" && row.Code == "Success" && row.RequestPaginationTokenSHA256 != "" {
		t.Run(row.Label, func(t *testing.T) { v.replayPageChain(t, row, row.Label) })
		return false // Changed-filter continuation is exhausted and compared as a set.
	}
	if !ebsCopyReplayRow(t, v.ebsSnapshotReplay, rows, index) {
		return false
	}
	if row.Operation == "DescribeVolumes" && row.Code == "Success" {
		var output struct {
			Volumes []struct{ VolumeID, State string }
		}
		awsDecodeJSON(t, row.Output, &output)
		for _, volume := range output.Volumes {
			if state := v.volumes[volume.VolumeID]; state != nil && volume.State == "creating" && !v.clock.Now().Before(state.created.Add(ebsdomain.VolumeCreationDelay)) {
				return false // Independent native worker ordering is not a local SLA.
			}
		}
	}
	if strings.Contains(row.Label, "-state-") || strings.Contains(row.Label, "available-") || strings.Contains(row.Label, "readiness") || strings.Contains(row.Label, "-settled-status-") || strings.Contains(row.Label, "-settled-volumes-") {
		key := row.Service + "/" + row.Operation + "/" + row.Caller + "/" + string(row.Input)
		observation := row.Code + "/" + string(row.Output)
		if v.polls[key] == observation {
			return false
		}
		v.polls[key] = observation
	}
	return true
}

func (v *ebsVolumeReplay) prepare(t *testing.T, row ebsNativeCall) ebsNativeCall {
	t.Helper()
	v.operation = row.Operation
	var input map[string]any
	awsDecodeJSON(t, row.Input, &input)
	v.mapZones(input, v.zones[v.zoneScope(row)])
	if input["NextToken"] == "<redacted>" {
		token := v.pageTokens[row.RequestPaginationTokenSHA256]
		if token == "" {
			if row.Code == "Success" {
				t.Fatal("successful page has no retained issuing token")
			}
			token = "invalid"
		}
		input["NextToken"] = token
	}
	row.Input, _ = json.Marshal(input)
	if row.Code == "Success" && row.Service == "ec2" {
		var output any
		awsDecodeJSON(t, row.Output, &output)
		v.bindManagedKeys(t, row, output)
	}
	return row
}

func (v *ebsVolumeReplay) mapZones(value any, bindings map[string]string) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "AvailabilityZone" || key == "AvailabilityZoneId" {
				if raw, ok := child.(string); ok && bindings[raw] != "" {
					node[key] = bindings[raw]
				}
			}
			if key == "Values" && (node["Name"] == "availability-zone" || node["Name"] == "availability-zone-id") {
				for i, value := range child.([]any) {
					if raw, ok := value.(string); ok && bindings[raw] != "" {
						child.([]any)[i] = bindings[raw]
					}
				}
			}
			v.mapZones(child, bindings)
		}
	case []any:
		for _, child := range node {
			v.mapZones(child, bindings)
		}
	}
}

func (v *ebsVolumeReplay) bindManagedKeys(t *testing.T, row ebsNativeCall, value any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "KmsKeyId" || key == "KmsKeyArn" {
				if native, ok := child.(string); ok && strings.HasPrefix(native, "arn:") && v.bindings[native] == "" && !v.literalKeys[native] {
					var input struct{ KmsKeyID string }
					awsDecodeJSON(t, row.Input, &input)
					if input.KmsKeyID != "" && input.KmsKeyID != "alias/aws/ebs" {
						// Unresolved explicit key identities remain literal. Mapping
						// them to the default would hide asynchronous KMS failures.
						v.literalKeys[native] = true
						continue
					}
					parts := strings.SplitN(native, ":", 6)
					if len(parts) != 6 || parts[2] != "kms" {
						t.Fatalf("invalid native KMS identity %s", native)
					}
					account := parts[4]
					if mapped := v.bindings[account]; mapped != "" {
						account = mapped
					}
					control := ec2.New(ec2.Options{Region: parts[3], BaseEndpoint: aws.String(v.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
					if _, err := control.GetEbsDefaultKmsKeyId(t.Context(), &ec2.GetEbsDefaultKmsKeyIdInput{}); err != nil {
						t.Fatal(err)
					}
					client := v.clients.kmsRegion(parts[3], account, "test", "")
					actual, err := client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: aws.String("alias/aws/ebs")})
					if err != nil {
						t.Fatal(err)
					}
					v.bind(t, native, aws.ToString(actual.KeyMetadata.Arn))
				}
			}
			v.bindManagedKeys(t, row, child)
		}
	case []any:
		for _, child := range node {
			v.bindManagedKeys(t, row, child)
		}
	}
}

func (v *ebsVolumeReplay) advancePhase(t *testing.T, row ebsNativeCall) {
	t.Helper()
	advance := func(at time.Time) {
		if at.After(v.clock.Now()) {
			v.clock.Advance(at.Sub(v.clock.Now()))
		}
	}
	var input struct {
		VolumeID   string
		VolumeIDs  []string
		SnapshotID string
	}
	awsDecodeJSON(t, row.Input, &input)
	if row.Service == "ebs" && row.Code == "ResourceNotFoundException" &&
		(row.Reason == "SNAPSHOT_NOT_FOUND" || row.Error.Reason == "SNAPSHOT_NOT_FOUND") {
		if deleted := v.deletedSnapshots[input.SnapshotID]; !deleted.IsZero() {
			// EC2 deletion precedes bounded direct-plane invisibility. Advance
			// only when a later native read actually observes that phase.
			advance(deleted.Add(ebsdomain.DeletionDelay))
		}
	}
	var output struct {
		Volumes              []ec2types.Volume
		VolumesModifications []struct{ VolumeID, ModificationState string }
		VolumeStatuses       []ec2types.VolumeStatusItem
	}
	if row.Code == "Success" {
		awsDecodeJSON(t, row.Output, &output)
	}
	if row.Operation == "CreateVolume" && row.Code == "Success" {
		var volume ec2types.Volume
		awsDecodeJSON(t, row.Output, &volume)
		if v.volumes[aws.ToString(volume.VolumeId)] != nil {
			// Idempotent admission returns the existing disk's live projection.
			// Its native state/configuration proves the same publication phases
			// as DescribeVolumes, rather than a new creation deadline.
			output.Volumes = []ec2types.Volume{volume}
		}
	}
	if row.Operation == "CreateSnapshot" && row.Code == "Success" {
		if state := v.volumes[input.VolumeID]; state != nil {
			advance(state.created.Add(ebsdomain.VolumeCreationDelay))
			if !state.lastSnapshot.IsZero() {
				advance(state.lastSnapshot.Add(ebsdomain.VolumeSnapshotInterval))
			}
		}
	}
	if row.Operation == "DescribeVolumes" && row.Code == "Success" && len(input.VolumeIDs) == 0 {
		for _, state := range v.volumes {
			if !state.deleted.IsZero() {
				advance(state.deleted.Add(ebsdomain.VolumeDeletionDelay))
			}
		}
	}
	for _, volume := range output.Volumes {
		if state := v.volumes[aws.ToString(volume.VolumeId)]; state != nil && string(volume.State) == "available" {
			advance(state.created.Add(ebsdomain.VolumeCreationDelay))
			if modification := state.modification; modification != nil {
				changed := aws.ToInt32(modification.OriginalSize) != aws.ToInt32(modification.TargetSize) ||
					modification.OriginalVolumeType != modification.TargetVolumeType ||
					aws.ToInt32(modification.OriginalIops) != aws.ToInt32(modification.TargetIops) ||
					aws.ToInt32(modification.OriginalThroughput) != aws.ToInt32(modification.TargetThroughput) ||
					aws.ToBool(modification.OriginalMultiAttachEnabled) != aws.ToBool(modification.TargetMultiAttachEnabled)
				targetObserved := aws.ToInt32(volume.Size) == aws.ToInt32(modification.TargetSize) &&
					volume.VolumeType == modification.TargetVolumeType &&
					aws.ToInt32(volume.Iops) == aws.ToInt32(modification.TargetIops) &&
					aws.ToInt32(volume.Throughput) == aws.ToInt32(modification.TargetThroughput) &&
					aws.ToBool(volume.MultiAttachEnabled) == aws.ToBool(modification.TargetMultiAttachEnabled)
				if changed && targetObserved {
					// Native target settings prove the atomic publication phase;
					// unchanged/no-op projections do not prove worker completion.
					advance(state.modified.Add(ebsdomain.VolumeModificationOptimizingDelay))
				}
			}
		}
	}
	for _, volume := range output.VolumeStatuses {
		state := v.volumes[aws.ToString(volume.VolumeId)]
		if state == nil || volume.VolumeStatus == nil {
			continue
		}
		for _, detail := range volume.VolumeStatus.Details {
			if string(detail.Name) == "initialization-state" && aws.ToString(detail.Status) == "completed" {
				advance(state.created.Add(ebsdomain.VolumeInitializationDelay))
			}
		}
	}
	for _, modification := range output.VolumesModifications {
		if state := v.volumes[modification.VolumeID]; state != nil && !state.modified.IsZero() {
			switch modification.ModificationState {
			case "optimizing":
				advance(state.modified.Add(ebsdomain.VolumeModificationOptimizingDelay))
			case "completed":
				advance(state.modified.Add(ebsdomain.VolumeModificationCompletionDelay))
			}
		}
	}
	if row.Operation == "ModifyVolume" && row.Code == "Success" {
		if state := v.volumes[input.VolumeID]; state != nil {
			advance(state.created.Add(ebsdomain.VolumeCreationDelay))
			if !state.modified.IsZero() {
				advance(state.modified.Add(ebsdomain.VolumeModificationCompletionDelay))
			}
		}
	}
	if row.Code == "InvalidVolume.NotFound" && row.Operation == "DescribeVolumes" {
		for _, id := range input.VolumeIDs {
			if state := v.volumes[id]; state != nil {
				if !state.deleted.IsZero() {
					advance(state.deleted.Add(ebsdomain.VolumeDeletionDelay))
				} else {
					advance(state.created.Add(ebsdomain.VolumeCreationDelay))
				}
			}
		}
	}
}

func (v *ebsVolumeReplay) observe(t *testing.T, row ebsNativeCall, want, got map[string]any) {
	t.Helper()
	var input struct {
		VolumeID   string
		VolumeIDs  []string
		SnapshotID string
	}
	awsDecodeJSON(t, row.Input, &input)
	switch row.Operation {
	case "CreateVolume":
		native, actual := want["VolumeId"].(string), got["VolumeId"].(string)
		if !ebsVolumeIDPattern.MatchString(actual) {
			t.Fatalf("invalid volume ID %q", actual)
		}
		v.bind(t, native, actual)
		if v.volumes[native] == nil {
			v.volumes[native] = &ebsReplayVolume{created: v.clock.Now()}
		}
	case "ModifyVolume":
		v.volumes[input.VolumeID].modified = v.clock.Now()
		var output ec2.ModifyVolumeOutput
		if err := awstest.DecodeSDK(row.Output, &output); err != nil {
			t.Fatal(err)
		}
		if output.VolumeModification == nil {
			t.Fatal("successful native modification has no target configuration")
		}
		v.volumes[input.VolumeID].modification = output.VolumeModification
	case "DeleteVolume":
		if state := v.volumes[input.VolumeID]; state != nil && state.deleted.IsZero() {
			state.deleted = v.clock.Now()
		}
	case "CreateSnapshot":
		if state := v.volumes[input.VolumeID]; state != nil {
			state.lastSnapshot = v.clock.Now()
		}
	case "DeleteSnapshot":
		v.deletedSnapshots[input.SnapshotID] = v.clock.Now()
	}
	if row.Operation == "DescribeVolumeStatus" && len(input.VolumeIDs) == 1 && input.VolumeIDs[0] == "" {
		// Native treats the empty selector as all account volumes. Keep every
		// captured-owned row, not the unrelated ambient disk in that account.
		rows, _ := want["VolumeStatuses"].([]any)
		owned := make([]any, 0, len(rows))
		for _, row := range rows {
			id, _ := row.(map[string]any)["VolumeId"].(string)
			if v.volumes[id] != nil {
				owned = append(owned, row)
			}
		}
		want["VolumeStatuses"] = owned
	}
	if row.ResponsePaginationTokenSHA256 != "" {
		actual, ok := got["NextToken"].(string)
		if !ok || actual == "" {
			t.Fatal("native continuation lost its local page token")
		}
		v.pageTokens[row.ResponsePaginationTokenSHA256] = actual
	}
	v.mapZones(want, v.zones[v.zoneScope(row)])
	v.normalizeVolumeDocument(t, "response", want, got)
}

func (v *ebsVolumeReplay) normalizeVolumeDocument(t *testing.T, path string, want, got any) {
	t.Helper()
	switch before := want.(type) {
	case map[string]any:
		after, ok := got.(map[string]any)
		if !ok {
			return
		}
		id, _ := before["VolumeId"].(string)
		state := v.volumes[id]
		for key, value := range before {
			if value != nil && state != nil && (key == "CreateTime" || key == "StartTime" && before["ModificationState"] != nil || key == "EndTime") {
				actual, ok := after[key].(string)
				when, err := time.Parse(time.RFC3339Nano, actual)
				if !ok || err != nil {
					t.Fatalf("%s.%s invalid lifecycle time %v", path, key, after[key])
				}
				expected := state.created
				if key == "CreateTime" && v.operation == "CreateVolume" {
					expected = expected.Truncate(time.Second)
				} else if key == "StartTime" {
					expected = state.modified.Truncate(time.Second)
				} else if key == "EndTime" {
					expected = state.modified.Add(ebsdomain.VolumeModificationCompletionDelay).Truncate(time.Second)
				}
				if when.Sub(expected).Abs() > time.Millisecond {
					t.Fatalf("%s.%s changed lifecycle identity: %s, expected %s", path, key, when, expected)
				}
				before[key] = actual
			}
			if key == "Volumes" || key == "VolumesModifications" || key == "VolumeStatuses" || key == "Snapshots" {
				identity := "VolumeId"
				if key == "Snapshots" {
					identity = "SnapshotId"
				}
				sortRows := func(value any, native bool) {
					rows, ok := value.([]any)
					if !ok {
						return
					}
					id := func(row any) string {
						document, _ := row.(map[string]any)
						value, _ := document[identity].(string)
						if native && v.bindings[value] != "" {
							return v.bindings[value]
						}
						return value
					}
					slices.SortFunc(rows, func(a, b any) int { return strings.Compare(id(a), id(b)) })
				}
				sortRows(value, true)
				sortRows(after[key], false)
			}
			v.normalizeVolumeDocument(t, path+"."+key, value, after[key])
		}
	case []any:
		after, ok := got.([]any)
		if !ok || len(before) != len(after) {
			return
		}
		for i, value := range before {
			v.normalizeVolumeDocument(t, fmt.Sprintf("%s[%d]", path, i), value, after[i])
		}
	}
}

func (v *ebsVolumeReplay) replayPageChain(t *testing.T, row ebsNativeCall, group string) {
	t.Helper()
	row = v.prepare(t, row)
	v.advancePhase(t, row)
	var input ec2.DescribeVolumesInput
	if err := awstest.DecodeSDK(ec2AuditReplace(t, row.Input, v.bindings), &input); err != nil {
		t.Fatal(err)
	}
	client := func() *ec2.Client {
		return ec2.New(ec2.Options{Region: v.region(row), BaseEndpoint: aws.String(v.clients.server.URL), Credentials: v.provider(t, row.Caller), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
	}
	all := &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{}}
	seen := map[string]bool{}
	for {
		page, err := client().DescribeVolumes(t.Context(), &input)
		if err != nil {
			t.Fatal(err)
		}
		if input.NextToken != nil {
			v.clients = v.reopen()
			replayed, err := client().DescribeVolumes(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			localBindings := map[string]string{}
			for _, local := range v.zones[v.zoneScope(row)] {
				localBindings[local] = local
			}
			ec2NetworkCompare(t, "replayed page", ec2NetworkDocument(t, page), ec2NetworkDocument(t, replayed), localBindings)
		}
		for _, volume := range page.Volumes {
			id := aws.ToString(volume.VolumeId)
			if seen[id] {
				t.Fatalf("page chain repeats volume %s", id)
			}
			seen[id] = true
			all.Volumes = append(all.Volumes, volume)
		}
		if input.NextToken == nil && row.ResponsePaginationTokenSHA256 != "" {
			if aws.ToString(page.NextToken) == "" {
				t.Fatal("bounded owned inventory lost its native continuation")
			}
			v.pageTokens[row.ResponsePaginationTokenSHA256] = aws.ToString(page.NextToken)
		}
		if aws.ToString(page.NextToken) == "" {
			break
		}
		if seen["token:"+aws.ToString(page.NextToken)] {
			t.Fatal("page token did not advance")
		}
		seen["token:"+aws.ToString(page.NextToken)] = true
		input.NextToken = page.NextToken
		v.clients = v.reopen()
	}
	expected := &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{}}
	for _, raw := range v.pageRows[group] {
		var volume ec2types.Volume
		if err := awstest.DecodeSDK(raw, &volume); err != nil {
			t.Fatal(err)
		}
		expected.Volumes = append(expected.Volumes, volume)
	}
	want, got := ec2NetworkDocument(t, expected), ec2NetworkDocument(t, all)
	v.mapZones(want, v.zones[v.zoneScope(row)])
	v.normalizeVolumeDocument(t, "pages", want, got)
	v.normalize(t, "pages", want, got, "")
	ec2NetworkCompare(t, "complete native volume page chain", want, got, v.bindings)
	v.clients = v.reopen()
}

func (v *ebsVolumeReplay) checkIsolationAndTags(t *testing.T, row ebsNativeCall, id string) {
	t.Helper()
	for _, scope := range []struct{ account, region string }{
		{"333333333333", v.region(row)},
		{v.account(row), "us-west-2"},
	} {
		client := ec2.New(ec2.Options{Region: scope.region, BaseEndpoint: aws.String(v.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(scope.account, "test", ""), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
		_, err := client.DescribeVolumes(t.Context(), &ec2.DescribeVolumesInput{VolumeIds: []string{id}})
		assertAPIError(t, err, "InvalidVolume.NotFound")
		_, err = client.DeleteVolume(t.Context(), &ec2.DeleteVolumeInput{VolumeId: aws.String(id)})
		assertAPIError(t, err, "InvalidVolume.NotFound")
		_, err = client.CreateSnapshot(t.Context(), &ec2.CreateSnapshotInput{VolumeId: aws.String(id)})
		assertAPIError(t, err, "InvalidVolume.NotFound")
	}
	client := func() *ec2.Client {
		return ec2.New(ec2.Options{Region: v.region(row), BaseEndpoint: aws.String(v.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(v.account(row), "test", ""), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
	}
	readTags := func() map[string]string {
		output, err := client().DescribeTags(t.Context(), &ec2.DescribeTagsInput{Filters: []ec2types.Filter{{Name: aws.String("resource-id"), Values: []string{id}}}})
		if err != nil {
			t.Fatal(err)
		}
		tags := map[string]string{}
		for _, tag := range output.Tags {
			if aws.ToString(tag.ResourceId) != id || string(tag.ResourceType) != "volume" {
				t.Fatalf("volume tag escaped its owner projection: %+v", tag)
			}
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		return tags
	}
	before := readTags()
	const tagKey = "stackd-replay-retention"
	if _, collision := before[tagKey]; collision {
		t.Fatal("native fixture collides with the retained tag scenario")
	}
	tag := ec2types.Tag{Key: aws.String(tagKey), Value: aws.String("retained")}
	if _, err := client().CreateTags(t.Context(), &ec2.CreateTagsInput{Resources: []string{id}, Tags: []ec2types.Tag{tag}}); err != nil {
		t.Fatal(err)
	}
	v.clients = v.reopen()
	expected := maps.Clone(before)
	expected[tagKey] = "retained"
	if after := readTags(); !maps.Equal(after, expected) {
		t.Fatalf("volume tags were not retained independently: %v, want %v", after, expected)
	}
	if _, err := client().DeleteTags(t.Context(), &ec2.DeleteTagsInput{Resources: []string{id}, Tags: []ec2types.Tag{{Key: tag.Key, Value: aws.String("other")}}}); err != nil {
		t.Fatal(err)
	}
	v.clients = v.reopen()
	if after := readTags(); !maps.Equal(after, expected) {
		t.Fatalf("nonmatching DeleteTags removed retained volume tags: %v", after)
	}
	if _, err := client().DeleteTags(t.Context(), &ec2.DeleteTagsInput{Resources: []string{id}, Tags: []ec2types.Tag{tag}}); err != nil {
		t.Fatal(err)
	}
	v.clients = v.reopen()
	if after := readTags(); !maps.Equal(after, before) {
		t.Fatalf("DeleteTags did not restore the original volume tags: %v, want %v", after, before)
	}
}
