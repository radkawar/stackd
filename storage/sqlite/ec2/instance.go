package ec2

import (
	"database/sql"
	"errors"
	"time"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func instanceTime(v time.Time) sql.NullTime {
	if v.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: v.UTC(), Valid: true}
}

func instanceDateTime(v *api.DateTime) sql.NullTime {
	if v == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: time.Time(*v).UTC(), Valid: true}
}

func instanceDateTimePointer(v sql.NullTime) *api.DateTime {
	if !v.Valid {
		return nil
	}
	return new(api.DateTime(v.Time))
}

func (r reader) Instance(k domain.ResourceKey) (domain.InstanceRecord, error) {
	row, err := r.q.GetInstance(r.ctx, sqlcgen.GetInstanceParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.InstanceRecord{}, missing(err)
	}
	return r.instance(row)
}

func (r reader) Instances(scope domain.Scope) ([]domain.InstanceRecord, error) {
	rows, err := r.q.ListInstances(r.ctx, sqlcgen.ListInstancesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.instanceRows(rows)
}

func (r reader) PreparedInstances() ([]domain.InstanceRecord, error) {
	rows, err := r.q.PreparedInstances(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.instanceRows(rows)
}

func (r reader) PendingInstances(deadline time.Time) ([]domain.InstanceRecord, error) {
	rows, err := r.q.PendingInstances(r.ctx, sql.NullTime{Time: deadline.UTC(), Valid: true})
	if err != nil {
		return nil, err
	}
	return r.instanceRows(rows)
}

func (r reader) NextInstanceDeadline() (time.Time, bool, error) {
	due, err := r.q.NextInstanceDeadline(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return due.Time, due.Valid, nil
}

func (r reader) instanceRows(rows []sqlcgen.Ec2Instance) ([]domain.InstanceRecord, error) {
	out := make([]domain.InstanceRecord, 0, len(rows))
	for _, row := range rows {
		record, err := r.instance(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (r reader) instance(row sqlcgen.Ec2Instance) (domain.InstanceRecord, error) {
	out := domain.InstanceRecord{
		Key:           domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID},
		ReservationID: row.ReservationID, UserData: row.UserData, MetadataTokenKey: row.MetadataTokenKey, PublicKey: row.PublicKey,
		LambdaCapacityProviderARN: row.LambdaCapacityProviderArn, LambdaManagedGeneration: row.LambdaManagedGeneration,
		IdentityCredentials:     domain.InstanceCredentialReferences{V1: row.IdentityCredentialIDV1, V2: row.IdentityCredentialIDV2},
		IdentityInfoLastUpdated: row.IdentityInfoLastUpdated.Time,
		ShutdownBehavior:        row.ShutdownBehavior, DisableAPIStop: row.DisableApiStop, DisableAPITermination: row.DisableApiTermination,
		Intent: domain.InstanceIntent(row.Intent), Generation: uint64(row.Generation), RuntimePrepared: row.RuntimePrepared, EffectStarted: row.EffectStarted, Force: row.Force,
		NextActionAt: row.NextActionAt.Time, ShutdownDeadline: row.ShutdownDeadline.Time, CommandID: row.CommandID, CausationID: row.CausationID,
		Console: row.Console, ConsoleOffset: row.ConsoleOffset, ConsoleAt: row.ConsoleAt.Time,
		Credits: domain.InstanceCreditRecord{Mode: row.CreditMode, Earned: time.Duration(row.CreditEarned), Launch: time.Duration(row.CreditLaunch), Surplus: time.Duration(row.CreditSurplus), Excess: time.Duration(row.CreditExcess), Usage: time.Duration(row.CreditUsage), MetricUsage: time.Duration(row.CreditMetricUsage), MetricCharged: time.Duration(row.CreditMetricCharged), MetricPeriodEnd: row.CreditMetricPeriodEnd.Time, UpdatedAt: row.CreditUpdatedAt.Time, StoppedAt: row.CreditStoppedAt.Time, HourEnd: row.CreditHourEnd.Time, NativePID: int(row.CreditNativePid), NativeStartTimeTicks: uint64(row.CreditNativeStartTimeTicks)},
		Performance: domain.InstancePerformanceRecord{
			NativePID: int(row.PerformanceNativePid), NativeStartTimeTicks: uint64(row.PerformanceNativeStartTimeTicks),
			InterfaceIndex: int(row.PerformanceInterfaceIndex), CPUUsage: time.Duration(row.PerformanceCpuUsage),
			BytesIn: uint64(row.PerformanceBytesIn), BytesOut: uint64(row.PerformanceBytesOut),
			ObservedAt: row.PerformanceObservedAt.Time, SampleAt: row.PerformanceSampleAt.Time,
			WindowAt: row.PerformanceWindowAt.Time, Detailed: row.PerformanceDetailed,
			InstancePerformanceStatistics: domain.InstancePerformanceStatistics{
				CPUCount: row.PerformanceCpuCount, CPUSum: row.PerformanceCpuSum, CPUMin: row.PerformanceCpuMin, CPUMax: row.PerformanceCpuMax,
				NetworkIn: uint64(row.PerformanceNetworkIn), NetworkOut: uint64(row.PerformanceNetworkOut), NetworkObserved: row.PerformanceNetworkObserved,
			},
		},
		Data: api.Instance{
			AmiLaunchIndex: integerPointer[api.Integer](row.AmiLaunchIndex), Architecture: stringPointer[api.ArchitectureValues](row.Architecture), BootMode: stringPointer[api.BootModeValues](row.BootMode), ClientToken: stringPointer[api.String](row.ClientToken),
			CurrentInstanceBootMode: stringPointer[api.InstanceBootModeValues](row.CurrentInstanceBootMode), EbsOptimized: boolPointer[api.Boolean](row.EbsOptimized), EnaSupport: boolPointer[api.Boolean](row.EnaSupport),
			ImageId: stringPointer[api.String](row.ImageID), InstanceId: stringPointer[api.String](row.InstanceID), InstanceType: stringPointer[api.InstanceType](row.InstanceType), KeyName: stringPointer[api.String](row.KeyName), LaunchTime: instanceDateTimePointer(row.LaunchTime),
			PrivateDnsName: stringPointer[api.String](row.PrivateDnsName), PrivateIpAddress: stringPointer[api.String](row.PrivateIpAddress), RootDeviceName: stringPointer[api.String](row.RootDeviceName), RootDeviceType: stringPointer[api.DeviceType](row.RootDeviceType), SourceDestCheck: boolPointer[api.Boolean](row.SourceDestCheck),
			StateTransitionReason: stringPointer[api.String](row.StateTransitionReason), SubnetId: stringPointer[api.String](row.SubnetID), VirtualizationType: stringPointer[api.VirtualizationType](row.VirtualizationType), VpcId: stringPointer[api.String](row.VpcID),
		},
	}
	out.Health.UpdatedAt = row.HealthUpdatedAt.Time
	out.Health.System.Status, out.Health.System.ImpairedSince = api.StatusType(row.SystemCheckStatus), row.SystemImpairedSince.Time
	out.Health.Guest.Status, out.Health.Guest.ImpairedSince = api.StatusType(row.GuestCheckStatus), row.GuestImpairedSince.Time
	out.Health.AttachedEBS.Status, out.Health.AttachedEBS.ImpairedSince = api.StatusType(row.EbsCheckStatus), row.EbsImpairedSince.Time
	out.Health.HibernationReady = row.HibernationReady
	d := &out.Data
	if out.LambdaCapacityProviderARN != "" {
		d.Operator = &api.OperatorResponse{Managed: new(api.Boolean(true)), HiddenByDefault: new(api.Boolean(false)), Principal: new(api.String("scaler.lambda.amazonaws.com"))}
	}
	if row.HibernationConfigured.Valid {
		d.HibernationOptions = &api.HibernationOptions{Configured: boolPointer[api.Boolean](row.HibernationConfigured)}
	}
	if err := unmarshalFields(jsonReadField{row.CpuOptions, &d.CpuOptions}, jsonReadField{row.IamInstanceProfile, &d.IamInstanceProfile}, jsonReadField{row.MetadataOptions, &d.MetadataOptions}, jsonReadField{row.Monitoring, &d.Monitoring}, jsonReadField{row.Placement, &d.Placement}, jsonReadField{row.State, &d.State}, jsonReadField{row.StateReason, &d.StateReason}); err != nil {
		return out, err
	}
	if err := r.instancePerformanceGroups(&out); err != nil {
		return out, err
	}
	if err := r.instanceChildren(row, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (w writer) PutInstance(v domain.InstanceRecord) error {
	k, d, c, m := v.Key, &v.Data, &v.Credits, &v.Performance
	p := sqlcgen.PutInstanceParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		ReservationID: v.ReservationID, UserData: v.UserData, MetadataTokenKey: v.MetadataTokenKey, PublicKey: v.PublicKey,
		LambdaCapacityProviderArn: v.LambdaCapacityProviderARN, LambdaManagedGeneration: v.LambdaManagedGeneration,
		IdentityCredentialIDV1:  v.IdentityCredentials.V1,
		IdentityCredentialIDV2:  v.IdentityCredentials.V2,
		IdentityInfoLastUpdated: instanceTime(v.IdentityInfoLastUpdated),
		ShutdownBehavior:        v.ShutdownBehavior, DisableApiStop: v.DisableAPIStop, DisableApiTermination: v.DisableAPITermination,
		Intent: string(v.Intent), Generation: sqlite.Uint64(v.Generation), RuntimePrepared: v.RuntimePrepared, EffectStarted: v.EffectStarted, Force: v.Force,
		NextActionAt: instanceTime(v.NextActionAt), ShutdownDeadline: instanceTime(v.ShutdownDeadline), CommandID: v.CommandID, CausationID: v.CausationID,
		Console: v.Console, ConsoleOffset: v.ConsoleOffset, ConsoleAt: instanceTime(v.ConsoleAt),
		HealthUpdatedAt:   instanceTime(v.Health.UpdatedAt),
		HibernationReady:  v.Health.HibernationReady,
		SystemCheckStatus: string(v.Health.System.Status), SystemImpairedSince: instanceTime(v.Health.System.ImpairedSince),
		GuestCheckStatus: string(v.Health.Guest.Status), GuestImpairedSince: instanceTime(v.Health.Guest.ImpairedSince),
		EbsCheckStatus: string(v.Health.AttachedEBS.Status), EbsImpairedSince: instanceTime(v.Health.AttachedEBS.ImpairedSince),
		CreditMode: c.Mode, CreditEarned: int64(c.Earned), CreditLaunch: int64(c.Launch), CreditSurplus: int64(c.Surplus), CreditExcess: int64(c.Excess), CreditUsage: int64(c.Usage), CreditUpdatedAt: instanceTime(c.UpdatedAt), CreditStoppedAt: instanceTime(c.StoppedAt), CreditHourEnd: instanceTime(c.HourEnd), CreditNativePid: int64(c.NativePID), CreditNativeStartTimeTicks: sqlite.Uint64(c.NativeStartTimeTicks),
		CreditMetricUsage: int64(c.MetricUsage), CreditMetricCharged: int64(c.MetricCharged), CreditMetricPeriodEnd: instanceTime(c.MetricPeriodEnd),
		PerformanceNativePid: int64(m.NativePID), PerformanceNativeStartTimeTicks: sqlite.Uint64(m.NativeStartTimeTicks),
		PerformanceInterfaceIndex: int64(m.InterfaceIndex), PerformanceCpuUsage: int64(m.CPUUsage),
		PerformanceBytesIn: sqlite.Uint64(m.BytesIn), PerformanceBytesOut: sqlite.Uint64(m.BytesOut),
		PerformanceObservedAt: instanceTime(m.ObservedAt), PerformanceSampleAt: instanceTime(m.SampleAt),
		PerformanceWindowAt: instanceTime(m.WindowAt), PerformanceDetailed: m.Detailed,
		PerformanceCpuCount: m.CPUCount, PerformanceCpuSum: m.CPUSum, PerformanceCpuMin: m.CPUMin, PerformanceCpuMax: m.CPUMax,
		PerformanceNetworkIn: sqlite.Uint64(m.NetworkIn), PerformanceNetworkOut: sqlite.Uint64(m.NetworkOut), PerformanceNetworkObserved: m.NetworkObserved,
		AmiLaunchIndex: nullableInteger(d.AmiLaunchIndex), Architecture: nullableString(d.Architecture), BootMode: nullableString(d.BootMode), ClientToken: nullableString(d.ClientToken),
		CurrentInstanceBootMode: nullableString(d.CurrentInstanceBootMode), EbsOptimized: nullableBool(d.EbsOptimized), EnaSupport: nullableBool(d.EnaSupport),
		ImageID: nullableString(d.ImageId), InstanceID: nullableString(d.InstanceId), InstanceType: nullableString(d.InstanceType), KeyName: nullableString(d.KeyName), LaunchTime: instanceDateTime(d.LaunchTime),
		PrivateDnsName: nullableString(d.PrivateDnsName), PrivateIpAddress: nullableString(d.PrivateIpAddress), RootDeviceName: nullableString(d.RootDeviceName), RootDeviceType: nullableString(d.RootDeviceType), SourceDestCheck: nullableBool(d.SourceDestCheck),
		StateTransitionReason: nullableString(d.StateTransitionReason), SubnetID: nullableString(d.SubnetId), VirtualizationType: nullableString(d.VirtualizationType), VpcID: nullableString(d.VpcId),
		MappingsPresent: d.BlockDeviceMappings != nil, NetworksPresent: d.NetworkInterfaces != nil, GroupsPresent: d.SecurityGroups != nil, TagsPresent: d.Tags != nil,
	}
	if d.HibernationOptions != nil {
		p.HibernationConfigured = nullableBool(d.HibernationOptions.Configured)
	}
	if err := marshalFields(jsonWriteField{&p.CpuOptions, d.CpuOptions}, jsonWriteField{&p.IamInstanceProfile, d.IamInstanceProfile}, jsonWriteField{&p.MetadataOptions, d.MetadataOptions}, jsonWriteField{&p.Monitoring, d.Monitoring}, jsonWriteField{&p.Placement, d.Placement}, jsonWriteField{&p.State, d.State}, jsonWriteField{&p.StateReason, d.StateReason}); err != nil {
		return err
	}
	if err := w.q.PutInstance(w.ctx, p); err != nil {
		return err
	}
	if err := w.putInstancePerformanceGroups(v); err != nil {
		return err
	}
	return w.putInstanceChildren(v)
}
