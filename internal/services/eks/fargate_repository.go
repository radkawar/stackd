package eks

import (
	native "stackd/compute/eks"
	"time"
)

type FargateProfile struct {
	Key                                                                           Key
	Name, ID, RoleARN, RoleID, Status, Operation, Error, ClientToken, RequestHash string
	Selectors                                                                     []native.FargateSelector
	Subnets                                                                       []string
	Tags                                                                          map[string]string
	Created, Due                                                                  time.Time
	Generation                                                                    int64
}

func (p FargateProfile) ARN() string {
	return "arn:" + p.Key.Partition + ":eks:" + p.Key.Region + ":" + p.Key.AccountID + ":fargateprofile/" + p.Key.Name + "/" + p.Name + "/" + p.ID
}

type FargateReader interface {
	FargateProfile(Key, string) (FargateProfile, error)
	FargateProfiles(Key) ([]FargateProfile, error)
}
type FargateTransaction interface {
	FargateReader
	PutFargateProfile(FargateProfile) error
	DeleteFargateProfile(Key, string) error
}
