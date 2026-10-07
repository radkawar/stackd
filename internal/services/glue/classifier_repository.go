package glue

import api "stackd/internal/awsapi/glue"

type ClassifierRecord struct {
	CFNOwner   string
	Key        ResourceKey
	Classifier api.Classifier
}
