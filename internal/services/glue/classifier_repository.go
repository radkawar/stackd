package glue

import api "stackd/internal/awsapi/glue"

type ClassifierRecord struct {
	Key        ResourceKey
	Classifier api.Classifier
}
