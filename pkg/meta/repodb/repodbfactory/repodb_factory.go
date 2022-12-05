package repodbfactory

import (
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/meta/repodb"
)

func Create(dbtype string, parameters interface{}) (repodb.RepoDB, error) {
	switch dbtype {
	case "boltdb":
		{
			properParameters, ok := parameters.(repodb.BoltDBParameters)
			if !ok {
				panic("failed type assertion")
			}

			return repodb.NewBoltDBWrapper(properParameters)
		}
	case "dynamodb":
		{
			properParameters, ok := parameters.(repodb.DynamoDBDriverParameters)
			if !ok {
				panic("failed type assertion")
			}

			return repodb.NewDynamoDBWrapper(properParameters)
		}
	default:
		{
			return nil, errors.ErrBadConfig
		}
	}
}
