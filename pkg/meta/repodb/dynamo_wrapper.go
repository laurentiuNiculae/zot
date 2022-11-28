package repodb

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	godigest "github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
)

type DynamoDBWrapper struct {
	client *dynamodb.Client
	log    log.Logger
}

type DynamoDBDriverParameters struct {
	Endpoint, Region string
}

func NewDynamoDBWrapper(params DynamoDBDriverParameters) (*DynamoDBWrapper, error) {
	// custom endpoint resolver to point to localhost
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           params.Endpoint,
				SigningRegion: region,
			}, nil
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(params.Region),
		config.WithEndpointResolverWithOptions(customResolver))
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &DynamoDBWrapper{
		client: dynamodb.NewFromConfig(cfg),
		log:    log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (dwr DynamoDBWrapper) SetRepoDescription(repo, description string) error {
	return nil
}

func (dwr DynamoDBWrapper) IncrementRepoStars(repo string) error {
	return nil
}

func (dwr DynamoDBWrapper) DecrementRepoStars(repo string) error {
	return nil
}

func (dwr DynamoDBWrapper) GetRepoStars(repo string) (int, error) {
	return 0, nil
}

func (dwr DynamoDBWrapper) SetRepoLogo(repo string, logoPath string) error {
	return nil
}

func (dwr DynamoDBWrapper) SetRepoTag(repo string, tag string, manifestDigest godigest.Digest) error {
	if err := validateRepoTagInput(repo, tag, manifestDigest); err != nil {
		return err
	}

	resp, err := dwr.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String("RepoMetadataTable"),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return err
	}

	repoMeta := RepoMetadata{
		Name: repo,
		Tags: map[string]string{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	repoMeta.Tags[tag] = manifestDigest.String()

	repoAttributeValue, err := attributevalue.Marshal(repoMeta)
	if err != nil {
		return err
	}

	_, err = dwr.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMetadata": repoAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String("RepoMetadataTable"),
		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
	})

	return err
}

func (dwr DynamoDBWrapper) DeleteRepoTag(repo string, tag string) error {
	resp, err := dwr.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String("RepoMetadataTable"),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return err
	}

	if resp.Item == nil {
		return nil
	}

	var repoMeta RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return err
	}

	delete(repoMeta.Tags, tag)

	repoAttributeValue, err := attributevalue.Marshal(repoMeta)
	if err != nil {
		return err
	}

	_, err = dwr.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMetadata": repoAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String("RepoMetadataTable"),
		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
	})

	return err
}

func (dwr DynamoDBWrapper) GetRepoMeta(repo string) (RepoMetadata, error) {
	resp, err := dwr.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String("RepoMetadataTable"),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return RepoMetadata{}, err
	}

	if resp.Item == nil {
		return RepoMetadata{}, zerr.ErrRepoMetaNotFound
	}

	var repoMeta RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return RepoMetadata{}, err
	}

	return repoMeta, nil
}

func (dwr DynamoDBWrapper) GetManifestMeta(manifestDigest godigest.Digest) (ManifestMetadata, error) {
	resp, err := dwr.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String("ManifestMetadataTable"),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: manifestDigest.String()},
		},
	})
	if err != nil {
		return ManifestMetadata{}, err
	}

	if resp.Item == nil {
		return ManifestMetadata{}, zerr.ErrManifestMetaNotFound
	}

	var manifestMetadata ManifestMetadata

	err = attributevalue.Unmarshal(resp.Item["ManifestMetadata"], &manifestMetadata)
	if err != nil {
		return ManifestMetadata{}, err
	}

	return manifestMetadata, nil
}

func (dwr DynamoDBWrapper) SetManifestMeta(manifestDigest godigest.Digest, mm ManifestMetadata) error {
	mmAttributeValue, err := attributevalue.Marshal(mm)
	if err != nil {
		return err
	}

	_, err = dwr.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#MM": "ManifestMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ManifestMetadata": mmAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{
				Value: manifestDigest.String(),
			},
		},
		TableName:        aws.String("ManifestMetadataTable"),
		UpdateExpression: aws.String("SET #MM = :ManifestMetadata"),
	})

	return err
}

func (dwr DynamoDBWrapper) IncrementManifestDownloads(manifestDigest godigest.Digest) error {
	return nil
}

func (dwr DynamoDBWrapper) AddManifestSignature(manifestDigest godigest.Digest, sm SignatureMetadata) error {
	return nil
}

func (dwr DynamoDBWrapper) DeleteSignature(manifestDigest godigest.Digest, sm SignatureMetadata) error {
	return nil
}

func (dwr DynamoDBWrapper) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta RepoMetadata) bool, requestedPage PageInput,
) ([]RepoMetadata, error) {
	return []RepoMetadata{}, nil
}

func (dwr DynamoDBWrapper) SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	return []RepoMetadata{}, map[string]ManifestMetadata{}, nil
}

func (dwr DynamoDBWrapper) SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	return []RepoMetadata{}, map[string]ManifestMetadata{}, nil
}

func (dwr DynamoDBWrapper) SearchDigests(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	return []RepoMetadata{}, map[string]ManifestMetadata{}, nil
}

func (dwr DynamoDBWrapper) SearchLayers(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	return []RepoMetadata{}, map[string]ManifestMetadata{}, nil
}

func (dwr DynamoDBWrapper) SearchForAscendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	return []RepoMetadata{}, map[string]ManifestMetadata{}, nil
}

func (dwr DynamoDBWrapper) SearchForDescendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	return []RepoMetadata{}, map[string]ManifestMetadata{}, nil
}
