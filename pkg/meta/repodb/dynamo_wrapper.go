package repodb

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
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

type dynamoAttributesIterator struct {
	Client    *dynamodb.Client
	Table     string
	Attribute string

	itemBuffer       []map[string]types.AttributeValue
	currentItemIndex int
	lastEvaluatedKey map[string]types.AttributeValue

	log log.Logger
}

func newDynamoAttributesIterator(client *dynamodb.Client, table, attribute string, log log.Logger,
) dynamoAttributesIterator {
	return dynamoAttributesIterator{
		Client:           client,
		Table:            table,
		Attribute:        attribute,
		itemBuffer:       []map[string]types.AttributeValue{},
		currentItemIndex: 0,
		log:              log,
	}
}

func (dii *dynamoAttributesIterator) First(ctx context.Context) (types.AttributeValue, error) {
	scanOutput, err := dii.Client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(dii.Table),
	})
	if err != nil {
		return nil, err
	}

	if len(scanOutput.Items) == 0 {
		return nil, nil
	}

	dii.itemBuffer = scanOutput.Items
	dii.lastEvaluatedKey = scanOutput.LastEvaluatedKey
	dii.currentItemIndex = 1

	return dii.itemBuffer[0][dii.Attribute], nil
}

func (dii *dynamoAttributesIterator) Next(ctx context.Context) (types.AttributeValue, error) {
	if len(dii.itemBuffer) <= dii.currentItemIndex {
		if dii.lastEvaluatedKey == nil {
			return nil, nil
		}

		scanOutput, err := dii.Client.Scan(ctx, &dynamodb.ScanInput{
			TableName:         aws.String(dii.Table),
			ExclusiveStartKey: dii.lastEvaluatedKey,
		})
		if err != nil {
			return nil, err
		}

		// all items have been scanned
		if len(scanOutput.Items) == 0 {
			return nil, nil
		}

		dii.itemBuffer = scanOutput.Items
		dii.lastEvaluatedKey = scanOutput.LastEvaluatedKey
		dii.currentItemIndex = 0
	}

	nextItem := dii.itemBuffer[dii.currentItemIndex][dii.Attribute]
	dii.currentItemIndex++

	return nextItem, nil
}

func (dwr DynamoDBWrapper) SetRepoDescription(repo, description string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.Description = description

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DynamoDBWrapper) IncrementRepoStars(repo string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.Stars++

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DynamoDBWrapper) DecrementRepoStars(repo string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	if repoMeta.Stars > 0 {
		repoMeta.Stars--
	}

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DynamoDBWrapper) GetRepoStars(repo string) (int, error) {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return 0, err
	}

	return repoMeta.Stars, nil
}

func (dwr DynamoDBWrapper) SetRepoLogo(repo string, logoPath string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.LogoPath = logoPath

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
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

	err = dwr.setRepoMeta(repo, repoMeta)

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

	if len(repoMeta.Tags) == 0 {
		_, err := dwr.client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
			TableName: aws.String("RepoMetadataTable"),
			Key: map[string]types.AttributeValue{
				"RepoName": &types.AttributeValueMemberS{Value: repo},
			},
		})

		return err
	}

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

func (dwr DynamoDBWrapper) GetManifestMeta(manifestDigest godigest.Digest,
) (ManifestMetadata, error) { //nolint:contextcheck
	resp, err := dwr.client.GetItem(context.Background(), &dynamodb.GetItemInput{
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

func (dwr DynamoDBWrapper) SetManifestMeta(manifestDigest godigest.Digest, manifestMeta ManifestMetadata) error {
	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = map[string][]string{}
	}

	mmAttributeValue, err := attributevalue.Marshal(manifestMeta)
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
	manifestMeta, err := dwr.GetManifestMeta(manifestDigest)
	if err != nil {
		return err
	}

	manifestMeta.DownloadCount++

	err = dwr.SetManifestMeta(manifestDigest, manifestMeta)

	return err
}

func (dwr DynamoDBWrapper) AddManifestSignature(manifestDigest godigest.Digest, sigMeta SignatureMetadata) error {
	manifestMeta, err := dwr.GetManifestMeta(manifestDigest)
	if err != nil {
		return err
	}

	manifestMeta.Signatures[sigMeta.SignatureType] = append(manifestMeta.Signatures[sigMeta.SignatureType],
		sigMeta.SignatureDigest.String())

	err = dwr.SetManifestMeta(manifestDigest, manifestMeta)

	return err
}

func (dwr DynamoDBWrapper) DeleteSignature(manifestDigest godigest.Digest, sigMeta SignatureMetadata) error {
	manifestMeta, err := dwr.GetManifestMeta(manifestDigest)
	if err != nil {
		return err
	}

	sigType := sigMeta.SignatureType

	for i, sig := range manifestMeta.Signatures[sigType] {
		if sig == sigMeta.SignatureDigest.String() {
			signaturesCount := len(manifestMeta.Signatures[sigType])

			if signaturesCount < 1 {
				manifestMeta.Signatures[sigType] = []string{}

				return nil
			}

			// put element to be deleted at the end of the array
			manifestMeta.Signatures[sigType][i] = manifestMeta.Signatures[sigType][signaturesCount-1]

			// trim the last element
			manifestMeta.Signatures[sigType] = manifestMeta.Signatures[sigType][:signaturesCount-1]

			err := dwr.SetManifestMeta(manifestDigest, manifestMeta)

			return err
		}
	}

	return nil
}

func (dwr DynamoDBWrapper) GetMultipleRepoMeta(ctx context.Context,
	filter func(repoMeta RepoMetadata) bool, requestedPage PageInput,
) ([]RepoMetadata, error) {
	var (
		repoMetaAttributeIterator = newDynamoAttributesIterator(
			dwr.client, "RepoMetadataTable", "RepoMetadata", dwr.log,
		)

		pageFinder PageFinder
	)

	pageFinder, err := NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []RepoMetadata{}, err
		}

		var repoMeta RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []RepoMetadata{}, err
		}

		if ok, err := repoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if filter(repoMeta) {
			pageFinder.Add(DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}
	}

	foundRepos := pageFinder.Page()

	return foundRepos, err
}

func (dwr DynamoDBWrapper) SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	var (
		foundManifestMetadataMap = make(map[string]ManifestMetadata)
		manifestMetadataMap      = make(map[string]ManifestMetadata)
		pageFinder               PageFinder

		repoMetaAttributeIterator = newDynamoAttributesIterator(
			dwr.client, "RepoMetadataTable", "RepoMetadata", dwr.log,
		)
	)

	pageFinder, err := NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []RepoMetadata{}, map[string]ManifestMetadata{}, err
		}

		var repoMeta RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []RepoMetadata{}, map[string]ManifestMetadata{}, err
		}

		if ok, err := repoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if score := ScoreRepoName(searchText, repoMeta.Name); score != -1 {
			var (
				// specific values used for sorting that need to be calculated based on all manifests from the repo
				repoDownloads     = 0
				repoLastUpdated   time.Time
				firstImageChecked = true
				osSet             = map[string]bool{}
				archSet           = map[string]bool{}
				isSigned          = false
			)

			for _, manifestDigest := range repoMeta.Tags {
				var manifestMeta ManifestMetadata

				manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

				if !manifestDownloaded {
					manifestMeta, err = dwr.GetManifestMeta(godigest.Digest(manifestDigest)) //nolint:contextcheck
					if err != nil {
						return []RepoMetadata{}, map[string]ManifestMetadata{},
							errors.Wrapf(err, "repodb: error while getting manifest metadata for digest %s", manifestDigest)
					}
				}

				// get fields related to filtering
				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return []RepoMetadata{}, map[string]ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmarshaling config content for digest %s", manifestDigest)
				}

				osSet[configContent.OS] = true
				archSet[configContent.Architecture] = true

				// get fields related to sorting
				repoDownloads += manifestMeta.DownloadCount

				imageLastUpdated, err := getImageLastUpdatedTimestamp(manifestMeta.ConfigBlob)
				if err != nil {
					return []RepoMetadata{}, map[string]ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmarshaling image config referenced by digest %s", manifestDigest)
				}

				if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
					repoLastUpdated = imageLastUpdated
					firstImageChecked = false

					isSigned = checkIsSigned(manifestMeta.Signatures)
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			repoFilterData := filterData{
				OsList:   getMapKeys(osSet),
				ArchList: getMapKeys(archSet),
				IsSigned: isSigned,
			}

			if !acceptedByFilter(filter, repoFilterData) {
				continue
			}

			pageFinder.Add(DetailedRepoMeta{
				RepoMeta:   repoMeta,
				Score:      score,
				Downloads:  repoDownloads,
				UpdateTime: repoLastUpdated,
			})
		}
	}

	foundRepos := pageFinder.Page()

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, manifestDigest := range repoMeta.Tags {
			foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
		}
	}

	return foundRepos, foundManifestMetadataMap, err
}

func (dwr DynamoDBWrapper) SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	var (
		foundManifestMetadataMap  = make(map[string]ManifestMetadata)
		manifestMetadataMap       = make(map[string]ManifestMetadata)
		repoMetaAttributeIterator = newDynamoAttributesIterator(
			dwr.client, "RepoMetadataTable", "RepoMetadata", dwr.log,
		)

		pageFinder PageFinder
	)

	pageFinder, err := NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, err
	}

	searchedRepo, searchedTag, err := getRepoTag(searchText)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{},
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []RepoMetadata{}, map[string]ManifestMetadata{}, err
		}

		var repoMeta RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []RepoMetadata{}, map[string]ManifestMetadata{}, err
		}

		if ok, err := repoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if repoMeta.Name == searchedRepo {
			matchedTags := make(map[string]string)
			// take all manifestMetas
			for tag, manifestDigest := range repoMeta.Tags {
				if !strings.HasPrefix(tag, searchedTag) {
					continue
				}

				matchedTags[tag] = manifestDigest

				// in case tags reference the same manifest we don't download from DB multiple times
				if manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]; manifestExists {
					manifestMetadataMap[manifestDigest] = manifestMeta

					continue
				}

				manifestMeta, err := dwr.GetManifestMeta(godigest.Digest(manifestDigest)) //nolint:contextcheck
				if err != nil {
					return []RepoMetadata{}, map[string]ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return []RepoMetadata{}, map[string]ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				imageFilterData := filterData{
					OsList:   []string{configContent.OS},
					ArchList: []string{configContent.Architecture},
					IsSigned: false,
				}

				if !acceptedByFilter(filter, imageFilterData) {
					delete(matchedTags, tag)
					delete(manifestMetadataMap, manifestDigest)

					continue
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}
	}

	foundRepos := pageFinder.Page()

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, manifestDigest := range repoMeta.Tags {
			foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
		}
	}

	return foundRepos, foundManifestMetadataMap, err
}

func (dwr DynamoDBWrapper) setRepoMeta(repo string, repoMeta RepoMetadata) error {
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

func (dwr DynamoDBWrapper) createRepoMetaTable() error {
	_, err := dwr.client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String("RepoMetadataTable"),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("RepoName"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("RepoName"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	return err
}

func (dwr DynamoDBWrapper) deleteRepoMetaTable() error {
	_, err := dwr.client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String("RepoMetadataTable"),
	})

	return err
}

func (dwr DynamoDBWrapper) ResetRepoMetaTable() error {
	err := dwr.deleteRepoMetaTable()
	if err != nil {
		return err
	}

	return dwr.createRepoMetaTable()
}

func (dwr DynamoDBWrapper) createManifestMetaTable() error {
	_, err := dwr.client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String("ManifestMetadataTable"),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("Digest"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("Digest"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	return err
}

func (dwr DynamoDBWrapper) deleteManifestMetaTable() error {
	_, err := dwr.client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String("ManifestMetadataTable"),
	})

	return err
}

func (dwr DynamoDBWrapper) ResetManifestMetaTable() error {
	err := dwr.deleteManifestMetaTable()
	if err != nil {
		return err
	}

	return dwr.createManifestMetaTable()
}

func (dwr DynamoDBWrapper) SearchDigests(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (dwr DynamoDBWrapper) SearchLayers(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (dwr DynamoDBWrapper) SearchForAscendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (dwr DynamoDBWrapper) SearchForDescendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}
