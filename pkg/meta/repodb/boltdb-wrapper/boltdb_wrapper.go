package bolt

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/meta/repodb/common"
	"zotregistry.io/zot/pkg/meta/repodb/version"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

type DBParameters struct {
	RootDir string
}

type DBWrapper struct {
	DB      *bolt.DB
	Patches []func(DB *bolt.DB) error
	Log     log.Logger
}

func NewBoltDBWrapper(params DBParameters) (*DBWrapper, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "repo.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	err = boltDB.Update(func(transaction *bolt.Tx) error {
		versionBuck, err := transaction.CreateBucketIfNotExists([]byte(repodb.VersionBucket))
		if err != nil {
			return err
		}

		err = versionBuck.Put([]byte(version.DBVersionKey), []byte(version.CurrentVersion))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(repodb.ManifestDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(repodb.IndexDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(repodb.RepoMetadataBucket))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &DBWrapper{
		DB:      boltDB,
		Patches: version.GetBoltDBPatches(),
		Log:     log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (bdw DBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData repodb.ManifestData) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestDataBucket))

		mdBlob, err := json.Marshal(manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", manifestDigest)
		}

		err = buck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest data with for digest %s", manifestDigest)
		}

		return nil
	})

	return err
}

func (bdw DBWrapper) GetManifestData(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
	var manifestData repodb.ManifestData

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestDataBucket))

		mdBlob := buck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestDataNotFound
		}

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
		}

		return nil
	})

	return manifestData, err
}

func (bdw DBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta repodb.ManifestMetadata,
) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMeta := repodb.RepoMetadata{
			Name:       repo,
			Tags:       map[string]repodb.Descriptor{},
			Statistics: map[string]repodb.DescriptorStatistics{},
			Signatures: map[string]repodb.ManifestSignatures{},
		}

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}
		}

		mdBlob, err := json.Marshal(repodb.ManifestData{
			ManifestBlob: manifestMeta.ManifestBlob,
			ConfigBlob:   manifestMeta.ConfigBlob,
		})
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", manifestDigest)
		}

		err = dataBuck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest meta with for digest %s", manifestDigest)
		}

		updatedRepoMeta := common.UpdateManifestMeta(repoMeta, manifestDigest, manifestMeta)

		updatedRepoMetaBlob, err := json.Marshal(updatedRepoMeta)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for updated repo meta '%s'", repo)
		}

		return repoBuck.Put([]byte(repo), updatedRepoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
	var manifestMetadata repodb.ManifestMetadata

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		mdBlob := dataBuck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestData repodb.ManifestData

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
		}

		var repoMeta repodb.RepoMetadata

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err = json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
			}
		}

		manifestMetadata.ManifestBlob = manifestData.ManifestBlob
		manifestMetadata.ConfigBlob = manifestData.ConfigBlob
		manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

		manifestMetadata.Signatures = repodb.ManifestSignatures{}
		if repoMeta.Signatures[manifestDigest.String()] != nil {
			manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
		}

		return nil
	})

	return manifestMetadata, err
}

func (bdw DBWrapper) SetIndexData(indexDigest godigest.Digest, indexData repodb.IndexData) error {
	// we make the assumption that the oci layout is consistent and all manifests refferenced inside the
	// index are present
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.IndexDataBucket))

		imBlob, err := json.Marshal(indexData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", indexDigest)
		}

		err = buck.Put([]byte(indexDigest), imBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest meta with for digest %s", indexDigest)
		}

		return nil
	})

	return err
}

func (bdw DBWrapper) GetIndexData(indexDigest godigest.Digest) (repodb.IndexData, error) {
	var indexData repodb.IndexData

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.IndexDataBucket))

		mmBlob := buck.Get([]byte(indexDigest))

		if len(mmBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		err := json.Unmarshal(mmBlob, &indexData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", indexDigest)
		}

		return nil
	})

	return indexData, err
}

func (bdw DBWrapper) SetRepoTag(repo string, tag string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if err := common.ValidateRepoTagInput(repo, tag, manifestDigest); err != nil {
		return err
	}

	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			// create a new object
			repoMeta := repodb.RepoMetadata{
				Name: repo,
				Tags: map[string]repodb.Descriptor{
					tag: {
						Digest:    manifestDigest.String(),
						MediaType: mediaType,
					},
				},
				Statistics: map[string]repodb.DescriptorStatistics{
					manifestDigest.String(): {DownloadCount: 0},
				},
				Signatures: map[string]repodb.ManifestSignatures{
					manifestDigest.String(): {},
				},
			}

			repoMetaBlob, err := json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}

		// object found
		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Tags[tag] = repodb.Descriptor{
			Digest:    manifestDigest.String(),
			MediaType: mediaType,
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) GetRepoMeta(repo string) (repodb.RepoMetadata, error) {
	var repoMeta repodb.RepoMetadata

	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		// object found
		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		return nil
	})

	return repoMeta, err
}

func (bdw DBWrapper) DeleteRepoTag(repo string, tag string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return nil
		}

		// object found
		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		delete(repoMeta.Tags, tag)

		if len(repoMeta.Tags) == 0 {
			return buck.Delete([]byte(repo))
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) IncrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Stars++

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) DecrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		if repoMeta.Stars > 0 {
			repoMeta.Stars--
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) GetRepoStars(repo string) (int, error) {
	stars := 0

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		buck.Get([]byte(repo))
		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		stars = repoMeta.Stars

		return nil
	})

	return stars, err
}

func (bdw DBWrapper) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta repodb.RepoMetadata) bool,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, error) {
	var (
		foundRepos = make([]repodb.RepoMetadata, 0)
		pageFinder repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := repodb.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, _ = pageFinder.Page()

		return nil
	})

	return foundRepos, err
}

func (bdw DBWrapper) IncrementImageDownloads(repo string, reference string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		descriptorDigest := reference

		if !common.ReferenceIsDigest(reference) {
			// search digest for tag
			descriptor, found := repoMeta.Tags[reference]

			if !found {
				return zerr.ErrManifestMetaNotFound
			}

			descriptorDigest = descriptor.Digest
		}

		manifestStatistics := repoMeta.Statistics[descriptorDigest]
		manifestStatistics.DownloadCount++
		repoMeta.Statistics[descriptorDigest] = manifestStatistics

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta repodb.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		var (
			manifestSignatures repodb.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			manifestSignatures = repodb.ManifestSignatures{}
		}

		signatureSlice := manifestSignatures[sygMeta.SignatureType]
		if !common.SignatureAlreadyExists(signatureSlice, sygMeta) {
			if sygMeta.SignatureType == repodb.NotationType {
				signatureSlice = append(signatureSlice, repodb.SignatureInfo{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				})
			} else if sygMeta.SignatureType == repodb.CosignType {
				signatureSlice = []repodb.SignatureInfo{{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				}}
			}
		}

		manifestSignatures[sygMeta.SignatureType] = signatureSlice

		repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta repodb.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		sigType := sigMeta.SignatureType

		var (
			manifestSignatures repodb.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			return zerr.ErrManifestMetaNotFound
		}

		signatureSlice := manifestSignatures[sigType]

		newSignatureSlice := make([]repodb.SignatureInfo, 0, len(signatureSlice)-1)

		for _, sigDigest := range signatureSlice {
			if sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest {
				newSignatureSlice = append(newSignatureSlice, sigDigest)
			}
		}

		manifestSignatures[sigType] = newSignatureSlice

		repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
	error,
) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		foundindexDataMap        = make(map[string]repodb.IndexData)
		pageFinder               repodb.PageFinder
		pageInfo                 repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{}, err
	}

	err = bdw.DB.View(func(transaction *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
			indexDataMap        = make(map[string]repodb.IndexData)
			repoBuck            = transaction.Bucket([]byte(repodb.RepoMetadataBucket))
			indexBuck           = transaction.Bucket([]byte(repodb.IndexDataBucket))
			manifestBuck        = transaction.Bucket([]byte(repodb.ManifestDataBucket))
		)

		cursor := repoBuck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			var repoMeta repodb.RepoMetadata

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if score := common.ScoreRepoName(searchText, string(repoName)); score != -1 {
				var (
					// specific values used for sorting that need to be calculated based on all manifests from the repo
					repoDownloads     = 0
					repoLastUpdated   time.Time
					firstImageChecked = true
					osSet             = map[string]bool{}
					archSet           = map[string]bool{}
					isSigned          = false
				)

				for tag, descriptor := range repoMeta.Tags {
					switch descriptor.MediaType {
					case ispec.MediaTypeImageManifest:
						var manifestMeta repodb.ManifestMetadata

						manifestMeta, manifestDownloaded := manifestMetadataMap[descriptor.Digest]

						if !manifestDownloaded {
							manifestMetaBlob := manifestBuck.Get([]byte(descriptor.Digest))
							if manifestMetaBlob == nil {
								return zerr.ErrManifestMetaNotFound
							}

							err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
							if err != nil {
								return errors.Wrapf(err, "repodb: error while unmarshaling manifest metadata for digest %s", descriptor.Digest)
							}
						}

						// get fields related to filtering
						var configContent ispec.Image

						err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmarshaling config content for digest %s", descriptor.Digest)
						}

						osSet[configContent.OS] = true
						archSet[configContent.Architecture] = true

						// get fields related to sorting
						repoDownloads += repoMeta.Statistics[descriptor.Digest].DownloadCount

						imageLastUpdated := common.GetImageLastUpdatedTimestamp(configContent)

						if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
							repoLastUpdated = imageLastUpdated
							firstImageChecked = false

							isSigned = common.CheckIsSigned(repoMeta.Signatures[descriptor.Digest])
						}

						manifestMetadataMap[descriptor.Digest] = manifestMeta
					case ispec.MediaTypeImageIndex:
						var indexLastUpdated time.Time

						digest := descriptor.Digest

						if _, indexExists := indexDataMap[digest]; indexExists {
							continue
						}

						indexDataBlob := indexBuck.Get([]byte(digest))
						if indexDataBlob == nil {
							return zerr.ErrManifestMetaNotFound
						}

						var indexData repodb.IndexData

						err := json.Unmarshal(indexDataBlob, &indexData)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", digest)
						}

						var indexContent ispec.Index

						err = json.Unmarshal(indexData.IndexBlob, &indexContent)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmashaling index content for %s:%s", repoName, tag)
						}

						for _, manifest := range indexContent.Manifests {
							digest := manifest.Digest.String()

							if _, manifestExists := manifestMetadataMap[digest]; manifestExists {
								continue
							}

							manifestDataBlob := manifestBuck.Get([]byte(digest))
							if manifestDataBlob == nil {
								return zerr.ErrManifestMetaNotFound
							}

							var manifestData repodb.ManifestData

							err := json.Unmarshal(manifestDataBlob, &manifestData)
							if err != nil {
								return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", digest)
							}

							var configContent ispec.Image

							err = json.Unmarshal(manifestData.ConfigBlob, &configContent)
							if err != nil {
								return errors.Wrapf(err, "repodb: error while unmashaling image config for digest %s", digest)
							}

							osSet[configContent.OS] = true
							archSet[configContent.Architecture] = true

							// get fields related to sorting
							repoDownloads += repoMeta.Statistics[descriptor.Digest].DownloadCount

							imageLastUpdated := common.GetImageLastUpdatedTimestamp(configContent)
							if firstImageChecked || indexLastUpdated.Before(imageLastUpdated) {
								indexLastUpdated = imageLastUpdated
								firstImageChecked = false

								isSigned = common.CheckIsSigned(repoMeta.Signatures[descriptor.Digest])
							}

							manifestMetadataMap[digest] = repodb.ManifestMetadata{
								ManifestBlob: manifestData.ManifestBlob,
								ConfigBlob:   manifestData.ConfigBlob,
							}
						}

						if repoLastUpdated.Before(indexLastUpdated) {
							repoLastUpdated = indexLastUpdated
						}

						indexDataMap[digest] = indexData
					default:
						bdw.Log.Error().Msg("Unsupported type")
					}
				}

				repoFilterData := repodb.FilterData{
					OsList:   common.GetMapKeys(osSet),
					ArchList: common.GetMapKeys(archSet),
					IsSigned: isSigned,
				}

				if !common.AcceptedByFilter(filter, repoFilterData) {
					continue
				}

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta:   repoMeta,
					Score:      score,
					Downloads:  repoDownloads,
					UpdateTime: repoLastUpdated,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta and indexData we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
				case ispec.MediaTypeImageIndex:
					indexData := indexDataMap[descriptor.Digest]

					var indexContent ispec.Index

					err := json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return err
					}

					for _, manifestDescriptor := range indexContent.Manifests {
						manifestDigest := manifestDescriptor.Digest.String()

						foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
					}

					indexDataMap[descriptor.Digest] = indexData
				default:
					bdw.Log.Error().Msg("Unsupported type")
				}
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (bdw DBWrapper) FilterTags(ctx context.Context, filter repodb.FilterFunc,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
	repodb.PageInfo, error,
) {
	var (
		foundRepos          = make([]repodb.RepoMetadata, 0)
		manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		indexDataMap        = make(map[string]repodb.IndexData)
		pageFinder          repodb.PageFinder
		pageInfo            repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{}, err
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		var (
			repoBuck     = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			indexBuck    = tx.Bucket([]byte(repodb.IndexDataBucket))
			manifestBuck = tx.Bucket([]byte(repodb.ManifestDataBucket))
			cursor       = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.First()

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := repodb.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			matchedTags := make(map[string]repodb.Descriptor)
			// take all manifestMetas
			for tag, descriptor := range repoMeta.Tags {
				matchedTags[tag] = descriptor
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					manifestDigest := descriptor.Digest

					// in case tags reference the same manifest we don't download from DB multiple times
					if manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]; manifestExists {
						manifestMetadataMap[manifestDigest] = manifestMeta

						continue
					}

					manifestDataBlob := manifestBuck.Get([]byte(manifestDigest))
					if manifestDataBlob == nil {
						return zerr.ErrManifestMetaNotFound
					}

					var manifestData repodb.ManifestData

					err := json.Unmarshal(manifestDataBlob, &manifestData)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
					}

					var configContent ispec.Image

					err = json.Unmarshal(manifestData.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
					}

					manifestMeta := repodb.ManifestMetadata{
						ConfigBlob:   manifestData.ConfigBlob,
						ManifestBlob: manifestData.ManifestBlob,
					}

					if !filter(repoMeta, manifestMeta) {
						delete(matchedTags, tag)
						delete(manifestMetadataMap, manifestDigest)

						continue
					}

					manifestMetadataMap[manifestDigest] = manifestMeta
				case ispec.MediaTypeImageIndex:
					digest := descriptor.Digest

					if _, indexExists := indexDataMap[digest]; indexExists {
						continue
					}

					indexDataBlob := indexBuck.Get([]byte(digest))
					if indexDataBlob == nil {
						return zerr.ErrManifestMetaNotFound
					}

					var indexData repodb.IndexData

					err := json.Unmarshal(indexDataBlob, &indexData)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", digest)
					}

					var indexContent ispec.Index

					err = json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling index content for %s:%s", repoName, tag)
					}

					manifestHasBeenMatched := false

					for _, manifest := range indexContent.Manifests {
						digest := manifest.Digest.String()

						if _, manifestExists := manifestMetadataMap[digest]; manifestExists {
							continue
						}

						manifestMetaBlob := manifestBuck.Get([]byte(digest))
						if manifestMetaBlob == nil {
							return zerr.ErrManifestMetaNotFound
						}

						var manifestMeta repodb.ManifestMetadata

						err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", digest)
						}

						manifestMetadataMap[digest] = manifestMeta

						if filter(repoMeta, manifestMeta) {
							manifestHasBeenMatched = true
						}
					}

					if !manifestHasBeenMatched {
						delete(matchedTags, tag)

						for _, manifest := range indexContent.Manifests {
							delete(manifestMetadataMap, manifest.Digest.String())
						}

						continue
					}

					indexDataMap[digest] = indexData
				default:
					bdw.Log.Error().Msg("Unsupported type")
				}
			}

			if len(matchedTags) == 0 {
				continue
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(repodb.DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}

		foundRepos, pageInfo = pageFinder.Page()

		return nil
	})

	return foundRepos, manifestMetadataMap, indexDataMap, pageInfo, err
}

func (bdw DBWrapper) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	var (
		foundRepos          = make([]repodb.RepoMetadata, 0)
		manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		indexDataMap        = make(map[string]repodb.IndexData)
		pageInfo            repodb.PageInfo

		pageFinder repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{}, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{},
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		var (
			repoBuck     = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			indexBuck    = tx.Bucket([]byte(repodb.IndexDataBucket))
			manifestBuck = tx.Bucket([]byte(repodb.ManifestDataBucket))
			cursor       = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.Seek([]byte(searchedRepo))

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := repodb.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if string(repoName) == searchedRepo {
				matchedTags := make(map[string]repodb.Descriptor)
				// take all manifestMetas
				for tag, descriptor := range repoMeta.Tags {
					if !strings.HasPrefix(tag, searchedTag) {
						continue
					}

					matchedTags[tag] = descriptor

					switch descriptor.MediaType {
					case ispec.MediaTypeImageManifest:
						// in case tags reference the same manifest we don't download from DB multiple times
						if manifestMeta, manifestExists := manifestMetadataMap[descriptor.Digest]; manifestExists {
							manifestMetadataMap[descriptor.Digest] = manifestMeta

							continue
						}

						manifestMetaBlob := manifestBuck.Get([]byte(descriptor.Digest))
						if manifestMetaBlob == nil {
							return zerr.ErrManifestMetaNotFound
						}

						var manifestMeta repodb.ManifestMetadata

						err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
						}

						var configContent ispec.Image

						err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
						}

						imageFilterData := repodb.FilterData{
							OsList:   []string{configContent.OS},
							ArchList: []string{configContent.Architecture},
							IsSigned: false,
						}

						if !common.AcceptedByFilter(filter, imageFilterData) {
							delete(matchedTags, tag)
							delete(manifestMetadataMap, descriptor.Digest)

							continue
						}

						manifestMetadataMap[descriptor.Digest] = manifestMeta
					case ispec.MediaTypeImageIndex:
						digest := descriptor.Digest

						if _, indexExists := indexDataMap[digest]; indexExists {
							continue
						}

						indexDataBlob := indexBuck.Get([]byte(digest))
						if indexDataBlob == nil {
							return zerr.ErrManifestMetaNotFound
						}

						var indexData repodb.IndexData

						err := json.Unmarshal(indexDataBlob, &indexData)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", digest)
						}

						var indexContent ispec.Index

						err = json.Unmarshal(indexData.IndexBlob, &indexContent)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmashaling index content for %s:%s", repoName, tag)
						}

						manifestHasBeenMatched := false

						for _, manifest := range indexContent.Manifests {
							digest := manifest.Digest.String()

							if _, manifestExists := manifestMetadataMap[digest]; manifestExists {
								continue
							}

							manifestDataBlob := manifestBuck.Get([]byte(digest))
							if manifestDataBlob == nil {
								return zerr.ErrManifestMetaNotFound
							}

							var manifestData repodb.ManifestData

							err := json.Unmarshal(manifestDataBlob, &manifestData)
							if err != nil {
								return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", digest)
							}

							var configContent ispec.Image

							err = json.Unmarshal(manifestData.ConfigBlob, &configContent)
							if err != nil {
								return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
							}

							imageFilterData := repodb.FilterData{
								OsList:   []string{configContent.OS},
								ArchList: []string{configContent.Architecture},
								IsSigned: false,
							}

							manifestMetadataMap[digest] = repodb.ManifestMetadata{
								ManifestBlob: manifestData.ManifestBlob,
								ConfigBlob:   manifestData.ConfigBlob,
							}

							if common.AcceptedByFilter(filter, imageFilterData) {
								manifestHasBeenMatched = true
							}
						}

						if !manifestHasBeenMatched {
							delete(matchedTags, tag)

							for _, manifest := range indexContent.Manifests {
								delete(manifestMetadataMap, manifest.Digest.String())
							}

							continue
						}

						indexDataMap[digest] = indexData
					default:
						bdw.Log.Error().Msg("Unsupported type")
					}
				}

				if len(matchedTags) == 0 {
					continue
				}

				repoMeta.Tags = matchedTags

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		return nil
	})

	return foundRepos, manifestMetadataMap, indexDataMap, pageInfo, err
}

func (bdw *DBWrapper) PatchDB() error {
	var DBVersion string

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		versionBuck := tx.Bucket([]byte(repodb.VersionBucket))
		DBVersion = string(versionBuck.Get([]byte(version.DBVersionKey)))

		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "patching the database failed, can't read db version")
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return errors.New("DB has broken format, no version found")
	}

	for patchIndex, patch := range bdw.Patches {
		if patchIndex < version.GetVersionIndex(DBVersion) {
			continue
		}

		err := patch(bdw.DB)
		if err != nil {
			return err
		}
	}

	return nil
}
