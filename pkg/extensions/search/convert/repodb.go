package convert

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/meta/repodb"
)

type SkipQGLField struct {
	Vulnerabilities bool
}

func RepoMeta2RepoSummary(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata, indexMetaMap map[string]repodb.IndexMetadata,
	skip SkipQGLField, cveInfo cveinfo.CveInfo,
) *gql_generated.RepoSummary {
	var (
		repoLastUpdatedTimestamp = time.Time{}
		repoPlatformsSet         = map[string]*gql_generated.OsArch{}
		repoVendorsSet           = map[string]bool{}
		lastUpdatedImageSummary  *gql_generated.ImageSummary
		repoStarCount            = repoMeta.Stars
		isBookmarked             = false
		isStarred                = false
		repoDownloadCount        = 0
		repoName                 = repoMeta.Name

		// map used to keep track of all blobs of a repo without dublicates as
		// some images may have the same layers
		repoBlob2Size = make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		size = int64(0)
	)

	for tag, descriptor := range repoMeta.Tags {
		// TODO: Descriptor2ImageSummary(descriptor) ImageSummary
		imageSummary, imageBlobsMap, err := Descriptor2ImageSummary(ctx, descriptor, repoMeta.Name, tag, true, repoMeta,
			manifestMetaMap, indexMetaMap, cveInfo)
		if err != nil {
			continue
		}

		for blobDigest, blobSize := range imageBlobsMap {
			repoBlob2Size[blobDigest] = blobSize
		}

		for _, manifestSummary := range imageSummary.Manifests {
			if *manifestSummary.Vendor != "" {
				repoVendorsSet[*manifestSummary.Vendor] = true
			}

			if *manifestSummary.Platform.Os != "" || *manifestSummary.Platform.Arch != "" {
				opSys, arch := *manifestSummary.Platform.Os, *manifestSummary.Platform.Arch

				osArchString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
				repoPlatformsSet[osArchString] = &gql_generated.OsArch{Os: &opSys, Arch: &arch}
			}

			repoDownloadCount += manifestMetaMap[*manifestSummary.Digest].DownloadCount
		}

		if repoLastUpdatedTimestamp.Equal(time.Time{}) {
			// initialize with first time value
			repoLastUpdatedTimestamp = *imageSummary.LastUpdated
			lastUpdatedImageSummary = imageSummary
		} else if repoLastUpdatedTimestamp.Before(*imageSummary.LastUpdated) {
			repoLastUpdatedTimestamp = *imageSummary.LastUpdated
			lastUpdatedImageSummary = imageSummary
		}

		repoDownloadCount += repoMeta.Statistics[descriptor.Digest].DownloadCount
	}

	// calculate repo size = sum all manifest, config and layer blobs sizes
	for _, blobSize := range repoBlob2Size {
		size += blobSize
	}

	repoSize := strconv.FormatInt(size, 10)
	score := 0

	repoPlatforms := make([]*gql_generated.OsArch, 0, len(repoPlatformsSet))
	for _, osArch := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, osArch)
	}

	repoVendors := make([]*string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, &vendor)
	}

	// We only scan the latest image on the repo for performance reasons
	// Check if vulnerability scanning is disabled
	if cveInfo != nil && lastUpdatedImageSummary != nil && !skip.Vulnerabilities {
		imageName := fmt.Sprintf("%s:%s", repoMeta.Name, *lastUpdatedImageSummary.Tag)

		imageCveSummary, err := cveInfo.GetCVESummaryForImage(imageName)
		if err != nil {
			// Log the error, but we should still include the image in results
			graphql.AddError(
				ctx,
				gqlerror.Errorf(
					"unable to run vulnerability scan on tag %s in repo %s: error: %s",
					*lastUpdatedImageSummary.Tag, repoMeta.Name, err.Error(),
				),
			)
		}

		lastUpdatedImageSummary.Vulnerabilities = &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity: &imageCveSummary.MaxSeverity,
			Count:       &imageCveSummary.Count,
		}
	}

	return &gql_generated.RepoSummary{
		Name:          &repoName,
		LastUpdated:   &repoLastUpdatedTimestamp,
		Size:          &repoSize,
		Platforms:     repoPlatforms,
		Vendors:       repoVendors,
		Score:         &score,
		NewestImage:   lastUpdatedImageSummary,
		DownloadCount: &repoDownloadCount,
		StarCount:     &repoStarCount,
		IsBookmarked:  &isBookmarked,
		IsStarred:     &isStarred,
	}
}

func Descriptor2ImageSummary(ctx context.Context, descriptor repodb.Descriptor, repo, tag string, skipCVE bool,
	repoMeta repodb.RepoMetadata, manifestMetaMap map[string]repodb.ManifestMetadata,
	indexMetaMap map[string]repodb.IndexMetadata, cveInfo cveinfo.CveInfo,
) (*gql_generated.ImageSummary, map[string]int64, error) {
	switch descriptor.MediaType {
	case ispec.MediaTypeImageManifest:
		return ImageManifest2ImageSummary(ctx, repo, tag, godigest.Digest(descriptor.Digest), skipCVE,
			repoMeta, manifestMetaMap[descriptor.Digest], cveInfo)
	case ispec.MediaTypeImageIndex:
		// TODO: Add INDEX META somehow
		return ImageIndex2ImageSummary(ctx, repo, tag, godigest.Digest(descriptor.Digest), skipCVE,
			repoMeta, indexMetaMap[descriptor.Digest], manifestMetaMap, cveInfo)
	default:
		return &gql_generated.ImageSummary{}, map[string]int64{}, nil
	}
}

func severityValue(severity string) int {
	sevMap := map[string]int{
		"NONE":     0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	return sevMap[severity]
}

func ImageIndex2ImageSummary(ctx context.Context, repo, tag string, indexDigest godigest.Digest, skipCVE bool,
	repoMeta repodb.RepoMetadata, indexMeta repodb.IndexMetadata, manifestMetaMap map[string]repodb.ManifestMetadata,
	cveInfo cveinfo.CveInfo,
) (*gql_generated.ImageSummary, map[string]int64, error) {
	var indexContent ispec.Index

	err := json.Unmarshal(indexMeta.IndexBlob, &indexContent)
	if err != nil {
		return &gql_generated.ImageSummary{}, map[string]int64{}, err
	}

	var (
		indexLastUpdated          time.Time
		isSigned                  bool
		totalIndexSize            int64
		indexSize                 string
		totalDownloadCount        int
		maxSeverity               string
		totalVulnerabilitiesCount int

		manifestSummaries = make([]*gql_generated.ManifestSummary, 0, len(indexContent.Manifests))
		indexBlobs        = make(map[string]int64, 0)
	)

	for _, descriptor := range indexContent.Manifests {
		manifestSummary, manifestBlobs, err := ImageManifest2ManifestSummary(ctx, repo, tag, descriptor.Digest, skipCVE,
			manifestMetaMap[descriptor.Digest.String()], cveInfo)
		if err != nil {
			return &gql_generated.ImageSummary{}, map[string]int64{}, err
		}

		manifestSize := int64(0)

		for digest, size := range manifestBlobs {
			indexBlobs[digest] = size
			manifestSize += size
		}

		if indexLastUpdated.Before(*manifestSummary.LastUpdated) {
			indexLastUpdated = *manifestSummary.LastUpdated
		}

		totalIndexSize += manifestSize

		if severityValue(*manifestSummary.Vulnerabilities.MaxSeverity) > severityValue(maxSeverity) {
			maxSeverity = *manifestSummary.Vulnerabilities.MaxSeverity
		}

		totalVulnerabilitiesCount += *manifestSummary.Vulnerabilities.Count

		manifestSummaries = append(manifestSummaries, manifestSummary)
	}

	for _, signatures := range repoMeta.Signatures[indexDigest.String()] {
		if len(signatures) > 0 {
			isSigned = true
		}
	}

	indexSize = strconv.FormatInt(totalIndexSize, 10)

	annotations := common.GetAnnotations(indexContent.Annotations, map[string]string{})

	indexSummary := gql_generated.ImageSummary{
		RepoName:      &repo,
		Tag:           &tag,
		Manifests:     manifestSummaries,
		LastUpdated:   &indexLastUpdated,
		IsSigned:      &isSigned,
		Size:          &indexSize,
		DownloadCount: &totalDownloadCount,
		Description:   &annotations.Description,
		Title:         &annotations.Title,
		Documentation: &annotations.Documentation,
		Licenses:      &annotations.Licenses,
		Labels:        &annotations.Labels,
		Source:        &annotations.Source,
		Logo:          &annotations.Logo,
		Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity: &maxSeverity,
			Count:       &totalVulnerabilitiesCount,
		},
	}

	return &indexSummary, indexBlobs, nil
}

func ImageManifest2ImageSummary(ctx context.Context, repo, tag string, digest godigest.Digest, skipCVE bool,
	repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata, cveInfo cveinfo.CveInfo,
) (*gql_generated.ImageSummary, map[string]int64, error) {
	var (
		manifestContent ispec.Manifest
		manifestDigest  = digest.String()
	)

	err := json.Unmarshal(manifestMeta.ManifestBlob, &manifestContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal manifest blob for image: %s:%s, manifest digest: %s, "+
			"error: %s", repo, tag, manifestDigest, err.Error()))

		return &gql_generated.ImageSummary{}, map[string]int64{}, err
	}

	var configContent ispec.Image

	err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal config blob for image: %s:%s, manifest digest: %s, error: %s",
			repo, tag, manifestDigest, err.Error()))

		return &gql_generated.ImageSummary{}, map[string]int64{}, err
	}

	var (
		repoName         = repo
		configDigest     = manifestContent.Config.Digest.String()
		configSize       = manifestContent.Config.Size
		opSys            = configContent.OS
		arch             = configContent.Architecture
		osArch           = gql_generated.OsArch{Os: &opSys, Arch: &arch}
		imageLastUpdated = common.GetImageLastUpdated(configContent)
		downloadCount    = repoMeta.Statistics[digest.String()].DownloadCount
		isSigned         = false
	)

	for _, signatures := range repoMeta.Signatures[digest.String()] {
		if len(signatures) > 0 {
			isSigned = true
		}
	}

	size, imageBlobsMap := getImageBlobsInfo(
		manifestDigest, int64(len(manifestMeta.ManifestBlob)),
		configDigest, configSize,
		manifestContent.Layers)
	imageSize := strconv.FormatInt(size, 10)

	annotations := common.GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

	authors := annotations.Authors
	if authors == "" {
		authors = configContent.Author
	}

	historyEntries, err := getAllHistory(manifestContent, configContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("error generating history on tag %s in repo %s: "+
			"manifest digest: %s, error: %s", tag, repo, manifestDigest, err.Error()))
	}

	imageCveSummary := cveinfo.ImageCVESummary{}

	if cveInfo != nil && !skipCVE {
		imageName := fmt.Sprintf("%s:%s", repo, tag)
		imageCveSummary, err = cveInfo.GetCVESummaryForImage(imageName)

		if err != nil {
			// Log the error, but we should still include the manifest in results
			graphql.AddError(ctx, gqlerror.Errorf("unable to run vulnerability scan on tag %s in repo %s: "+
				"manifest digest: %s, error: %s", tag, repo, manifestDigest, err.Error()))
		}
	}

	imageSummary := gql_generated.ImageSummary{
		RepoName: &repoName,
		Tag:      &tag,
		Manifests: []*gql_generated.ManifestSummary{
			{
				RepoName:      &repoName,
				Tag:           &tag,
				Digest:        &manifestDigest,
				ConfigDigest:  &configDigest,
				LastUpdated:   &imageLastUpdated,
				IsSigned:      &isSigned,
				Size:          &imageSize,
				Platform:      &osArch,
				Vendor:        &annotations.Vendor,
				DownloadCount: &downloadCount,
				Layers:        getLayersSummaries(manifestContent),
				History:       historyEntries,
				Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
					MaxSeverity: &imageCveSummary.MaxSeverity,
					Count:       &imageCveSummary.Count,
				},
			},
		},
		LastUpdated:   &imageLastUpdated,
		IsSigned:      &isSigned,
		Size:          &imageSize,
		DownloadCount: &downloadCount,
		Description:   &annotations.Description,
		Title:         &annotations.Title,
		Documentation: &annotations.Documentation,
		Licenses:      &annotations.Licenses,
		Labels:        &annotations.Labels,
		Source:        &annotations.Source,
		Logo:          &annotations.Logo,
		Authors:       &authors,
		Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity: &imageCveSummary.MaxSeverity,
			Count:       &imageCveSummary.Count,
		},
	}

	return &imageSummary, imageBlobsMap, nil
}

func ImageManifest2ManifestSummary(ctx context.Context, repo, tag string, manifestDigest godigest.Digest,
	skipCVE bool, manifestMeta repodb.ManifestMetadata, cveInfo cveinfo.CveInfo,
) (*gql_generated.ManifestSummary, map[string]int64, error) {
	var manifestContent ispec.Manifest

	err := json.Unmarshal(manifestMeta.ManifestBlob, &manifestContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal manifest blob for image: %s:%s, manifest digest: %s, "+
			"error: %s", repo, tag, manifestDigest, err.Error()))

		return &gql_generated.ManifestSummary{}, map[string]int64{}, err
	}

	var configContent ispec.Image

	err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal config blob for image: %s:%s, manifest digest: %s, error: %s",
			repo, tag, manifestDigest, err.Error()))

		return &gql_generated.ManifestSummary{}, map[string]int64{}, err
	}

	var (
		repoName          = repo
		manifestDigestStr = manifestDigest.String()
		isSigned          = len(manifestMeta.Signatures) > 0
		configDigest      = manifestContent.Config.Digest.String()
		configSize        = manifestContent.Config.Size
		opSys             = configContent.OS
		arch              = configContent.Architecture
		osArch            = gql_generated.OsArch{Os: &opSys, Arch: &arch}
		imageLastUpdated  = common.GetImageLastUpdated(configContent)
		downloadCount     = manifestMeta.DownloadCount
	)

	size, imageBlobsMap := getImageBlobsInfo(
		manifestDigestStr, int64(len(manifestMeta.ManifestBlob)),
		configDigest, configSize,
		manifestContent.Layers)
	imageSize := strconv.FormatInt(size, 10)

	annotations := common.GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

	historyEntries, err := getAllHistory(manifestContent, configContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("error generating history on tag %s in repo %s: "+
			"manifest digest: %s, error: %s", tag, repo, manifestDigestStr, err.Error()))
	}

	imageCveSummary := cveinfo.ImageCVESummary{}

	if cveInfo != nil && !skipCVE {
		imageName := fmt.Sprintf("%s:%s", repo, tag)
		imageCveSummary, err = cveInfo.GetCVESummaryForImage(imageName)

		if err != nil {
			// Log the error, but we should still include the manifest in results
			graphql.AddError(ctx, gqlerror.Errorf("unable to run vulnerability scan on tag %s in repo %s: "+
				"manifest digest: %s, error: %s", tag, repo, manifestDigestStr, err.Error()))
		}
	}

	manifestSummary := gql_generated.ManifestSummary{
		RepoName:      &repoName,
		Tag:           &tag,
		Digest:        &manifestDigestStr,
		ConfigDigest:  &configDigest,
		LastUpdated:   &imageLastUpdated,
		IsSigned:      &isSigned,
		Size:          &imageSize,
		Platform:      &osArch,
		Vendor:        &annotations.Vendor,
		DownloadCount: &downloadCount,
		Layers:        getLayersSummaries(manifestContent),
		History:       historyEntries,
		Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity: &imageCveSummary.MaxSeverity,
			Count:       &imageCveSummary.Count,
		},
	}

	return &manifestSummary, imageBlobsMap, nil
}

func getImageBlobsInfo(manifestDigest string, manifestSize int64, configDigest string, configSize int64,
	layers []ispec.Descriptor,
) (int64, map[string]int64) {
	imageBlobsMap := map[string]int64{}
	imageSize := int64(0)

	// add config size
	imageSize += configSize
	imageBlobsMap[configDigest] = configSize

	// add manifest size
	imageSize += manifestSize
	imageBlobsMap[manifestDigest] = manifestSize

	// add layers size
	for _, layer := range layers {
		imageBlobsMap[layer.Digest.String()] = layer.Size
		imageSize += layer.Size
	}

	return imageSize, imageBlobsMap
}

func RepoMeta2ImageSummaries(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata, indexMetaMap map[string]repodb.IndexMetadata,
	skip SkipQGLField, cveInfo cveinfo.CveInfo,
) []*gql_generated.ImageSummary {
	imageSummaries := make([]*gql_generated.ImageSummary, 0, len(repoMeta.Tags))

	for tag, descriptor := range repoMeta.Tags {
		imageSummary, _, err := Descriptor2ImageSummary(ctx, descriptor, repoMeta.Name, tag, skip.Vulnerabilities,
			repoMeta, manifestMetaMap, indexMetaMap, cveInfo)

		if err != nil {
			continue
		}

		imageSummaries = append(imageSummaries, imageSummary)
	}

	return imageSummaries
}

func RepoMeta2ExpandedRepoInfo(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata, indexMetaMap map[string]repodb.IndexMetadata,
	skip SkipQGLField, cveInfo cveinfo.CveInfo,
) (*gql_generated.RepoSummary, []*gql_generated.ImageSummary) {
	var (
		repoLastUpdatedTimestamp = time.Time{}
		repoPlatformsSet         = map[string]*gql_generated.OsArch{}
		repoVendorsSet           = map[string]bool{}
		lastUpdatedImageSummary  *gql_generated.ImageSummary
		repoStarCount            = repoMeta.Stars
		isBookmarked             = false
		isStarred                = false
		repoDownloadCount        = 0
		repoName                 = repoMeta.Name

		// map used to keep track of all blobs of a repo without dublicates as
		// some images may have the same layers
		repoBlob2Size = make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		size = int64(0)

		imageSummaries = make([]*gql_generated.ImageSummary, 0, len(repoMeta.Tags))
	)

	for tag, descriptor := range repoMeta.Tags {

		imageSummary, imageBlobs, err := Descriptor2ImageSummary(ctx, descriptor, repoName, tag, true,
			repoMeta, manifestMetaMap, indexMetaMap, cveInfo)
		if err != nil {
			// TODO: handle error
			continue
		}

		for _, manifestSummary := range imageSummary.Manifests {
			if *manifestSummary.Vendor != "" {
				repoVendorsSet[*manifestSummary.Vendor] = true
			}

			opSys, arch := *manifestSummary.Platform.Os, *manifestSummary.Platform.Arch
			if opSys != "" || arch != "" {
				osArchString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
				repoPlatformsSet[osArchString] = &gql_generated.OsArch{Os: &opSys, Arch: &arch}
			}

			updateRepoBlobsMap(imageBlobs, repoBlob2Size)
		}

		if repoLastUpdatedTimestamp.Equal(time.Time{}) {
			// initialize with first time value
			repoLastUpdatedTimestamp = *imageSummary.LastUpdated
			lastUpdatedImageSummary = imageSummary
		} else if repoLastUpdatedTimestamp.Before(*imageSummary.LastUpdated) {
			repoLastUpdatedTimestamp = *imageSummary.LastUpdated
			lastUpdatedImageSummary = imageSummary
		}

		repoDownloadCount += *imageSummary.DownloadCount

		imageSummaries = append(imageSummaries, imageSummary)
	}

	// calculate repo size = sum all manifest, config and layer blobs sizes
	for _, blobSize := range repoBlob2Size {
		size += blobSize
	}

	repoSize := strconv.FormatInt(size, 10)
	score := 0

	repoPlatforms := make([]*gql_generated.OsArch, 0, len(repoPlatformsSet))
	for _, osArch := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, osArch)
	}

	repoVendors := make([]*string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, &vendor)
	}

	// We only scan the latest image on the repo for performance reasons
	// Check if vulnerability scanning is disabled
	if cveInfo != nil && lastUpdatedImageSummary != nil && !skip.Vulnerabilities {
		// TODO: check if trivy can scan multi-arch images

		imageName := fmt.Sprintf("%s:%s", repoMeta.Name, *lastUpdatedImageSummary.Tag)

		imageCveSummary, err := cveInfo.GetCVESummaryForImage(imageName)
		if err != nil {
			// Log the error, but we should still include the image in results
			graphql.AddError(
				ctx,
				gqlerror.Errorf(
					"unable to run vulnerability scan on tag %s in repo %s: error: %s",
					*lastUpdatedImageSummary.Tag, repoMeta.Name, err.Error(),
				),
			)
		}

		lastUpdatedImageSummary.Vulnerabilities = &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity: &imageCveSummary.MaxSeverity,
			Count:       &imageCveSummary.Count,
		}
	}

	summary := &gql_generated.RepoSummary{
		Name:          &repoName,
		LastUpdated:   &repoLastUpdatedTimestamp,
		Size:          &repoSize,
		Platforms:     repoPlatforms,
		Vendors:       repoVendors,
		Score:         &score,
		NewestImage:   lastUpdatedImageSummary,
		DownloadCount: &repoDownloadCount,
		StarCount:     &repoStarCount,
		IsBookmarked:  &isBookmarked,
		IsStarred:     &isStarred,
	}

	return summary, imageSummaries
}

func GetPreloads(ctx context.Context) map[string]bool {
	if !graphql.HasOperationContext(ctx) {
		return map[string]bool{}
	}

	nestedPreloads := GetNestedPreloads(
		graphql.GetOperationContext(ctx),
		graphql.CollectFieldsCtx(ctx, nil),
		"",
	)

	preloads := map[string]bool{}

	for _, str := range nestedPreloads {
		preloads[str] = true
	}

	return preloads
}

func GetNestedPreloads(ctx *graphql.OperationContext, fields []graphql.CollectedField, prefix string,
) []string {
	preloads := []string{}

	for _, column := range fields {
		prefixColumn := GetPreloadString(prefix, column.Name)
		preloads = append(preloads, prefixColumn)
		preloads = append(preloads,
			GetNestedPreloads(ctx, graphql.CollectFields(ctx, column.Selections, nil), prefixColumn)...,
		)
	}

	return preloads
}

func GetPreloadString(prefix, name string) string {
	if len(prefix) > 0 {
		return prefix + "." + name
	}

	return name
}
