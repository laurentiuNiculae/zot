//go:build search

package convert

import (
	"context"
	"errors"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/boltdb"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestCVEConvert(t *testing.T) {
	Convey("Test adding CVE information to Summary objects", t, func() {
		params := boltdb.DBParameters{
			RootDir: t.TempDir(),
		}
		boltDB, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDB, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		image := CreateImageWith().
			Layers([]Layer{{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    ispec.MediaTypeEmptyJSON,
				Blob:      ispec.DescriptorEmptyJSON.Data,
			}}).DefaultConfig().Build()

		err = metaDB.SetRepoReference("repo1", "0.1.0", image.AsImageMeta())
		So(err, ShouldBeNil)

		repoMetaList, err := metaDB.SearchRepos(context.Background(), "")
		So(err, ShouldBeNil)

		imageMeta, err := metaDB.FilterImageMeta(context.Background(), []string{image.DigestStr()})

		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)

		Convey("Add CVE Summary to ImageSummary", func() {
			var imageSummary *gql_generated.ImageSummary

			So(imageSummary, ShouldBeNil)

			updateImageSummaryVulnerabilities(ctx,
				imageSummary,
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{}, ErrTestError
					},
				},
			)

			So(imageSummary, ShouldBeNil)
			So(graphql.GetErrors(ctx), ShouldBeNil)

			imageSummary, _, err = ImageManifest2ImageSummary(ctx, GetFullImageMeta("0.1.0", repoMetaList[0],
				imageMeta[image.DigestStr()]))
			So(err, ShouldBeNil)

			So(imageSummary, ShouldNotBeNil)
			So(imageSummary.Vulnerabilities, ShouldBeNil)

			updateImageSummaryVulnerabilities(ctx,
				imageSummary,
				SkipQGLField{
					Vulnerabilities: true,
				},
				mocks.CveInfoMock{},
			)

			So(imageSummary.Vulnerabilities, ShouldNotBeNil)
			So(*imageSummary.Vulnerabilities.Count, ShouldEqual, 0)
			So(*imageSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "")
			So(graphql.GetErrors(ctx), ShouldBeNil)

			imageSummary.Vulnerabilities = nil

			updateImageSummaryVulnerabilities(ctx,
				imageSummary,
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{
							Count:       1,
							MaxSeverity: "HIGH",
						}, nil
					},
				},
			)

			So(imageSummary.Vulnerabilities, ShouldNotBeNil)
			So(*imageSummary.Vulnerabilities.Count, ShouldEqual, 1)
			So(*imageSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "HIGH")
			So(graphql.GetErrors(ctx), ShouldBeNil)
			So(len(imageSummary.Manifests), ShouldEqual, 1)
			So(imageSummary.Manifests[0].Vulnerabilities, ShouldNotBeNil)
			So(*imageSummary.Manifests[0].Vulnerabilities.Count, ShouldEqual, 1)
			So(*imageSummary.Manifests[0].Vulnerabilities.MaxSeverity, ShouldEqual, "HIGH")

			imageSummary.Vulnerabilities = nil

			updateImageSummaryVulnerabilities(ctx,
				imageSummary,
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{}, ErrTestError
					},
				},
			)

			So(imageSummary.Vulnerabilities, ShouldNotBeNil)
			So(*imageSummary.Vulnerabilities.Count, ShouldEqual, 0)
			So(*imageSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "")
			So(graphql.GetErrors(ctx).Error(), ShouldContainSubstring, "unable to run vulnerability scan on tag")
		})

		Convey("Add CVE Summary to RepoSummary", func() {
			var repoSummary *gql_generated.RepoSummary
			So(repoSummary, ShouldBeNil)

			updateRepoSummaryVulnerabilities(ctx,
				repoSummary,
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{
							Count:       1,
							MaxSeverity: "HIGH",
						}, nil
					},
				},
			)

			So(repoSummary, ShouldBeNil)
			So(graphql.GetErrors(ctx), ShouldBeNil)

			imageSummary, _, err := ImageManifest2ImageSummary(ctx, GetFullImageMeta("0.1.0", repoMetaList[0],
				imageMeta[image.DigestStr()]))
			So(err, ShouldBeNil)

			So(imageSummary, ShouldNotBeNil)

			repoSummary = &gql_generated.RepoSummary{}
			repoSummary.NewestImage = imageSummary

			So(repoSummary.NewestImage.Vulnerabilities, ShouldBeNil)

			updateImageSummaryVulnerabilities(ctx,
				imageSummary,
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{
							Count:       1,
							MaxSeverity: "HIGH",
						}, nil
					},
				},
			)

			So(repoSummary.NewestImage.Vulnerabilities, ShouldNotBeNil)
			So(*repoSummary.NewestImage.Vulnerabilities.Count, ShouldEqual, 1)
			So(*repoSummary.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "HIGH")
			So(graphql.GetErrors(ctx), ShouldBeNil)
		})

		Convey("Add CVE Summary to ManifestSummary", func() {
			var manifestSummary *gql_generated.ManifestSummary

			So(manifestSummary, ShouldBeNil)

			updateManifestSummaryVulnerabilities(ctx,
				manifestSummary,
				"repo1",
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{
							Count:       1,
							MaxSeverity: "HIGH",
						}, nil
					},
				},
			)

			So(manifestSummary, ShouldBeNil)
			So(graphql.GetErrors(ctx), ShouldBeNil)

			imageSummary, _, err := ImageManifest2ImageSummary(ctx, GetFullImageMeta("0.1.0", repoMetaList[0],
				imageMeta[image.DigestStr()]))
			So(err, ShouldBeNil)
			manifestSummary = imageSummary.Manifests[0]

			updateManifestSummaryVulnerabilities(ctx,
				manifestSummary,
				"repo1",
				SkipQGLField{
					Vulnerabilities: true,
				},
				mocks.CveInfoMock{},
			)

			So(manifestSummary, ShouldNotBeNil)
			So(manifestSummary.Vulnerabilities, ShouldNotBeNil)
			So(*manifestSummary.Vulnerabilities.Count, ShouldEqual, 0)
			So(*manifestSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "")

			manifestSummary.Vulnerabilities = nil

			updateManifestSummaryVulnerabilities(ctx,
				manifestSummary,
				"repo1",
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{
							Count:       1,
							MaxSeverity: "HIGH",
						}, nil
					},
				},
			)

			So(manifestSummary.Vulnerabilities, ShouldNotBeNil)
			So(*manifestSummary.Vulnerabilities.Count, ShouldEqual, 1)
			So(*manifestSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "HIGH")

			manifestSummary.Vulnerabilities = nil

			updateManifestSummaryVulnerabilities(ctx,
				manifestSummary,
				"repo1",
				SkipQGLField{
					Vulnerabilities: false,
				},
				mocks.CveInfoMock{
					GetCVESummaryForImageMediaFn: func(repo string, digest, mediaType string,
					) (cvemodel.ImageCVESummary, error) {
						return cvemodel.ImageCVESummary{}, ErrTestError
					},
				},
			)

			So(manifestSummary.Vulnerabilities, ShouldNotBeNil)
			So(*manifestSummary.Vulnerabilities.Count, ShouldEqual, 0)
			So(*manifestSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "")
			So(graphql.GetErrors(ctx).Error(), ShouldContainSubstring, "unable to run vulnerability scan in repo")
		})
	})
}
