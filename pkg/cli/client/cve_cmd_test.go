//go:build search
// +build search

package client_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli/client"
	zcommon "zotregistry.io/zot/pkg/common"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	test "zotregistry.io/zot/pkg/test/common"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/mocks"
	ociutils "zotregistry.io/zot/pkg/test/oci-utils"
)

func TestNegativeServerResponse(t *testing.T) {
	Convey("Test from real server without search endpoint", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log.NewLogger("debug", ""))
		err := WriteImageToFileSystem(CreateDefaultVulnerableImage(), "zot-cve-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		conf.Storage.RootDirectory = dir
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: 2,
			Trivy:          trivyConfig,
		}
		defaultVal := false
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		if err != nil {
			panic(err)
		}

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		_, err = test.ReadLogFileAndSearchString(logPath, "CVE config not provided, skipping CVE update", 90*time.Second)
		if err != nil {
			panic(err)
		}

		Convey("Status Code Not Found", func() {
			args := []string{"list", "zot-cve-test:0.0.1", "--config", "cvetest"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cveCmd := client.NewCVECommand(client.NewSearchService())
			buff := bytes.NewBufferString("")
			cveCmd.SetOut(buff)
			cveCmd.SetErr(buff)
			cveCmd.SetArgs(args)
			err = cveCmd.Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, zerr.ErrExtensionNotEnabled.Error())
		})
	})

	Convey("Test non-existing manifest blob", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		imageStore := local.NewImageStore(dir, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		image := CreateRandomImage()

		err := WriteImageToFileSystem(image, "zot-cve-test", "0.0.1", storeController)
		So(err, ShouldBeNil)

		err = os.RemoveAll(path.Join(dir, "zot-cve-test/blobs"))
		if err != nil {
			panic(err)
		}

		conf.Storage.RootDirectory = dir
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: 2,
			Trivy:          trivyConfig,
		}
		defaultVal := true
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		if err != nil {
			panic(err)
		}

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctx := context.Background()

		if err := ctlr.Init(ctx); err != nil {
			panic(err)
		}

		ctlr.CveScanner = getMockCveScanner(ctlr.MetaDB)

		go func() {
			if err := ctlr.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		test.WaitTillServerReady(url)

		_, err = test.ReadLogFileAndSearchString(logPath, "DB update completed, next update scheduled", 90*time.Second)
		if err != nil {
			panic(err)
		}

		args := []string{"fixed", "zot-cve-test", "CVE-2019-9923", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

//nolint:dupl
func TestServerCVEResponse(t *testing.T) {
	port := test.GetFreePort()
	url := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	dir := t.TempDir()

	conf.Storage.RootDirectory = dir
	trivyConfig := &extconf.TrivyConfig{
		DBRepository: "ghcr.io/project-zot/trivy-db",
	}
	cveConfig := &extconf.CVEConfig{
		UpdateInterval: 2,
		Trivy:          trivyConfig,
	}
	defaultVal := true
	searchConfig := &extconf.SearchConfig{
		BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		CVE:        cveConfig,
	}
	conf.Extensions = &extconf.ExtensionConfig{
		Search: searchConfig,
	}

	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	writers := io.MultiWriter(os.Stdout, logFile)

	ctlr := api.NewController(conf)
	ctlr.Log.Logger = ctlr.Log.Output(writers)

	ctx := context.Background()

	if err := ctlr.Init(ctx); err != nil {
		panic(err)
	}

	ctlr.CveScanner = getMockCveScanner(ctlr.MetaDB)

	go func() {
		if err := ctlr.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	defer ctlr.Shutdown()

	test.WaitTillServerReady(url)

	image := CreateDefaultImage()

	err = UploadImage(image, url, "zot-cve-test", "0.0.1")
	if err != nil {
		panic(err)
	}

	_, err = test.ReadLogFileAndSearchString(logPath, "DB update completed, next update scheduled", 90*time.Second)
	if err != nil {
		panic(err)
	}

	Convey("Test CVE by image name - GQL - positive", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldContainSubstring, "ID SEVERITY TITLE")
		So(str, ShouldContainSubstring, "CVE")
	})

	Convey("Test CVE by image name - GQL - search CVE by title in results", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--cve-id", "CVE-C1", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldContainSubstring, "ID SEVERITY TITLE")
		So(str, ShouldContainSubstring, "CVE-C1")
		So(str, ShouldNotContainSubstring, "CVE-2")
	})

	Convey("Test CVE by image name - GQL - search CVE by id in results", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--cve-id", "CVE-2", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldContainSubstring, "ID SEVERITY TITLE")
		So(str, ShouldContainSubstring, "CVE-2")
		So(str, ShouldNotContainSubstring, "CVE-1")
	})

	Convey("Test CVE by image name - GQL - search nonexistent CVE", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--cve-id", "CVE-100", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldContainSubstring, "No CVEs found for image")
	})

	Convey("Test CVE by image name - GQL - invalid image", t, func() {
		args := []string{"list", "invalid:0.0.1", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE by image name - GQL - invalid image name and tag", t, func() {
		args := []string{"list", "invalid:", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE by image name - GQL - invalid output format", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "-f", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})

	Convey("Test images by CVE ID - GQL - positive", t, func() {
		args := []string{"affected", "CVE-2019-9923", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldEqual, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE zot-cve-test 0.0.1 linux/amd64 db573b01 false 854B")
	})

	Convey("Test images by CVE ID - GQL - invalid CVE ID", t, func() {
		args := []string{"affected", "CVE-invalid", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test images by CVE ID - GQL - invalid output format", t, func() {
		args := []string{"affected", "CVE-2019-9923", "-f", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - positive", t, func() {
		args := []string{"fixed", "zot-cve-test", "CVE-2019-9923", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldEqual, "")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - random cve", t, func() {
		args := []string{"fixed", "zot-cve-test", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - random image", t, func() {
		args := []string{"fixed", "zot-cv-test", "CVE-2019-20807", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - invalid image", t, func() {
		args := []string{"fixed", "zot-cv-test:tag", "CVE-2019-20807", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test CVE by name and CVE ID - GQL - positive", t, func() {
		args := []string{"affected", "CVE-2019-9923", "--repo", "zot-cve-test", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE zot-cve-test 0.0.1 linux/amd64 db573b01 false 854B")
	})

	Convey("Test CVE by name and CVE ID - GQL - invalid name and CVE ID", t, func() {
		args := []string{"affected", "CVE-20807", "--repo", "test", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH SIGNED SIZE")
	})

	Convey("Test CVE by name and CVE ID - GQL - invalid output format", t, func() {
		args := []string{"affected", "CVE-2019-9923", "--repo", "zot-cve-test", "-f", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})
}

func TestCVESort(t *testing.T) {
	rootDir := t.TempDir()
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE: &extconf.CVEConfig{
				UpdateInterval: 2,
				Trivy: &extconf.TrivyConfig{
					DBRepository: "ghcr.io/project-zot/trivy-db",
				},
			},
		},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = rootDir

	image1 := CreateRandomImage()

	storeController := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)

	err := WriteImageToFileSystem(image1, "repo", "tag", storeController)
	if err != nil {
		t.FailNow()
	}

	ctx := context.Background()

	if err := ctlr.Init(ctx); err != nil {
		panic(err)
	}

	ctlr.CveScanner = mocks.CveScannerMock{
		ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
			return map[string]cvemodel.CVE{
				"CVE-2023-1255": {
					ID:       "CVE-2023-1255",
					Severity: "LOW",
					Title:    "Input buffer over-read in AES-XTS implementation and testing",
				},
				"CVE-2023-2650": {
					ID:       "CVE-2023-2650",
					Severity: "MEDIUM",
					Title:    "Possible DoS translating ASN.1 object identifier and executer",
				},
				"CVE-2023-2975": {
					ID:       "CVE-2023-2975",
					Severity: "HIGH",
					Title:    "AES-SIV cipher implementation contains a bug that can break",
				},
				"CVE-2023-3446": {
					ID:       "CVE-2023-3446",
					Severity: "CRITICAL",
					Title:    "Excessive time spent checking DH keys and parenthesis",
				},
				"CVE-2023-3817": {
					ID:       "CVE-2023-3817",
					Severity: "MEDIUM",
					Title:    "Excessive time spent checking DH q parameter and arguments",
				},
			}, nil
		},
	}

	go func() {
		if err := ctlr.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	defer ctlr.Shutdown()

	test.WaitTillServerReady(baseURL)

	space := regexp.MustCompile(`\s+`)

	Convey("test sorting", t, func() {
		args := []string{"list", "repo:tag", "--sort-by", "severity", "--url", baseURL}
		cmd := client.NewCVECommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldResemble,
			"ID SEVERITY TITLE "+
				"CVE-2023-3446 CRITICAL Excessive time spent checking DH keys and par... "+
				"CVE-2023-2975 HIGH AES-SIV cipher implementation contains a bug ... "+
				"CVE-2023-2650 MEDIUM Possible DoS translating ASN.1 object identif... "+
				"CVE-2023-3817 MEDIUM Excessive time spent checking DH q parameter ... "+
				"CVE-2023-1255 LOW Input buffer over-read in AES-XTS implementat...")

		args = []string{"list", "repo:tag", "--sort-by", "alpha-asc", "--url", baseURL}
		cmd = client.NewCVECommand(client.NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldResemble,
			"ID SEVERITY TITLE "+
				"CVE-2023-1255 LOW Input buffer over-read in AES-XTS implementat... "+
				"CVE-2023-2650 MEDIUM Possible DoS translating ASN.1 object identif... "+
				"CVE-2023-2975 HIGH AES-SIV cipher implementation contains a bug ... "+
				"CVE-2023-3446 CRITICAL Excessive time spent checking DH keys and par... "+
				"CVE-2023-3817 MEDIUM Excessive time spent checking DH q parameter ...")

		args = []string{"list", "repo:tag", "--sort-by", "alpha-dsc", "--url", baseURL}
		cmd = client.NewCVECommand(client.NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldResemble,
			"ID SEVERITY TITLE "+
				"CVE-2023-3817 MEDIUM Excessive time spent checking DH q parameter ... "+
				"CVE-2023-3446 CRITICAL Excessive time spent checking DH keys and par... "+
				"CVE-2023-2975 HIGH AES-SIV cipher implementation contains a bug ... "+
				"CVE-2023-2650 MEDIUM Possible DoS translating ASN.1 object identif... "+
				"CVE-2023-1255 LOW Input buffer over-read in AES-XTS implementat...")
	})
}

func getMockCveScanner(metaDB mTypes.MetaDB) cveinfo.Scanner {
	// MetaDB loaded with initial data now mock the scanner
	// Setup test CVE data in mock scanner
	scanner := mocks.CveScannerMock{
		ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
			if strings.Contains(image, "zot-cve-test@sha256:db573b01") ||
				image == "zot-cve-test:0.0.1" {
				return map[string]cvemodel.CVE{
					"CVE-1": {
						ID:          "CVE-1",
						Severity:    "CRITICAL",
						Title:       "Title for CVE-C1",
						Description: "Description of CVE-1",
					},
					"CVE-2019-9923": {
						ID:          "CVE-2019-9923",
						Severity:    "HIGH",
						Title:       "Title for CVE-2",
						Description: "Description of CVE-2",
					},
					"CVE-3": {
						ID:          "CVE-3",
						Severity:    "MEDIUM",
						Title:       "Title for CVE-3",
						Description: "Description of CVE-3",
					},
					"CVE-4": {
						ID:          "CVE-4",
						Severity:    "LOW",
						Title:       "Title for CVE-4",
						Description: "Description of CVE-4",
					},
					"CVE-5": {
						ID:          "CVE-5",
						Severity:    "UNKNOWN",
						Title:       "Title for CVE-5",
						Description: "Description of CVE-5",
					},
				}, nil
			}

			// By default the image has no vulnerabilities
			return map[string]cvemodel.CVE{}, nil
		},
		IsImageFormatScannableFn: func(repo string, reference string) (bool, error) {
			// Almost same logic compared to actual Trivy specific implementation
			imageDir := repo
			inputTag := reference

			repoMeta, err := metaDB.GetRepoMeta(context.Background(), imageDir)
			if err != nil {
				return false, err
			}

			manifestDigestStr := reference

			if zcommon.IsTag(reference) {
				var ok bool

				descriptor, ok := repoMeta.Tags[inputTag]
				if !ok {
					return false, zerr.ErrTagMetaNotFound
				}

				manifestDigestStr = descriptor.Digest
			}

			manifestDigest, err := godigest.Parse(manifestDigestStr)
			if err != nil {
				return false, err
			}

			manifestData, err := metaDB.GetImageMeta(manifestDigest)
			if err != nil {
				return false, err
			}

			for _, imageLayer := range manifestData.Manifests[0].Manifest.Layers {
				switch imageLayer.MediaType {
				case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):

					return true, nil
				default:

					return false, zerr.ErrScanNotSupported
				}
			}

			return false, nil
		},
	}

	return &scanner
}
