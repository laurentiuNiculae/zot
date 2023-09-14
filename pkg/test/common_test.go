//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package test_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	notconfig "github.com/notaryproject/notation-go/config"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
	testc "zotregistry.io/zot/pkg/test/common"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/inject"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("ErrTestError")

func TestGetOciLayoutDigests(t *testing.T) {
	dir := t.TempDir()

	Convey("image path is wrong", t, func() {
		So(func() { _, _, _ = test.GetOciLayoutDigests("inexistent-image") }, ShouldPanic)
	})

	Convey("no permissions when getting index", t, func() {
		storageCtlr := test.GetDefaultStoreController(dir, log.NewLogger("debug", ""))
		image := CreateDefaultImage()

		err := WriteImageToFileSystem(image, "test-index", "0.0.1", storageCtlr)
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test-index", "index.json"), 0o000)
		if err != nil {
			panic(err)
		}

		So(func() { _, _, _ = test.GetOciLayoutDigests(path.Join(dir, "test-index")) }, ShouldPanic)

		err = os.Chmod(path.Join(dir, "test-index", "index.json"), 0o755)
		if err != nil {
			panic(err)
		}
	})

	Convey("can't access manifest digest", t, func() {
		storageCtlr := test.GetDefaultStoreController(dir, log.NewLogger("debug", ""))
		image := CreateDefaultImage()

		err := WriteImageToFileSystem(image, "test-manifest", "0.0.1", storageCtlr)
		So(err, ShouldBeNil)

		buf, err := os.ReadFile(path.Join(dir, "test-manifest", "index.json"))
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		if err := json.Unmarshal(buf, &index); err != nil {
			panic(err)
		}

		err = os.Chmod(path.Join(dir, "test-manifest", "blobs/sha256", index.Manifests[0].Digest.Encoded()), 0o000)
		if err != nil {
			panic(err)
		}

		So(func() { _, _, _ = test.GetOciLayoutDigests(path.Join(dir, "test-manifest")) }, ShouldPanic)

		err = os.Chmod(path.Join(dir, "test-manifest", "blobs/sha256", index.Manifests[0].Digest.Encoded()), 0o755)
		if err != nil {
			panic(err)
		}
	})
}

func TestGetImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
	Convey("finishes successfully", t, func() {
		_, _, _, err := test.GetImageComponents(100)
		So(err, ShouldBeNil)
	})
}

func TestGetRandomImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetRandomImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
}

func TestGetImageComponentsWithConfig(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetImageComponentsWithConfig(ispec.Image{})
			So(err, ShouldNotBeNil)
		}
	})
}

func TestWaitTillTrivyDBDownloadStarted(t *testing.T) {
	Convey("finishes successfully", t, func() {
		tempDir := t.TempDir()
		go func() {
			test.WaitTillTrivyDBDownloadStarted(tempDir)
		}()

		time.Sleep(test.SleepTime)

		_, err := os.Create(path.Join(tempDir, "trivy.db"))
		So(err, ShouldBeNil)
	})
}

func TestControllerManager(t *testing.T) {
	Convey("Test StartServer Init() panic", t, func() {
		port := testc.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		// No storage configured
		So(func() { ctlrManager.StartServer() }, ShouldPanic)
	})

	Convey("Test RunServer panic", t, func() {
		tempDir := t.TempDir()

		// Invalid port
		conf := config.New()
		conf.HTTP.Port = "999999"
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		ctx := context.Background()

		err := ctlr.Init(ctx)
		So(err, ShouldBeNil)

		So(func() { ctlrManager.RunServer(ctx) }, ShouldPanic)
	})
}

func TestUploadMultiarchImage(t *testing.T) {
	Convey("make controller", t, func() {
		port := testc.GetFreePort()
		baseURL := testc.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := Image{
			Layers: [][]byte{
				layerBlob,
			},
			Manifest: ispec.Manifest{
				Versioned: specs.Versioned{
					SchemaVersion: 2,
				},
				Layers: []ispec.Descriptor{
					{
						Digest:    godigest.FromBytes(layerBlob),
						Size:      int64(len(layerBlob)),
						MediaType: ispec.MediaTypeImageLayerGzip,
					},
				},
				Config: ispec.DescriptorEmptyJSON,
			},
			Config: ispec.Image{},
		}

		manifestBuf, err := json.Marshal(img.Manifest)
		So(err, ShouldBeNil)

		Convey("Multiarch image uploaded successfully", func() {
			err = UploadMultiarchImage(MultiarchImage{
				Index: ispec.Index{
					Versioned: specs.Versioned{
						SchemaVersion: 2,
					},
					MediaType: ispec.MediaTypeImageIndex,
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromBytes(manifestBuf),
							Size:      int64(len(manifestBuf)),
						},
					},
				},
				Images: []Image{img},
			}, baseURL, "test", "index")
			So(err, ShouldBeNil)
		})

		Convey("Multiarch image without schemaVersion should fail validation", func() {
			err = UploadMultiarchImage(MultiarchImage{
				Index: ispec.Index{
					MediaType: ispec.MediaTypeImageIndex,
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromBytes(manifestBuf),
							Size:      int64(len(manifestBuf)),
						},
					},
				},
				Images: []Image{img},
			}, baseURL, "test", "index")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestReadLogFileAndSearchString(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = test.ReadLogFileAndSearchString("invalidPath", "DB update completed, next update scheduled", 1*time.Second)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := test.ReadLogFileAndSearchString(logPath, "invalid string", time.Microsecond)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})
}

func TestReadLogFileAndCountStringOccurence(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	_, err = logFile.Write([]byte("line1\n line2\n line3 line1 line2\n line1"))
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = test.ReadLogFileAndCountStringOccurence("invalidPath",
			"DB update completed, next update scheduled", 1*time.Second, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := test.ReadLogFileAndCountStringOccurence(logPath, "invalid string", time.Microsecond, 1)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})

	Convey("Count occurrence working", t, func() {
		ok, err := test.ReadLogFileAndCountStringOccurence(logPath, "line1", 90*time.Second, 3)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
	})
}

func TestInjectUploadImageWithBasicAuth(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		port := testc.GetFreePort()
		baseURL := testc.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		user := "user"
		password := "password"
		testString := test.GetCredString(user, password)
		htpasswdPath := test.MakeHtpasswdFileFromString(testString)
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")
		layerPath := path.Join(tempDir, "test", ".uploads")

		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			err = os.MkdirAll(layerPath, 0o700)
			if err != nil {
				t.Fatal(err)
			}
		}

		img := Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		Convey("first marshal", func() {
			injected := inject.InjectFailure(0)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("CreateBlobUpload POST call", func() {
			injected := inject.InjectFailure(1)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload PUT call", func() {
			injected := inject.InjectFailure(3)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("second marshal", func() {
			injected := inject.InjectFailure(5)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func TestCopyFile(t *testing.T) {
	Convey("destFilePath does not exist", t, func() {
		err := test.CopyFile("/path/to/srcFile", "~/path/to/some/unexisting/destDir/file")
		So(err, ShouldNotBeNil)
	})

	Convey("sourceFile does not exist", t, func() {
		err := test.CopyFile("/path/to/some/unexisting/file", path.Join(t.TempDir(), "destFile.txt"))
		So(err, ShouldNotBeNil)
	})
}

func TestIsDigestReference(t *testing.T) {
	Convey("not digest reference", t, func() {
		res := test.IsDigestReference("notDigestReference/input")
		So(res, ShouldBeFalse)
	})

	Convey("wrong input format", t, func() {
		res := test.IsDigestReference("wrongInput")
		So(res, ShouldBeFalse)
	})
}

func TestLoadNotationSigningkeys(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		_, err := test.LoadNotationSigningkeys(t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("wrong content of signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("not enough permissions to access signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o300) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("signingkeys.json not exists so it is created successfully", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldBeNil)
	})

	Convey("signingkeys.json not exists - error trying to create it", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		// create notation directory without write permissions
		err := os.Mkdir(dir, 0o555)
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})
}

func TestLoadNotationConfig(t *testing.T) {
	Convey("directory doesn't exist", t, func() {
		_, err := test.LoadNotationConfig(t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("wrong content of signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationConfig(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("check default value of signature format", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("{\"SignatureFormat\": \"\"}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		configInfo, err := test.LoadNotationConfig(tempDir)
		So(err, ShouldBeNil)
		So(configInfo.SignatureFormat, ShouldEqual, "jws")
	})
}

func TestSignWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := test.SignWithNotation("key", "reference", t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("key not found", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "reference", tempDir)
		So(err, ShouldEqual, test.ErrKeyNotFound)
	})

	Convey("not enough permissions to access notation/localkeys dir", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(tdir, "notation", "localkeys"), 0o000)
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "reference", tdir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(tdir, "notation", "localkeys"), 0o755)
		So(err, ShouldBeNil)
	})

	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error signing", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})
}

func TestVerifyWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := test.VerifyWithNotation("reference", t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.VerifyWithNotation("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.VerifyWithNotation("localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("invalid content of trustpolicy.json", t, func() {
		// start a new server
		port := testc.GetFreePort()
		baseURL := testc.GetBaseURL(port)
		dir := t.TempDir()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)
		// this blocks
		cm.StartAndWait(port)
		defer cm.StopServer()

		repoName := "signed-repo"
		tag := "1.0"
		cfg, layers, manifest, err := test.GetImageComponents(2)
		So(err, ShouldBeNil)

		err = UploadImage(
			Image{
				Config:   cfg,
				Layers:   layers,
				Manifest: manifest,
			}, baseURL, repoName, tag)
		So(err, ShouldBeNil)

		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		tempDir := t.TempDir()
		notationDir := path.Join(tempDir, "notation")
		err = os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "trustpolicy.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.VerifyWithNotation(fmt.Sprintf("localhost:%s/%s:%s", port, repoName, tag), tempDir)
		So(err, ShouldNotBeNil)
	})
}

func TestListNotarySignatures(t *testing.T) {
	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		_, err = test.ListNotarySignatures("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		_, err = test.ListNotarySignatures("localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})
}

func TestGenerateNotationCerts(t *testing.T) {
	Convey("write key file with permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "localkeys")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)
	})

	Convey("write cert file with permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation", "localkeys")
		err := os.MkdirAll(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "cert.crt")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.Chmod(filePath, 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)

		err = os.Chmod(filePath, 0o755)
		So(err, ShouldBeNil)
	})

	Convey("signingkeys.json file - not enough permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "signingkeys.json")
		_, err = os.Create(filePath) //nolint: gosec
		So(err, ShouldBeNil)
		err = os.Chmod(filePath, 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)

		err = os.Remove(filePath)
		So(err, ShouldBeNil)
		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		signingKeysBuf, err := json.Marshal(notconfig.SigningKeys{})
		So(err, ShouldBeNil)
		err = os.WriteFile(filePath, signingKeysBuf, 0o555) //nolint:gosec // test code
		So(err, ShouldBeNil)
		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)
	})
	Convey("keysuite already exists in signingkeys.json", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		certName := "cert-test"
		filePath := path.Join(notationDir, "signingkeys.json")
		keyPath := path.Join(notationDir, "localkeys", certName+".key")
		certPath := path.Join(notationDir, "localkeys", certName+".crt")
		signingKeys := notconfig.SigningKeys{}
		keySuite := notconfig.KeySuite{
			Name: certName,
			X509KeyPair: &notconfig.X509KeyPair{
				KeyPath:         keyPath,
				CertificatePath: certPath,
			},
		}
		signingKeys.Keys = []notconfig.KeySuite{keySuite}
		signingKeysBuf, err := json.Marshal(signingKeys)
		So(err, ShouldBeNil)
		err = os.WriteFile(filePath, signingKeysBuf, 0o600)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), certName)
		So(err, ShouldNotBeNil)
	})
	Convey("truststore files", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		certName := "cert-test"
		trustStorePath := path.Join(notationDir, fmt.Sprintf("truststore/x509/ca/%s", certName))
		err = os.MkdirAll(trustStorePath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509"), 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509"), 0o755)
		So(err, ShouldBeNil)
		_, err = os.Create(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Remove(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca", certName), 0o555)
		So(err, ShouldBeNil)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)
	})
}

func TestWriteImageToFileSystem(t *testing.T) {
	Convey("WriteImageToFileSystem errors", t, func() {
		err := WriteImageToFileSystem(Image{}, "repo", "dig", storage.StoreController{
			DefaultStore: mocks.MockedImageStore{
				InitRepoFn: func(name string) error {
					return ErrTestError
				},
			},
		})
		So(err, ShouldNotBeNil)

		err = WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		count := 0
		err = WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						if count == 0 {
							count++

							return "", 0, nil
						}

						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		err = WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte,
					) (godigest.Digest, godigest.Digest, error) {
						return "", "", ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)
	})
}

func TestBearerServer(t *testing.T) {
	Convey("test MakeAuthTestServer() no serve key", t, func() {
		So(func() { test.MakeAuthTestServer("", "") }, ShouldPanic)
	})
}
