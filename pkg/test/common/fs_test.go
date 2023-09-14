package common_test

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	testc "zotregistry.io/zot/pkg/test/common"
)

var ErrTestError = errors.New("ErrTestError")

func TestCopyFiles(t *testing.T) {
	Convey("sourceDir does not exist", t, func() {
		err := testc.CopyFiles("/path/to/some/unexisting/directory", os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("destDir is a file", t, func() {
		dir := t.TempDir()

		testc.CopyTestFiles("../../test/data", dir)

		err := testc.CopyFiles(dir, "/etc/passwd")
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir does not have read permissions", t, func() {
		dir := t.TempDir()

		err := os.Chmod(dir, 0o300)
		So(err, ShouldBeNil)

		err = testc.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a subfolder that does not have read permissions", t, func() {
		dir := t.TempDir()

		sdir := "subdir"
		err := os.Mkdir(path.Join(dir, sdir), 0o300)
		So(err, ShouldBeNil)

		err = testc.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a file that does not have read permissions", t, func() {
		dir := t.TempDir()

		filePath := path.Join(dir, "file.txt")
		err := os.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(filePath, 0o300)
		So(err, ShouldBeNil)

		err = testc.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir contains a folder starting with invalid characters", t, func() {
		srcDir := t.TempDir()
		dstDir := t.TempDir()

		err := os.MkdirAll(path.Join(srcDir, "_trivy", "db"), 0o755)
		if err != nil {
			panic(err)
		}

		err = os.MkdirAll(path.Join(srcDir, "test-index"), 0o755)
		if err != nil {
			panic(err)
		}

		filePathTrivy := path.Join(srcDir, "_trivy", "db", "trivy.db")
		err = os.WriteFile(filePathTrivy, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		content, err := json.Marshal(index)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(srcDir, "test-index", "index.json"), content, 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = testc.CopyFiles(srcDir, dstDir)
		So(err, ShouldBeNil)

		_, err = os.Stat(path.Join(dstDir, "_trivy", "db", "trivy.db"))
		So(err, ShouldNotBeNil)
		So(os.IsNotExist(err), ShouldBeTrue)

		_, err = os.Stat(path.Join(dstDir, "test-index", "index.json"))
		So(err, ShouldBeNil)
	})
	Convey("panic when sourceDir does not exist", t, func() {
		So(func() { testc.CopyTestFiles("/path/to/some/unexisting/directory", os.TempDir()) }, ShouldPanic)
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
		_, err = testc.ReadLogFileAndSearchString("invalidPath", "DB update completed, next update scheduled", 1*time.Second)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := testc.ReadLogFileAndSearchString(logPath, "invalid string", time.Microsecond)
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
		_, err = testc.ReadLogFileAndCountStringOccurence("invalidPath",
			"DB update completed, next update scheduled", 1*time.Second, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := testc.ReadLogFileAndCountStringOccurence(logPath, "invalid string", time.Microsecond, 1)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})

	Convey("Count occurrence working", t, func() {
		ok, err := testc.ReadLogFileAndCountStringOccurence(logPath, "line1", 90*time.Second, 3)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
	})
}

func TestCopyTestKeysAndCerts(t *testing.T) {
	Convey("CopyTestKeysAndCerts", t, func() {
		// ------- Make test files unreadable -------
		dir := t.TempDir()
		file := filepath.Join(dir, "ca.crt")

		_, err := os.Create(file)
		So(err, ShouldBeNil)

		err = os.Chmod(file, 0o000)
		So(err, ShouldBeNil)

		err = testc.CopyTestKeysAndCerts(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(file, 0o777)
		So(err, ShouldBeNil)

		// ------- Copy fails -------

		err = os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		err = testc.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o777)
		So(err, ShouldBeNil)

		// ------- Folder creation fails -------

		file = filepath.Join(dir, "a-file.file")
		_, err = os.Create(file)
		So(err, ShouldBeNil)

		_, err = os.Stat(file)
		So(err, ShouldBeNil)

		err = testc.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)
	})
}
