//go:build userprefs
// +build userprefs

package extensions_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/extensions"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/log"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestAllowedMethodsHeaderUserPrefs(t *testing.T) {
	defaultVal := true

	Convey("Test http options response", t, func() {
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			},
		}
		baseURL := test.GetBaseURL(port)

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)
		defer ctrlManager.StopServer()

		resp, _ := resty.R().Options(baseURL + constants.FullUserPreferencesPrefix)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "PUT,OPTIONS")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
	})
}

func TestHandlers(t *testing.T) {
	const UserprefsBaseURL = "http://127.0.0.1:8080/v2/_zot/ext/userprefs"

	log := log.NewLogger("debug", "")
	mockmetaDB := mocks.MetaDBMock{}

	Convey("No repo in request", t, func() {
		request := httptest.NewRequest(http.MethodGet, UserprefsBaseURL+"", strings.NewReader("My string"))
		response := httptest.NewRecorder()

		extensions.PutStar(response, request, mockmetaDB, log)
		res := response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusBadRequest)
		defer res.Body.Close()

		extensions.PutBookmark(response, request, mockmetaDB, log)
		res = response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusBadRequest)
		defer res.Body.Close()
	})

	Convey("Empty repo in request", t, func() {
		request := httptest.NewRequest(http.MethodGet, UserprefsBaseURL+"?repo=", strings.NewReader("My string"))
		response := httptest.NewRecorder()

		extensions.PutStar(response, request, mockmetaDB, log)
		res := response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusNotFound)
		defer res.Body.Close()

		extensions.PutBookmark(response, request, mockmetaDB, log)
		res = response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusNotFound)
		defer res.Body.Close()
	})

	Convey("ToggleStarRepo different errors", t, func() {
		request := httptest.NewRequest(http.MethodGet, UserprefsBaseURL+"?repo=test",
			strings.NewReader("My string"))

		Convey("ErrRepoMetaNotFound", func() {
			mockmetaDB.ToggleStarRepoFn = func(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
				return metaTypes.NotChanged, zerr.ErrRepoMetaNotFound
			}

			mockmetaDB.ToggleBookmarkRepoFn = func(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
				return metaTypes.NotChanged, zerr.ErrRepoMetaNotFound
			}

			response := httptest.NewRecorder()
			extensions.PutBookmark(response, request, mockmetaDB, log)
			res := response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusNotFound)
			defer res.Body.Close()

			response = httptest.NewRecorder()
			extensions.PutStar(response, request, mockmetaDB, log)
			res = response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusNotFound)
			defer res.Body.Close()
		})

		Convey("ErrUserDataNotAllowed", func() {
			request = mux.SetURLVars(request, map[string]string{
				"name": "repo",
			})

			mockmetaDB.ToggleBookmarkRepoFn = func(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
				return metaTypes.NotChanged, zerr.ErrUserDataNotAllowed
			}

			mockmetaDB.ToggleStarRepoFn = func(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
				return metaTypes.NotChanged, zerr.ErrUserDataNotAllowed
			}

			response := httptest.NewRecorder()
			extensions.PutBookmark(response, request, mockmetaDB, log)
			res := response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusForbidden)
			defer res.Body.Close()

			response = httptest.NewRecorder()
			extensions.PutStar(response, request, mockmetaDB, log)
			res = response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusForbidden)
			defer res.Body.Close()
		})

		Convey("ErrUnexpectedError", func() {
			request = mux.SetURLVars(request, map[string]string{
				"name": "repo",
			})

			mockmetaDB.ToggleBookmarkRepoFn = func(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
				return metaTypes.NotChanged, ErrTestError
			}

			mockmetaDB.ToggleStarRepoFn = func(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
				return metaTypes.NotChanged, ErrTestError
			}
			response := httptest.NewRecorder()
			extensions.PutBookmark(response, request, mockmetaDB, log)
			res := response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusInternalServerError)
			defer res.Body.Close()

			response = httptest.NewRecorder()
			extensions.PutStar(response, request, mockmetaDB, log)
			res = response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusInternalServerError)
			defer res.Body.Close()
		})
	})
}
