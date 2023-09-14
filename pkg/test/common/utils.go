package common

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/phayes/freeport"
	"gopkg.in/resty.v1"
)

const (
	BaseURL       = "http://127.0.0.1:%s"
	BaseSecureURL = "https://127.0.0.1:%s"
	SleepTime     = 100 * time.Millisecond
)

type isser interface {
	Is(string) bool
}

// Index returns the index of the first occurrence of name in s,
// or -1 if not present.
func Index[E isser](s []E, name string) int {
	for i, v := range s {
		if v.Is(name) {
			return i
		}
	}

	return -1
}

// Contains reports whether name is present in s.
func Contains[E isser](s []E, name string) bool {
	return Index(s, name) >= 0
}

func Location(baseURL string, resp *resty.Response) string {
	// For some API responses, the Location header is set and is supposed to
	// indicate an opaque value. However, it is not clear if this value is an
	// absolute URL (https://server:port/v2/...) or just a path (/v2/...)
	// zot implements the latter as per the spec, but some registries appear to
	// return the former - this needs to be clarified
	loc := resp.Header().Get("Location")

	uloc, err := url.Parse(loc)
	if err != nil {
		return ""
	}

	path := uloc.Path

	return baseURL + path
}

func WaitTillServerReady(url string) {
	for {
		_, err := resty.R().Get(url)
		if err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

func WaitTillTrivyDBDownloadStarted(rootDir string) {
	for {
		if _, err := os.Stat(path.Join(rootDir, "_trivy", "db", "trivy.db")); err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

func GetFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	return fmt.Sprint(port)
}

func GetBaseURL(port string) string {
	return fmt.Sprintf(BaseURL, port)
}

func GetSecureBaseURL(port string) string {
	return fmt.Sprintf(BaseSecureURL, port)
}
