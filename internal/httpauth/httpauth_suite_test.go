package httpauth_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/na4ma4/jwt-auth-proxy/internal/httpauth"
	cache "github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func expectEqual(t *testing.T, name string, x, y interface{}) {
	t.Helper()
	if !cmp.Equal(x, y) {
		t.Errorf("%s got '%v', want '%v'", name, x, y)
	}
}

//nolint:gochecknoglobals // constants for tests.
var (
	successContent = []byte("Hello World!")

	authFunc = func(username string, password string, r *http.Request) (string, bool) {
		if v, ok := map[string]string{
			"test": "valid-pass",
		}[username]; ok {
			if strings.Compare(v, password) == 0 {
				return username, true
			}
		}

		return "", false
	}
)

func expectSuccessBody(t *testing.T, res *http.Response) {
	t.Helper()
	p := make([]byte, len(successContent))
	_, rdrErr := res.Body.Read(p)
	if rdrErr != nil && !errors.Is(rdrErr, io.EOF) {
		t.Errorf("expectSuccessBody:http.Response.Body.Read() got '%v', want '%v'", rdrErr, nil)
	}

	if diff := cmp.Diff(successContent, p); diff != "" {
		t.Errorf("expectSuccessBody:http.Response.Body mismatch (-want +got):\n%s", diff)
	}
}

func expectNotSuccessBody(t *testing.T, res *http.Response) {
	t.Helper()
	p := make([]byte, len(successContent))
	_, rdrErr := res.Body.Read(p)
	if rdrErr != nil && !errors.Is(rdrErr, io.EOF) {
		t.Errorf("expectNotSuccessBody:http.Response.Body.Read() got '%v', want '%v'", rdrErr, nil)
	}

	if cmp.Equal(successContent, p) {
		t.Errorf("expectNotSuccessBody:http.Response.Body got '%s', want different", p)
	}
}

func newAuthenticator() *httptest.Server {
	// logcore, logobs = observer.New(zap.DebugLevel)
	logcore, _ := observer.New(zap.DebugLevel)
	logger := zap.New(logcore)

	authenticator := &httpauth.BasicAuthHandler{
		BypassPaths: []string{"/v2/"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(successContent)
		}),
		RemoveAuth: true,
		BasicAuthWrapper: &httpauth.BasicAuthWrapper{
			Cache:         cache.New(time.Minute, time.Minute),
			Realm:         "im-a-test-realm",
			AuthFunc:      authFunc,
			Logger:        logger,
			CacheDuration: time.Minute,
		},
	}

	svr := httptest.NewTLSServer(authenticator)
	return svr
}
