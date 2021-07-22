package httpauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	cache "github.com/patrickmn/go-cache"
	"go.uber.org/zap"
)

// AuthProvider is a function that given a username, password and request, authenticates the user.
type AuthProvider func(username string, password string, r *http.Request) (string, bool)

// BasicAuthWrapper provides a wrapper that can authenticate using basic auth headers.
type BasicAuthWrapper struct {
	Cache               *cache.Cache
	Realm               string
	Logger              *zap.Logger
	AuthFunc            AuthProvider
	UnauthorizedHandler http.Handler
	CacheDuration       time.Duration
}

// Require authentication, and serve our error handler otherwise.
func (b *BasicAuthWrapper) requestAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, b.Realm))
	b.UnauthorizedHandler.ServeHTTP(w, r)
}

// ErrBasicAuthInvalid is returned when the basic authentication is invalid (missing header, invalid request, etc).
var ErrBasicAuthInvalid = errors.New("basic auth invalid")

type cachedResponse struct {
	Username string
	Result   bool
}

// authenticate retrieves and then validates the user:password combination provided in
// the request header. Returns 'false' if the user has not successfully authenticated.
func (b *BasicAuthWrapper) authenticate(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}

	// If AuthFunc is missing, fail logins
	if b.AuthFunc == nil {
		return "", false
	}

	if v, ok := b.Cache.Get(r.Header.Get("Authorization")); ok {
		// ACL Record cached
		if resp, ok := v.(cachedResponse); ok {
			if resp.Result {
				r.URL.User = url.User(resp.Username)
			}

			return resp.Username, resp.Result
		}
	}

	givenUser, givenPass, err := GetBasicAuthFromRequest(r)
	if err != nil {
		return "", false
	}

	authUser, authResult := b.AuthFunc(givenUser, givenPass, r)
	b.Cache.Set(
		r.Header.Get("Authorization"),
		cachedResponse{
			Username: authUser,
			Result:   authResult,
		},
		b.CacheDuration,
	)

	if authResult {
		r.URL.User = url.User(authUser)
	}

	return authUser, authResult
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// GetBasicAuthFromRequest returns basic auth username and password given a `*http.Request`.
//nolint:gomnd // basic authentication format
func GetBasicAuthFromRequest(r *http.Request) (string, string, error) {
	const basicScheme string = "Basic "

	if r == nil {
		return "", "", fmt.Errorf("%w: request is nil", ErrBasicAuthInvalid)
	}

	// Confirm the request is sending Basic Authentication credentials.
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, basicScheme) {
		return "", "", fmt.Errorf("%w: basic auth headers missing", ErrBasicAuthInvalid)
	}

	// Get the plain-text username and password from the request.
	// The first six characters are skipped - e.g. "Basic ".
	str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
	if err != nil {
		return "", "", fmt.Errorf("unable to decode basic authentication; %w", err)
	}

	// Split on the first ":" character only, with any subsequent colons assumed to be part
	// of the password. Note that the RFC2617 standard does not place any limitations on
	// allowable characters in the password.
	creds := bytes.SplitN(str, []byte(":"), 2)

	if len(creds) != 2 {
		return "", "", ErrBasicAuthInvalid
	}

	return string(creds[0]), string(creds[1]), nil
}
