package httpauth

import (
	"net/http"
	"strings"
)

// BasicAuthHandler is a http.Handler that uses BasicAuthWrapper to provide basic authentication support.
type BasicAuthHandler struct {
	Handler     http.Handler
	RemoveAuth  bool
	BypassPaths []string

	*BasicAuthWrapper
}

// ServeHTTP Satisfies the http.Handler interface for basicAuth.
func (b *BasicAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		username string
		ok       bool
	)

	if len(b.BypassPaths) > 0 {
		for _, bypassPath := range b.BypassPaths {
			if strings.HasPrefix(r.RequestURI, bypassPath) {
				b.Handler.ServeHTTP(w, r)

				return
			}
		}
	}

	// Check if we have a user-provided error handler, else set a default
	if b.UnauthorizedHandler == nil {
		b.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}

	// Check that the provided details match
	if username, ok = b.authenticate(r); !ok {
		b.requestAuth(w, r)

		return
	}

	if b.RemoveAuth {
		r.Header.Set("X-Username", username)
		r.Header.Del("Authorization")
	}

	// Call the next handler on success.
	b.Handler.ServeHTTP(w, r)
}
