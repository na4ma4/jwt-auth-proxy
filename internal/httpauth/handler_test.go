package httpauth_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestHTTPAuth_NoAuth(t *testing.T) {
	ts := newAuthenticator()

	c := ts.Client()
	res, resErr := c.Get(ts.URL)
	if resErr != nil {
		t.Errorf("http.Client.Get(%s) got '%v', want '%v'", ts.URL, resErr, nil)
	}

	expectEqual(t, "res.StatusCode", res.StatusCode, http.StatusUnauthorized)
	expectEqual(t, "res.Status", res.Status, "401 Unauthorized")

	if v := res.Header.Get("WWW-Authenticate"); !strings.Contains(v, `realm="im-a-test-realm"`) {
		t.Errorf("res.StatusCode got '%s', want to contain '%s'", v, `realm="im-a-test-realm"`)
	}

	expectNotSuccessBody(t, res)
}

func TestHTTPAuth_NoAuthBypass(t *testing.T) {
	ts := newAuthenticator()

	c := ts.Client()
	res, resErr := c.Get(ts.URL + "/v2/")
	if resErr != nil {
		t.Errorf("http.Client.Get(%s) got '%v', want '%v'", ts.URL+"/v2/", resErr, nil)
	}

	expectEqual(t, "res.StatusCode", res.StatusCode, http.StatusOK)
	expectEqual(t, "res.Status", res.Status, "200 OK")
	expectEqual(t, "Header[WWW-Authenticate]", res.Header.Get("WWW-Authenticate"), "")

	expectSuccessBody(t, res)
}

func TestHTTPAuth_ValidAuth(t *testing.T) {
	ts := newAuthenticator()

	c := ts.Client()
	r, reqErr := http.NewRequest(http.MethodGet, ts.URL, nil)
	if reqErr != nil {
		t.Errorf("http.NewRequest(%s) got '%v', want '%v'", ts.URL, reqErr, nil)
	}
	r.SetBasicAuth("test", "valid-pass")

	res, resErr := c.Do(r)
	if resErr != nil {
		t.Errorf("http.Client.Do(%s) got '%v', want '%v'", ts.URL, resErr, nil)
	}

	expectEqual(t, "res.StatusCode", res.StatusCode, http.StatusOK)
	expectEqual(t, "res.Status", res.Status, "200 OK")
	expectEqual(t, "Header[WWW-Authenticate]", res.Header.Get("WWW-Authenticate"), "")

	expectSuccessBody(t, res)
}

func TestHTTPAuth_ValidAuthBypass(t *testing.T) {
	ts := newAuthenticator()

	c := ts.Client()
	r, reqErr := http.NewRequest(http.MethodGet, ts.URL+"/v2/subpath", nil)
	if reqErr != nil {
		t.Errorf("http.NewRequest(%s) got '%v', want '%v'", ts.URL+"/v2/subpath", reqErr, nil)
	}
	r.SetBasicAuth("test", "valid-pass")

	res, resErr := c.Do(r)
	if resErr != nil {
		t.Errorf("http.Client.Do(%s) got '%v', want '%v'", ts.URL+"/v2/subpath", resErr, nil)
	}

	expectEqual(t, "res.StatusCode", res.StatusCode, http.StatusOK)
	expectEqual(t, "res.Status", res.Status, "200 OK")
	expectEqual(t, "Header[WWW-Authenticate]", res.Header.Get("WWW-Authenticate"), "")

	expectSuccessBody(t, res)
}

func TestHTTPAuth_InvalidAuth(t *testing.T) {
	ts := newAuthenticator()
	c := ts.Client()
	r, reqErr := http.NewRequest(http.MethodGet, ts.URL, nil)
	if reqErr != nil {
		t.Errorf("http.NewRequest(%s) got '%v', want '%v'", ts.URL, reqErr, nil)
	}
	r.SetBasicAuth("test", "invalid-pass")

	res, resErr := c.Do(r)
	if resErr != nil {
		t.Errorf("http.Client.Do(%s) got '%v', want '%v'", ts.URL, resErr, nil)
	}

	expectEqual(t, "res.StatusCode", res.StatusCode, http.StatusUnauthorized)
	expectEqual(t, "res.Status", res.Status, "401 Unauthorized")

	if v := res.Header.Get("WWW-Authenticate"); !strings.Contains(v, `realm="im-a-test-realm"`) {
		t.Errorf("res.StatusCode got '%s', want to contain '%s'", v, `realm="im-a-test-realm"`)
	}

	expectNotSuccessBody(t, res)
}

func TestHTTPAuth_NoAuthBypassSubdir(t *testing.T) {
	ts := newAuthenticator()
	c := ts.Client()
	res, resErr := c.Get(ts.URL + "/v2/subpath")
	if resErr != nil {
		t.Errorf("http.Client.Do(%s) got '%v', want '%v'", ts.URL, resErr, nil)
	}

	expectEqual(t, "res.StatusCode", res.StatusCode, http.StatusUnauthorized)
	expectEqual(t, "res.Status", res.Status, "401 Unauthorized")

	if v := res.Header.Get("WWW-Authenticate"); !strings.Contains(v, `realm="im-a-test-realm"`) {
		t.Errorf("res.StatusCode got '%s', want to contain '%s'", v, `realm="im-a-test-realm"`)
	}

	expectNotSuccessBody(t, res)
}
