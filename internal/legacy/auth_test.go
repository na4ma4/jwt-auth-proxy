package legacy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/na4ma4/jwt-auth-proxy/internal/legacy"
)

func TestLegacyAuth_Success(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	tests := []struct {
		name                     string
		username, password, hash string
	}{
		{
			"bcrypt(totally-secure-password)",
			"joey-bloggs", "totally-secure-password", "$2a$15$kbSk7OIgk0vHD4vYgShdMO7uGICkpiATpydRl5GnKrBJuBLcM0.yu",
		},
		{
			"bcrypt(another-password)",
			"jason-bloggs", "another-password", "$2a$15$GhI/8ct3YlhHlnJOd2/l8Ot2.BsYc058N/5XD9RAIsM8zGIvp6pPW",
		},
		{
			"bcrypt(ioC3phohShae1yiw5uedaed9beuroaRu)",
			"julie-bloggs", "ioC3phohShae1yiw5uedaed9beuroaRu", "$2a$15$kuaray2aouiQbjoJlhYeFuPanlEUN5R/S5qh/lnlJhw5r7.XX82xq",
		},
		{
			"plain(totally-secure-password)",
			"joey-bloggs", "totally-secure-password", "totally-secure-password",
		},
		{
			"plain(another-password)",
			"jason-bloggs", "another-password", "another-password",
		},
		{
			"plain(ioC3phohShae1yiw5uedaed9beuroaRu)",
			"julie-bloggs", "ioC3phohShae1yiw5uedaed9beuroaRu", "ioC3phohShae1yiw5uedaed9beuroaRu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			logger := newLogger()

			legacyAuthItems := map[string]legacy.AuthItem{
				tt.username: {
					Username: tt.username,
					Password: tt.hash,
				},
			}

			authFunc := legacy.AuthCheckFunc(logger, legacyAuthItems, denyAuthFunc)
			user, ok := authFunc(tt.username, tt.password, req)
			if user != tt.username {
				t.Errorf("authFunc(%s, %s, %s) username = %s, want %s", tt.username, tt.password, tt.hash, user, tt.username)
			}
			if !ok {
				t.Errorf("authFunc(%s, %s, %s) ok = %t, want %t", tt.username, tt.password, tt.hash, ok, true)
			}
		})
	}
}

func TestLegacyAuth_Fail(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	tests := []struct {
		name                     string
		username, password, hash string
	}{
		{
			"bcrypt(totally-secure-password)",
			"joey-bloggs", "totally-secure-password2", "$2a$15$kbSk7OIgk0vHD4vYgShdMO7uGICkpiATpydRl5GnKrBJuBLcM0.yu",
		},
		{
			"bcrypt(another-password)",
			"jason-bloggs", "another-password2", "$2a$15$GhI/8ct3YlhHlnJOd2/l8Ot2.BsYc058N/5XD9RAIsM8zGIvp6pPW",
		},
		{
			"bcrypt(ioC3phohShae1yiw5uedaed9beuroaRu)",
			"julie-bloggs", "ioC3phohShae1yiw5uedaed9beuroaRu2", "$2a$15$kuaray2aouiQbjoJlhYeFuPanlEUN5R/S5qh/lnlJhw5r7.XX82xq",
		},
		{
			"using hash as password:bcrypt($2a$15$kuaray2aouiQbjoJlhYeFuPanlEUN5R/S5qh/lnlJhw5r7.XX82xq)",
			"julie-bloggs", "$2a$15$kuaray2aouiQbjoJlhYeFuPanlEUN5R/S5qh/lnlJhw5r7.XX82xq",
			"$2a$15$kuaray2aouiQbjoJlhYeFuPanlEUN5R/S5qh/lnlJhw5r7.XX82xq",
		},
		{
			"plain(totally-secure-password)",
			"joey-bloggs", "totally-secure-password2", "totally-secure-password",
		},
		{
			"plain(another-password)",
			"jason-bloggs", "another-password2", "another-password",
		},
		{
			"plain(ioC3phohShae1yiw5uedaed9beuroaRu)",
			"julie-bloggs", "ioC3phohShae1yiw5uedaed9beuroaRu2", "ioC3phohShae1yiw5uedaed9beuroaRu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			logger := newLogger()

			legacyAuthItems := map[string]legacy.AuthItem{
				tt.username: {
					Username: tt.username,
					Password: tt.hash,
				},
			}

			authFunc := legacy.AuthCheckFunc(logger, legacyAuthItems, denyAuthFunc)
			user, ok := authFunc(tt.username, tt.password, req)
			if user != "" {
				t.Errorf("authFunc(%s, %s, %s) username ='%s', want '%s'", tt.username, tt.password, tt.hash, user, "")
			}
			if ok {
				t.Errorf("authFunc(%s, %s, %s) ok = %t, want %t", tt.username, tt.password, tt.hash, ok, false)
			}
		})
	}
}

func TestLegacyAuth_Fail_MixedPassword(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	tests := []struct {
		name                                      string
		username, password, passwordAttempt, hash string
	}{
		{
			"plain password (totally-secure/totally-secure-password)",
			"joey-bloggs", "totally-secure-password", "totally-secure", "totally-secure-password",
		},
		{
			"plain password (ioC3phohShae1yiw5uedaed9beuroaRu/another-password)",
			"jason-bloggs", "another-password", "ioC3phohShae1yiw5uedaed9beuroaRu", "another-password",
		},
		{
			"sending bcrypt hash as password",
			"julie-bloggs",
			"ioC3phohShae1yiw5uedaed9beuroaRu",
			"$2a$15$kuaray2aouiQbjoJlhYeFuPanlEUN5R/S5qh/lnlJhw5r7.XX82xq",
			"$2a$15$kuaray2aouiQbjoJlhYeFuPanlEUN5R/S5qh/lnlJhw5r7.XX82xq",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			logger := newLogger()

			legacyAuthItems := map[string]legacy.AuthItem{
				tt.username: {
					Username: tt.username,
					Password: tt.hash,
				},
			}

			authFunc := legacy.AuthCheckFunc(logger, legacyAuthItems, denyAuthFunc)
			user, ok := authFunc(tt.username, tt.passwordAttempt, req)
			if user != "" {
				t.Errorf("authFunc(%s, %s, %s) username ='%s', want '%s'", tt.username, tt.password, tt.hash, user, "")
			}
			if ok {
				t.Errorf("authFunc(%s, %s, %s) ok = %t, want %t", tt.username, tt.password, tt.hash, ok, false)
			}
		})
	}
}
