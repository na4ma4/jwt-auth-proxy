//nolint:gochecknoglobals // Testing
package jwtauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/na4ma4/jwt-auth-proxy/internal/jwtauth"
	"github.com/na4ma4/jwt/v2"
	"go.uber.org/zap"
)

func newSignerVerifier(t *testing.T) (*jwt.RSASigner, *jwt.RSAVerifier) {
	t.Helper()

	privatekey, pkErr := rsa.GenerateKey(rand.Reader, 2048)
	if pkErr != nil {
		t.Errorf("rsa.GenerateKey() got '%v', want '%v'", pkErr, nil)
	}
	signer := &jwt.RSASigner{
		PrivateKey: privatekey,
		Algorithm:  jwt.RS256,
	}
	verifier := &jwt.RSAVerifier{
		PublicKey: &privatekey.PublicKey,
		Audiences: []string{validAudienceA, validAudienceB},
	}

	return signer, verifier
}

func newTestRunner(verifier *jwt.RSAVerifier) (context.CancelFunc, chan *jwtauth.AuthRequest) {
	appContext, appCancel := context.WithCancel(context.Background())
	authChan := make(chan *jwtauth.AuthRequest)
	logger := zap.NewNop()
	go jwtauth.AuthRunner(appContext, logger, verifier, authChan)

	return appCancel, authChan
}

var ignoreDynamicResponse = cmpopts.IgnoreFields(
	jwtauth.AuthResponse{},
	"Result.ID",
	"Result.Expires",
	"Result.NotBefore",
	"Result.Claims",
)

var ignoreDynamicResponseWithError = cmpopts.IgnoreFields(
	jwtauth.AuthResponse{},
	"Error",
)

func TestJWTAuthRunner_Success_ValidAudienceA(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	appCancel, authChan := newTestRunner(verifier)
	defer appCancel()
	go func() {
		time.Sleep(time.Second)
		appCancel()
	}()

	token, tokenErr := signer.SignClaims(genClaims("test-user", []string{validAudienceA})...)
	if tokenErr != nil {
		t.Errorf("signer.SignClaims() got '%v', want '%v'", tokenErr, nil)
	}

	authResp := make(chan *jwtauth.AuthResponse)

	authChan <- &jwtauth.AuthRequest{
		Token:         token,
		ReturnChannel: authResp,
	}

	for resp := range authResp {
		expectResp := &jwtauth.AuthResponse{
			Error: nil,
			Result: jwt.VerifyResult{
				Audience: jwt.AudienceSlice{
					validAudienceA,
				},
				ClaimAudiences: jwt.AudienceSlice{
					validAudienceA,
				},
				Subject: "test-user",
			},
		}

		if diff := cmp.Diff(expectResp, resp, ignoreDynamicResponse); diff != "" {
			t.Errorf("jwtauth.AuthResponse() mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestJWTAuthRunner_Success_ValidAudienceB(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	appCancel, authChan := newTestRunner(verifier)
	defer appCancel()
	go func() {
		time.Sleep(time.Second)
		appCancel()
	}()

	testUserName := uuid.New().String()

	token, tokenErr := signer.SignClaims(genClaims(testUserName, []string{validAudienceB})...)
	if tokenErr != nil {
		t.Errorf("signer.SignClaims() got '%v', want '%v'", tokenErr, nil)
	}

	authResp := make(chan *jwtauth.AuthResponse)

	authChan <- &jwtauth.AuthRequest{
		Token:         token,
		ReturnChannel: authResp,
	}

	for resp := range authResp {
		expectResp := &jwtauth.AuthResponse{
			Error: nil,
			Result: jwt.VerifyResult{
				Audience: jwt.AudienceSlice{
					validAudienceB,
				},
				ClaimAudiences: jwt.AudienceSlice{
					validAudienceB,
				},
				Subject: testUserName,
			},
		}

		if diff := cmp.Diff(expectResp, resp, ignoreDynamicResponse); diff != "" {
			t.Errorf("jwtauth.AuthResponse() mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestJWTAuthRunner_Success_ValidAudienceAB(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	appCancel, authChan := newTestRunner(verifier)
	defer appCancel()
	go func() {
		time.Sleep(time.Second)
		appCancel()
	}()

	testUserName := uuid.New().String()

	token, tokenErr := signer.SignClaims(genClaims(testUserName, []string{validAudienceA, validAudienceB})...)
	if tokenErr != nil {
		t.Errorf("signer.SignClaims() got '%v', want '%v'", tokenErr, nil)
	}

	authResp := make(chan *jwtauth.AuthResponse)

	authChan <- &jwtauth.AuthRequest{
		Token:         token,
		ReturnChannel: authResp,
	}

	for resp := range authResp {
		expectResp := &jwtauth.AuthResponse{
			Error: nil,
			Result: jwt.VerifyResult{
				Audience: jwt.AudienceSlice{
					validAudienceA, validAudienceB,
				},
				ClaimAudiences: jwt.AudienceSlice{
					validAudienceA, validAudienceB,
				},
				Subject: testUserName,
			},
		}

		if diff := cmp.Diff(expectResp, resp, ignoreDynamicResponse); diff != "" {
			t.Errorf("jwtauth.AuthResponse() mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestJWTAuthRunner_Success_ValidAudienceA_WithInvalid(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	appCancel, authChan := newTestRunner(verifier)
	defer appCancel()
	go func() {
		time.Sleep(time.Second)
		appCancel()
	}()

	testUserName := uuid.New().String()

	token, tokenErr := signer.SignClaims(genClaims(testUserName, []string{validAudienceA, invalidAudience})...)
	if tokenErr != nil {
		t.Errorf("signer.SignClaims() got '%v', want '%v'", tokenErr, nil)
	}

	authResp := make(chan *jwtauth.AuthResponse)

	authChan <- &jwtauth.AuthRequest{
		Token:         token,
		ReturnChannel: authResp,
	}

	for resp := range authResp {
		expectResp := &jwtauth.AuthResponse{
			Error: nil,
			Result: jwt.VerifyResult{
				Audience: jwt.AudienceSlice{
					validAudienceA,
				},
				ClaimAudiences: jwt.AudienceSlice{
					validAudienceA, invalidAudience,
				},
				Subject: testUserName,
			},
		}

		if diff := cmp.Diff(expectResp, resp, ignoreDynamicResponse); diff != "" {
			t.Errorf("jwtauth.AuthResponse() mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestJWTAuthRunner_Fail(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	appCancel, authChan := newTestRunner(verifier)
	defer appCancel()
	go func() {
		time.Sleep(time.Second)
		appCancel()
	}()

	testUserName := uuid.New().String()

	token, tokenErr := signer.SignClaims(genClaims(testUserName, []string{invalidAudience})...)
	if tokenErr != nil {
		t.Errorf("signer.SignClaims() got '%v', want '%v'", tokenErr, nil)
	}

	authResp := make(chan *jwtauth.AuthResponse)

	authChan <- &jwtauth.AuthRequest{
		Token:         token,
		ReturnChannel: authResp,
	}

	for resp := range authResp {
		expectResp := &jwtauth.AuthResponse{
			Error:  jwt.ErrTokenInvalidAudience,
			Result: jwt.VerifyResult{},
		}

		if diff := cmp.Diff(expectResp, resp, ignoreDynamicResponseWithError); diff != "" {
			t.Errorf("jwtauth.AuthResponse() mismatch (-want +got):\n%s", diff)
		}

		if !errors.Is(resp.Error, jwt.ErrTokenInvalidAudience) {
			t.Errorf("signer.SignClaims() got '%v', want '%v'", resp.Error, jwt.ErrTokenInvalidAudience)
		}
	}
}
