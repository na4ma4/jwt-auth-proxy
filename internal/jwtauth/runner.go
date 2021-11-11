package jwtauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/na4ma4/jwt-auth-proxy/internal/httpauth"
	"github.com/na4ma4/jwt/v2"
	"go.uber.org/zap"
)

// AuthRequest is the authentication request and a return channel for the response.
type AuthRequest struct {
	Token         []byte
	ReturnChannel chan *AuthResponse
}

// AuthResponse is contains the response for a `AuthRequest`.
type AuthResponse struct {
	Result jwt.VerifyResult
	Error  error
}

var (
	// ErrInvalidToken is returned when a token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrUsernameIsEmpty is used for debug reporting.
	ErrUsernameIsEmpty = errors.New("username is empty")
)

// AuthRunner is the routine that runs the authentication checking channels.
func AuthRunner(ctx context.Context, logger *zap.Logger, verifier jwt.Verifier, authChan chan *AuthRequest) {
	for {
		select {
		case request := <-authChan:
			go doAuthRunner(logger, verifier, request)
		case <-ctx.Done():
			return
		}
	}
}

// doAuthRunner is the actual authentication check process (separated so it can be tested and defers will work).
func doAuthRunner(logger *zap.Logger, verifier jwt.Verifier, request *AuthRequest) {
	result, err := verifier.Verify(request.Token)
	if err != nil {
		logger.Debug("Error Verifying Token", zap.Error(err))
		request.ReturnChannel <- &AuthResponse{
			Error: err,
		}
		close(request.ReturnChannel)

		return
	}

	if strings.EqualFold(result.Subject, "") {
		logger.Debug("Verifying Token", zap.Error(ErrUsernameIsEmpty))
		request.ReturnChannel <- &AuthResponse{
			Error: ErrUsernameIsEmpty,
		}
		close(request.ReturnChannel)

		return
	}

	if result.IsOnline {
		request.ReturnChannel <- &AuthResponse{
			Result: result,
			Error:  fmt.Errorf("%w: online tokens can not be validated", ErrInvalidToken),
		}
		close(request.ReturnChannel)

		return
	}

	request.ReturnChannel <- &AuthResponse{
		Result: result,
		Error:  nil,
	}
	close(request.ReturnChannel)
}

// AuthCheckFunc returns a authentication check function for use with `httpauth.BasicAuth()``.
func AuthCheckFunc(logger *zap.Logger, authChan chan *AuthRequest) httpauth.AuthProvider {
	return func(username, password string, r *http.Request) (string, bool) {
		recUserCh := make(chan *AuthResponse)
		recPassCh := make(chan *AuthResponse)
		authChan <- &AuthRequest{
			Token:         []byte(username),
			ReturnChannel: recUserCh,
		}
		authChan <- &AuthRequest{
			Token:         []byte(password),
			ReturnChannel: recPassCh,
		}

		// Test username for token
		response := <-recUserCh
		if response.Error == nil && !strings.EqualFold(response.Result.Subject, "") {
			logger.Debug("Auth Success",
				zap.String("username", response.Result.Subject),
				zap.Bool("online", response.Result.IsOnline),
				zap.String("uuid", response.Result.ID),
				zap.Error(response.Error),
			)

			return response.Result.Subject, true
		}

		// Test password for token
		response = <-recPassCh
		if response.Error == nil && !strings.EqualFold(response.Result.Subject, "") {
			logger.Debug("Auth Success",
				zap.String("username", response.Result.Subject),
				zap.Bool("online", response.Result.IsOnline),
				zap.String("uuid", response.Result.ID),
				zap.Error(response.Error),
			)

			return response.Result.Subject, true
		}

		logger.Info("Auth Failure",
			zap.String("username", response.Result.Subject),
			zap.Bool("online", response.Result.IsOnline),
			zap.String("uuid", response.Result.ID),
			zap.Error(response.Error),
		)

		return "", false
	}
}
