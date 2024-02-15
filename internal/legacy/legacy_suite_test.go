package legacy_test

import (
	"net/http"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

//nolint:gochecknoglobals // constant for tests.
var denyAuthFunc = func(_ string, _ string, _ *http.Request) (string, bool) {
	return "", false
}

func newLogger() *zap.Logger {
	// logcore, logobs = observer.New(zap.DebugLevel)
	logcore, _ := observer.New(zap.DebugLevel)
	logger := zap.New(logcore)
	return logger
}
