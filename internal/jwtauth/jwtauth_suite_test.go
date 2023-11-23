package jwtauth_test

import (
	"time"

	"github.com/na4ma4/jwt/v2"
)

const (
	validAudienceA  = "valid-audience"
	validAudienceB  = "also-valid"
	invalidAudience = "invalid-audience"
)

func genClaims(subject string, audience []string) []jwt.Claim {
	return []jwt.Claim{
		jwt.String(jwt.Subject, subject),
		jwt.Strings(jwt.Audience, audience),
		jwt.Time(jwt.NotBefore, time.Now()),
		jwt.Time(jwt.Expires, time.Now().Add(time.Hour)),
	}
}
