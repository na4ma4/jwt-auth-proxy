//nolint:gochecknoglobals // Testing
package jwtauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/na4ma4/jwt-auth-proxy/internal/jwtauth"
	"github.com/na4ma4/jwt/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var appContext context.Context
var appCancel context.CancelFunc
var authChan chan *jwtauth.AuthRequest

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

var _ = Describe("jwtauth", func() {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	signer := &jwt.RSASigner{
		PrivateKey: privatekey,
		Algorithm:  jwt.RS256,
	}
	verifier := &jwt.RSAVerifier{
		PublicKey: &privatekey.PublicKey,
		Audiences: []string{validAudienceA, validAudienceB},
	}

	BeforeEach(func() {
		appContext, appCancel = context.WithCancel(context.Background())
		authChan = make(chan *jwtauth.AuthRequest)
		logger := zap.NewNop()
		go jwtauth.AuthRunner(appContext, logger, verifier, authChan)
	})

	AfterEach(func() {
		appCancel()
	})

	Context("should succeed", func() {
		It("valid audience [A]", func() {
			token, err := signer.SignClaims(genClaims("test-user", []string{validAudienceA})...)
			Expect(err).NotTo(HaveOccurred())

			authResp := make(chan *jwtauth.AuthResponse)

			authChan <- &jwtauth.AuthRequest{
				Token:         token,
				ReturnChannel: authResp,
			}

			for resp := range authResp {
				Expect(resp.Error).To(BeNil())
				Expect(resp.Result.Audience.Has(validAudienceA)).To(BeTrue())
				Expect(resp.Result.Audience.Has(validAudienceB)).To(BeFalse())
				Expect(resp.Result.Audience.Has(invalidAudience)).To(BeFalse())
				Expect(resp.Result.Subject).To(Equal("test-user"))
			}
		}, 1)

		It("valid audience [B]", func() {
			token, err := signer.SignClaims(genClaims("user-test", []string{validAudienceB})...)
			Expect(err).NotTo(HaveOccurred())

			authResp := make(chan *jwtauth.AuthResponse)

			authChan <- &jwtauth.AuthRequest{
				Token:         token,
				ReturnChannel: authResp,
			}

			for resp := range authResp {
				Expect(resp.Error).To(BeNil())
				Expect(resp.Result.Audience.Has(validAudienceA)).To(BeFalse())
				Expect(resp.Result.Audience.Has(validAudienceB)).To(BeTrue())
				Expect(resp.Result.Audience.Has(invalidAudience)).To(BeFalse())
				Expect(resp.Result.Subject).To(Equal("user-test"))
			}
		}, 1)

		It("valid audience [A+B]", func() {
			token, err := signer.SignClaims(genClaims("user-test", []string{validAudienceA, validAudienceB})...)
			Expect(err).NotTo(HaveOccurred())

			authResp := make(chan *jwtauth.AuthResponse)

			authChan <- &jwtauth.AuthRequest{
				Token:         token,
				ReturnChannel: authResp,
			}

			for resp := range authResp {
				Expect(resp.Error).To(BeNil())
				Expect(resp.Result.Audience.Has(validAudienceA)).To(BeTrue())
				Expect(resp.Result.Audience.Has(validAudienceB)).To(BeTrue())
				Expect(resp.Result.Audience.Has(invalidAudience)).To(BeFalse())
				Expect(resp.Result.Subject).To(Equal("user-test"))
			}
		}, 1)

		It("valid audience [A+invalid]", func() {
			token, err := signer.SignClaims(genClaims("user-test", []string{validAudienceA, invalidAudience})...)
			Expect(err).NotTo(HaveOccurred())

			authResp := make(chan *jwtauth.AuthResponse)

			authChan <- &jwtauth.AuthRequest{
				Token:         token,
				ReturnChannel: authResp,
			}

			for resp := range authResp {
				Expect(resp.Error).To(BeNil())
				Expect(resp.Result.Audience.Has(validAudienceA)).To(BeTrue())
				Expect(resp.Result.Audience.Has(validAudienceB)).To(BeFalse())
				Expect(resp.Result.Audience.Has(invalidAudience)).To(BeFalse())
				Expect(resp.Result.ClaimAudiences.Has(validAudienceA)).To(BeTrue())
				Expect(resp.Result.ClaimAudiences.Has(validAudienceB)).To(BeFalse())
				Expect(resp.Result.ClaimAudiences.Has(invalidAudience)).To(BeTrue())
				Expect(resp.Result.Subject).To(Equal("user-test"))
			}
		}, 1)
	})

	Context("should fail", func() {
		It("with invalid audience", func() {
			token, err := signer.SignClaims(genClaims("test-user", []string{invalidAudience})...)
			Expect(err).NotTo(HaveOccurred())

			authResp := make(chan *jwtauth.AuthResponse)

			authChan <- &jwtauth.AuthRequest{
				Token:         token,
				ReturnChannel: authResp,
			}

			for resp := range authResp {
				Expect(resp.Error).To(HaveOccurred())
				Expect(resp.Result.Audience).To(BeEmpty())
				Expect(resp.Result.Subject).To(BeEmpty())
			}
		}, 1)
	})
})
