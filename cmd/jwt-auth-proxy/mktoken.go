package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/na4ma4/config"
	pascaljwt "github.com/pascaldekloe/jwt"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

//nolint:gochecknoglobals // cobra uses globals in main
var cmdMakeToken = &cobra.Command{
	Use:    "mktoken <username> [password]",
	Short:  "Generate a token for testing",
	Run:    makeTokenCommand,
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
}

//nolint:gochecknoinits // init is used in main for cobra
func init() {
	cmdMakeToken.PersistentFlags().String("ca-key", "artifacts/certs/ca-key.pem", "CA private key to sign token with")
	_ = viper.BindPFlag("server.auth-ca-key", cmdMakeToken.PersistentFlags().Lookup("ca-key"))
	_ = viper.BindEnv("server.auth-ca-key", "AUTH_CA_KEY_FILE")

	cmdMakeToken.PersistentFlags().String("issuer", "test", "issuer to specify in token")
	_ = viper.BindPFlag("token.issuer", cmdMakeToken.PersistentFlags().Lookup("issuer"))
	_ = viper.BindEnv("token.issuer", "AUTH_TOKEN_ISSUER")

	rootCmd.AddCommand(cmdMakeToken)
}

// Added for future legacy support of bcrypted passwords.
//nolint:forbidigo,gomnd // printing generated hash of password.
func makeTokenCommand(cmd *cobra.Command, args []string) {
	cfg := config.NewViperConfigFromViper(viper.GetViper(), "jwt-auth-proxy")

	logger, _ := cfg.ZapConfig().Build()
	defer logger.Sync() //nolint:errcheck

	tokenClaims := &pascaljwt.Claims{
		Registered: pascaljwt.Registered{
			Audiences: []string{
				viper.GetString("server.audience"),
			},
			Issuer:    viper.GetString("token.issuer"),
			Subject:   args[0],
			Expires:   pascaljwt.NewNumericTime(time.Now().Add(24 * time.Hour)),
			NotBefore: pascaljwt.NewNumericTime(time.Now()),
			Issued:    pascaljwt.NewNumericTime(time.Now()),
			ID:        uuid.Must(uuid.NewV4()).String(),
		},
		Set: map[string]interface{}{
			"Online": true,
		},
	}

	privatePemData, err := os.ReadFile(viper.GetString("server.auth-ca-key"))
	if err != nil {
		logger.Fatal("unable to read private key", zap.Error(err))
	}

	privatePem, _ := pem.Decode(privatePemData)

	privateKey, err := x509.ParsePKCS1PrivateKey(privatePem.Bytes)
	if err != nil {
		logger.Fatal("unable to parse private key", zap.Error(err))
	}

	token, err := tokenClaims.RSASign(pascaljwt.RS256, privateKey)
	if err != nil {
		logger.Fatal("unable to sign token", zap.Error(err))
	}

	fmt.Printf("%s\n", token)
}
