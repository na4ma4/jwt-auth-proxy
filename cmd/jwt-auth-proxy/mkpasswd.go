package main

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/na4ma4/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var cmdMakePassword = &cobra.Command{
	Use:    "mkpasswd <username> [password]",
	Short:  "Generate a compatible hash for the legacy password",
	Run:    makePasswordCommand,
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
}

func init() {
	rootCmd.AddCommand(cmdMakePassword)
}

// Added for future legacy support of bcrypted passwords.
//
//nolint:forbidigo // printing generated hash of password.
func makePasswordCommand(_ *cobra.Command, args []string) {
	cfg := config.NewViperConfigFromViper(viper.GetViper(), "jwt-auth-proxy")

	logger, _ := cfg.ZapConfig().Build()
	defer logger.Sync()

	var password string

	username := args[0]

	if len(args) > 1 {
		// Password was specified on the command line
		password = args[1]
	} else {
		// Ask for password at prompt
		prompt := promptui.Prompt{
			Label: "Enter Password: ",
			Mask:  '*',
		}
		var err error

		if password, err = prompt.Run(); err != nil {
			logger.Panic("password entry failure", zap.Error(err))
		}
	}

	passwd, err := bcrypt.GenerateFromPassword([]byte(password), cfg.GetInt("auth.mincost"))
	if err != nil {
		logger.Panic("generate password failure", zap.Error(err))
	}

	fmt.Printf("%s:%s\n", username, passwd)
}
