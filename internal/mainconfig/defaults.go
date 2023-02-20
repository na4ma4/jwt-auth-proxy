package mainconfig

import "github.com/spf13/viper"

// ConfigInit is the common config initialisation for the commands.
//
//nolint:gomnd // defaults are magic.
func ConfigInit() {
	viper.SetConfigName("jwt-auth-proxy")
	viper.SetConfigType("toml")
	viper.AddConfigPath("./artifacts")
	viper.AddConfigPath("./test")
	viper.AddConfigPath("$HOME/.jwt-auth-proxy")
	viper.AddConfigPath("/etc/jwt-auth-proxy")
	viper.AddConfigPath("/usr/local/etc")
	viper.AddConfigPath("/usr/local/jwt-auth-proxy/etc")
	viper.AddConfigPath("$HOME/.config")
	viper.AddConfigPath("/run/secrets")
	viper.AddConfigPath(".")

	viper.SetDefault("server.address", "0.0.0.0")
	viper.SetDefault("server.port", 80)
	viper.SetDefault("server.realm", "Authentication Required")
	viper.SetDefault("server.cache.default-expire", "60s")
	viper.SetDefault("server.auth-ca", "/run/secrets/ca.pem")
	_ = viper.BindEnv("server.auth-ca", "AUTH_CA_FILE")

	viper.SetDefault("server.skip-tls-verify", false)
	_ = viper.BindEnv("server.skip-tls-verify", "SKIP_TLS_VERIFY")

	viper.SetDefault("server.ca-bundle", "/etc/ca-bundle.pem")
	_ = viper.BindEnv("server.ca-bundle", "CA_BUNDLE_FILE")

	viper.SetDefault("auth.mincost", 15)

	_ = viper.ReadInConfig()
}
