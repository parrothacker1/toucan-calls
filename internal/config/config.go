// Package config
package config

type Config struct {
	Server ServerConfig `mapstructure:"server"`
}

type ServerConfig struct {
	Logger LoggerConfig `mapstructure:"logger"`
}

type LoggerConfig struct {
}
