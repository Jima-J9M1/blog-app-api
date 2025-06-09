package main

import (
	"os"
	"go.uber.org/zap" // New: Import Zap
)

// Config holds all application configuration settings
type Config struct {
	Port string
	DatabaseURL string
	// Add other config fields here as needed, e.g., LogLevel string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
		logger.Info("PORT environment variable not set, using default", zap.String("default_port", port))
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "./blog.db" // Default SQLite database file
		logger.Info("DATABASE_URL environment variable not set, using default", zap.String("default_db_url", dbURL))
	}

	return Config{
		Port: port,
		DatabaseURL: dbURL,
	}
}