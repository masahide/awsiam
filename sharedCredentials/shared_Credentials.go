package sharedCredentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-ini/ini"
)

const (
	defaultProfile     = "default"
	awsAccessKeyID     = "aws_access_key_id"
	awsSecretAccessKey = "aws_secret_access_key"
	awsSessionToken    = "aws_session_token"
)

var (
	errUserHomeNotFound = errors.New("User home directory not found")
)

func filename() (string, error) {
	// Look for "AWS_SHARED_CREDENTIALS_FILE" env variable.
	// If the env value is empty will default to current user's home directory.
	// Linux/OSX: "$HOME/.aws/credentials"
	if credPath := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); credPath != "" {
		return credPath, nil
	}

	homeDir := os.Getenv("HOME") // *nix
	if homeDir == "" {
		return "", errUserHomeNotFound
	}
	return filepath.Join(homeDir, ".aws", "credentials"), nil
}

func createFile(filePath string) error {
	dir, _ := filepath.Split(filePath)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating directories, %s. %v", dir, err)
	}
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(filePath)
			if err != nil {
				return err
			}
			f.Close()
			if err = os.Chmod(filePath, 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

// Store is save accessKeys
func Store(accessKeyID, secretAccessKey, sessionToken, profile string) error {
	if profile == "" {
		profile = defaultProfile
	}
	credPath, err := filename()
	if err != nil {
		return err
	}

	// check if file exists, if not create it
	if _, err := os.Stat(credPath); err != nil {
		if os.IsNotExist(err) {
			err := createFile(credPath)
			if err != nil {
				return fmt.Errorf("%s: %s", "failed to create shared credentials file", err)
			}
		}
	}

	config, err := ini.Load(credPath)
	if err != nil {
		return fmt.Errorf("%s: %s", "failed to load shared credentials file", err)
	}

	iniProfile := config.Section(profile)
	if err != nil {
		return fmt.Errorf("%s: %s", "failed to get profile", err)
	}

	// Default to empty string if not found
	iniProfile.Key(awsAccessKeyID).SetValue(accessKeyID)

	iniProfile.Key(awsSecretAccessKey).SetValue(secretAccessKey)

	if sessionToken == "" {
		iniProfile.DeleteKey(awsSessionToken)
	} else {
		iniProfile.Key(awsSessionToken).SetValue(sessionToken)
	}

	err = config.SaveTo(credPath)
	if err != nil {
		return fmt.Errorf("%s: %s", "failed to save profile", err)
	}

	return nil
}
