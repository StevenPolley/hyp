package configuration

import (
	"encoding/base32"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

var secrets [][]byte

// LoadSecrets processes all files within the specified directory and attempts to
// convert the file contents to secrets to by used by hypd
func LoadSecrets(preSharedKeyDirectory string) ([][]byte, error) {
	secrets = make([][]byte, 0)
	err := filepath.Walk(preSharedKeyDirectory, processSecretFile)
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory '%s': %w", preSharedKeyDirectory, err)
	}

	return secrets, nil
}

// processSecretFile is called against each file in the preSharedKeyDirectory
// It reads each file and attemts to base32 decode their contents
func processSecretFile(path string, info fs.FileInfo, err error) error {
	if err != nil {
		return fmt.Errorf("failed to process file '%s': %w", path, err)
	}

	if info.IsDir() {
		return nil
	}

	secretBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file '%s': %w", path, err)
	}

	decodedSecret, err := base32.StdEncoding.DecodeString(string(secretBytes))
	if err != nil {
		return fmt.Errorf("failed to base32 decode secret '%s': %w", path, err)
	}

	secrets = append(secrets, decodedSecret)

	return nil
}
