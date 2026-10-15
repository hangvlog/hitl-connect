//go:build !windows

package main

import (
	"fmt"
	"os"
)

func createAuthorizationFile(profile string) (*os.File, error) {
	file, err := os.CreateTemp(profile, ".host-authorization-*")
	if err != nil {
		return nil, fmt.Errorf("HOST_AUTHORIZATION_CREATE_FAILED: %w", err)
	}
	return file, nil
}
func checkAuthorizationProtection(file *os.File) error { return nil }
